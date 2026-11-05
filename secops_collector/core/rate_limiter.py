"""Robust rate limiting and exponential backoff engine for secops-log-collector.

Handles HTTP 429 (Too Many Requests) and transient 5xx responses with
adaptive backoff, RFC 7231 / RFC 9110 'Retry-After' header compliance,
and randomized full jitter.
"""

from __future__ import annotations

import logging
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable, Optional, Set

import requests

logger = logging.getLogger("secops_collector.rate_limiter")


class RateLimitExceededError(Exception):
    """Raised when maximum retries are exhausted under rate limiting."""

    def __init__(self, message: str, status_code: int = 429, last_response: Optional[requests.Response] = None):
        super().__init__(message)
        self.status_code = status_code
        self.last_response = last_response


class ExecutionTimeoutError(Exception):
    """Raised when an operation would exceed the remaining execution time budget."""

    def __init__(self, message: str, remaining_seconds: float = 0.0, required_backoff: float = 0.0):
        super().__init__(message)
        self.remaining_seconds = remaining_seconds
        self.required_backoff = required_backoff


class RobustRateLimiter:
    """Manages resilient request execution against rate-limited APIs.

    Attributes:
        max_retries: Maximum number of retry attempts before failing.
        base_backoff_seconds: Initial backoff duration in seconds.
        max_backoff_seconds: Upper ceiling for exponential backoff delay.
        jitter: If True, applies randomized full-jitter to exponential intervals.
        retryable_status_codes: Set of HTTP status codes that trigger backoff.
        sleep_fn: Sleep execution function (injectable for instant unit tests).
        remaining_time_fn: Callable returning remaining execution seconds (e.g. Lambda context).
        min_reserve_seconds: Safety buffer reserved before deadline expiration.
    """

    DEFAULT_RETRYABLE_STATUSES: Set[int] = {429, 500, 502, 503, 504}

    def __init__(
        self,
        max_retries: int = 5,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 60.0,
        jitter: bool = True,
        retryable_status_codes: Optional[Set[int]] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
        remaining_time_fn: Optional[Callable[[], float]] = None,
        min_reserve_seconds: float = 15.0,
    ):
        self.max_retries = max(0, max_retries)
        self.base_backoff_seconds = max(0.1, base_backoff_seconds)
        self.max_backoff_seconds = max(self.base_backoff_seconds, max_backoff_seconds)
        self.jitter = jitter
        self.retryable_status_codes = retryable_status_codes or self.DEFAULT_RETRYABLE_STATUSES
        self.sleep_fn = sleep_fn or time.sleep
        self.remaining_time_fn = remaining_time_fn
        self.min_reserve_seconds = max(0.0, min_reserve_seconds)
        self.total_rate_limit_hits = 0

    def set_remaining_time_fn(self, remaining_time_fn: Optional[Callable[[], float]]) -> None:
        """Configure remaining time inspection callable."""
        self.remaining_time_fn = remaining_time_fn

    def _check_deadline(self, required_duration: float = 0.0) -> None:
        """Validate remaining execution budget against required duration and reserve buffer."""
        if self.remaining_time_fn is not None:
            remaining = self.remaining_time_fn()
            if remaining <= (required_duration + self.min_reserve_seconds):
                err_msg = (
                    f"Execution deadline imminent: {remaining:.2f}s remaining, "
                    f"required {required_duration:.2f}s backoff + {self.min_reserve_seconds:.2f}s reserve."
                )
                logger.warning(err_msg)
                raise ExecutionTimeoutError(
                    err_msg,
                    remaining_seconds=remaining,
                    required_backoff=required_duration,
                )

    def parse_retry_after(self, retry_after_header: Optional[str]) -> Optional[float]:
        """Parse HTTP Retry-After header as either seconds or an RFC 7231 HTTP-date.

        Returns delay in seconds, or None if header is missing or unparseable.
        """
        if not retry_after_header:
            return None

        clean_header = retry_after_header.strip()

        # 1. Attempt integer / float seconds parse
        try:
            seconds = float(clean_header)
            return max(0.0, seconds)
        except ValueError:
            pass

        # 2. Attempt RFC 7231 HTTP-date parse (e.g., 'Wed, 21 Oct 2026 07:28:00 GMT')
        try:
            target_dt = parsedate_to_datetime(clean_header)
            if target_dt.tzinfo is None:
                target_dt = target_dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            delta = (target_dt - now_dt).total_seconds()
            return max(0.0, delta)
        except Exception:
            logger.debug("Failed to parse Retry-After header value: %s", clean_header)
            return None

    def calculate_backoff(self, attempt: int, response: Optional[requests.Response] = None) -> float:
        """Compute the backoff sleep duration in seconds for a given attempt."""
        # Check for Retry-After header first if response is present
        if response is not None and "Retry-After" in response.headers:
            parsed_delay = self.parse_retry_after(response.headers.get("Retry-After"))
            if parsed_delay is not None:
                # Respect upstream server-specified delay
                return parsed_delay

        # Standard exponential backoff: base * 2^attempt
        exponential = self.base_backoff_seconds * (2**attempt)
        capped = min(self.max_backoff_seconds, exponential)

        if self.jitter:
            # Full jitter: uniform random in [0.1, capped]
            return random.uniform(0.1, capped)

        return capped

    def execute(
        self,
        request_fn: Callable[[], requests.Response],
        operation_name: str = "HTTP request",
    ) -> requests.Response:
        """Execute request_fn with automated retry and backoff handling.

        Raises:
            ExecutionTimeoutError: When execution deadline is imminent.
            RateLimitExceededError: When retry budget is exceeded.
            requests.RequestException: On non-retryable transport errors.
        """
        attempt = 0

        while True:
            # Pre-execution deadline check
            self._check_deadline(0.0)

            try:
                response = request_fn()

                if response.status_code not in self.retryable_status_codes:
                    return response

                self.total_rate_limit_hits += 1

                if attempt >= self.max_retries:
                    logger.error(
                        "%s failed after %d retries with status %d: %s",
                        operation_name,
                        attempt,
                        response.status_code,
                        response.text[:200] if response.text else "",
                    )
                    err_msg = (
                        f"{operation_name} exceeded max retries ({self.max_retries}). "
                        f"Last status: {response.status_code}"
                    )
                    raise RateLimitExceededError(
                        err_msg,
                        status_code=response.status_code,
                        last_response=response,
                    )

                backoff_time = self.calculate_backoff(attempt, response)

                # Post-response backoff deadline check
                self._check_deadline(backoff_time)

                logger.warning(
                    "%s received HTTP %d. Attempt %d/%d. Backing off for %.2fs...",
                    operation_name,
                    response.status_code,
                    attempt + 1,
                    self.max_retries,
                    backoff_time,
                )
                self.sleep_fn(backoff_time)
                attempt += 1

            except requests.RequestException as exc:
                # Catch network-level disconnects or timeouts and retry if attempts remain
                if attempt >= self.max_retries:
                    raise exc

                backoff_time = self.calculate_backoff(attempt, None)
                self._check_deadline(backoff_time)

                logger.warning(
                    "%s encountered network error (%s). Attempt %d/%d. Backing off for %.2fs...",
                    operation_name,
                    str(exc),
                    attempt + 1,
                    self.max_retries,
                    backoff_time,
                )
                self.sleep_fn(backoff_time)
                attempt += 1
