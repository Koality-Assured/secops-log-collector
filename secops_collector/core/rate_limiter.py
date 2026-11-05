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


class RobustRateLimiter:
    """Manages resilient request execution against rate-limited APIs.

    Attributes:
        max_retries: Maximum number of retry attempts before failing.
        base_backoff_seconds: Initial backoff duration in seconds.
        max_backoff_seconds: Upper ceiling for exponential backoff delay.
        jitter: If True, applies randomized full-jitter to exponential intervals.
        retryable_status_codes: Set of HTTP status codes that trigger backoff.
        sleep_fn: Sleep execution function (injectable for instant unit tests).
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
    ):
        self.max_retries = max(0, max_retries)
        self.base_backoff_seconds = max(0.1, base_backoff_seconds)
        self.max_backoff_seconds = max(self.base_backoff_seconds, max_backoff_seconds)
        self.jitter = jitter
        self.retryable_status_codes = retryable_status_codes or self.DEFAULT_RETRYABLE_STATUSES
        self.sleep_fn = sleep_fn or time.sleep
        self.total_rate_limit_hits = 0

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
                # Clamp within sensible upper bound
                return min(parsed_delay, self.max_backoff_seconds)

        # Standard exponential backoff: base * 2^attempt
        exponential = self.base_backoff_seconds * (2**attempt)
        capped = min(self.max_backoff_seconds, exponential)

        if self.jitter:
            # Full jitter: uniform random in [0, capped]
            return random.uniform(0.1, capped)

        return capped

    def execute(
        self,
        request_fn: Callable[[], requests.Response],
        operation_name: str = "HTTP request",
    ) -> requests.Response:
        """Execute request_fn with automated retry and backoff handling.

        Raises:
            RateLimitExceededError: When retry budget is exceeded.
            requests.RequestException: On non-retryable transport errors.
        """
        attempt = 0

        while True:
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
