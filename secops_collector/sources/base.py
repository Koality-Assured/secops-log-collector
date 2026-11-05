"""Base abstractions for modular API collector plugins."""

from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, Optional

import requests

from secops_collector.core.models import CollectorConfig, LogBatch, TimeWindow
from secops_collector.core.rate_limiter import RobustRateLimiter


def round_dt(dt: datetime.datetime, delta: datetime.timedelta) -> datetime.datetime:
    """Rounds a datetime object to the nearest delta interval.

    This ensures aligned query boundaries (e.g. clean 5-minute or 15-minute intervals)
    preventing gaps and redundant queries.
    """
    if dt.tzinfo is not None:
        # Round in UTC reference
        utc_min = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        return utc_min + round((dt - utc_min) / delta) * delta
    return datetime.datetime.min + round((dt - datetime.datetime.min) / delta) * delta


class BaseSource(ABC):
    """Abstract base class for all log source plugins."""

    def __init__(self, source_id: str):
        self.source_id = source_id
        self.config: Optional[CollectorConfig] = None
        self.credentials: Dict[str, Any] = {}
        self.rate_limiter: Optional[RobustRateLimiter] = None
        self.session: requests.Session = requests.Session()

    def initialize(
        self,
        config: CollectorConfig,
        credentials: Dict[str, Any],
        rate_limiter: Optional[RobustRateLimiter] = None,
    ) -> None:
        """Initialize source with configuration, credentials, and rate limiter."""
        self.config = config
        self.credentials = credentials
        self.rate_limiter = rate_limiter or RobustRateLimiter(
            max_retries=config.max_retries,
            base_backoff_seconds=config.backoff_factor,
        )

    @abstractmethod
    def collect(
        self,
        time_window: TimeWindow,
        checkpoint: Optional[Dict[str, Any]] = None,
    ) -> Iterator[LogBatch]:
        """Collect logs for given time window and yield LogBatch instances.

        If a checkpoint exists, the source may resume from the checkpoint cursor.
        Yields LogBatch objects ready for sink dispatch.
        """
        pass

    def build_time_window(
        self,
        now: Optional[datetime.datetime] = None,
        minutes: Optional[int] = None,
        rounding_minutes: Optional[int] = None,
    ) -> TimeWindow:
        """Generate a standard rounded time window for periodic polling."""
        ref_now = now or datetime.datetime.now(datetime.timezone.utc)
        window_minutes = minutes or (self.config.time_window_minutes if self.config else 5)
        rounding_mins = rounding_minutes or (self.config.time_rounding_minutes if self.config else 5)

        delta = datetime.timedelta(minutes=rounding_mins)
        end_raw = ref_now
        start_raw = ref_now - datetime.timedelta(minutes=window_minutes)

        rounded_start = round_dt(start_raw, delta)
        rounded_end = round_dt(end_raw, delta)

        # Ensure start is strictly before end
        if rounded_start >= rounded_end:
            rounded_end = rounded_start + datetime.timedelta(minutes=window_minutes)

        return TimeWindow(start_time=rounded_start, end_time=rounded_end)
