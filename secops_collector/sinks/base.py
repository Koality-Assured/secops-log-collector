"""Base abstractions for pluggable output sink plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from secops_collector.core.models import CollectorConfig, LogBatch
from secops_collector.core.rate_limiter import RobustRateLimiter


class BaseSink(ABC):
    """Abstract base class for all output sink plugins."""

    def __init__(self, sink_id: str):
        self.sink_id = sink_id
        self.config: Optional[CollectorConfig] = None
        self.credentials: Dict[str, Any] = {}
        self.rate_limiter: Optional[RobustRateLimiter] = None

    def initialize(
        self,
        config: CollectorConfig,
        credentials: Dict[str, Any],
        rate_limiter: Optional[RobustRateLimiter] = None,
    ) -> None:
        """Initialize sink with runtime configuration, credentials, and backoff policy."""
        self.config = config
        self.credentials = credentials
        self.rate_limiter = rate_limiter or RobustRateLimiter(
            max_retries=config.max_retries,
            base_backoff_seconds=config.backoff_factor,
        )

    @abstractmethod
    def write(self, batch: LogBatch) -> int:
        """Write a batch of logs to the destination sink.

        Returns:
            int: Number of records successfully accepted by the sink.
        """
        pass

    def flush(self) -> None:
        """Flush any pending buffered logs (optional for buffering sinks)."""
        pass

    def close(self) -> None:
        """Release underlying connections and resources."""
        pass
