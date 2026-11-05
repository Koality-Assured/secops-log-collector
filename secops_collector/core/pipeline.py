"""Pipeline orchestrator for secops-log-collector.

Coordinates credential resolution, discrete time-window calculation, state checkpointing,
source event collection, batch formatting, multi-sink dispatch, and telemetry generation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from secops_collector.core.models import CollectorConfig, PipelineMetrics, TimeWindow
from secops_collector.core.rate_limiter import RobustRateLimiter
from secops_collector.core.secrets import BaseSecretProvider, get_secret_provider
from secops_collector.core.state import BaseStateStore, get_state_store
from secops_collector.sinks import get_sink
from secops_collector.sinks.base import BaseSink
from secops_collector.sources import get_source
from secops_collector.sources.base import BaseSource

logger = logging.getLogger("secops_collector.pipeline")


class PipelineExecutionError(Exception):
    """Raised when pipeline execution encounters an unrecoverable failure."""

    pass


class IngestionPipeline:
    """Orchestrates security log ingestion from a source to one or more sinks."""

    def __init__(
        self,
        config: CollectorConfig,
        secret_provider: Optional[BaseSecretProvider] = None,
        state_store: Optional[BaseStateStore] = None,
        rate_limiter: Optional[RobustRateLimiter] = None,
    ):
        self.config = config
        self.secret_provider = secret_provider or get_secret_provider(
            backend=config.secrets_backend,
        )
        self.state_store = state_store or get_state_store(
            backend=config.state_backend,
            bucket_or_prefix=config.state_table_or_bucket,
        )
        self.rate_limiter = rate_limiter or RobustRateLimiter(
            max_retries=config.max_retries,
            base_backoff_seconds=config.backoff_factor,
        )

        self.source: BaseSource = get_source(config.source_type)
        self.sinks: List[BaseSink] = [get_sink(st) for st in config.sink_types]
        self.metrics = PipelineMetrics(source=config.source_type)

    def _resolve_source_credentials(self) -> Dict[str, Any]:
        """Fetch credentials for source plugin."""
        secret_name = self.config.secret_name_override or f"secops-{self.config.source_type}-credentials"
        try:
            creds = self.secret_provider.get_secret(secret_name)
            logger.info("Successfully resolved credentials for source '%s'", self.config.source_type)
            return creds
        except Exception as exc:
            logger.warning(
                "Could not load primary secret '%s' (%s). Falling back to direct source name.",
                secret_name,
                exc,
            )
            try:
                return self.secret_provider.get_secret(self.config.source_type)
            except Exception:
                # If still failing, return empty dict or re-raise
                logger.error("Failed to retrieve credentials for source '%s'", self.config.source_type)
                raise

    def _resolve_sink_credentials(self, sink_id: str) -> Dict[str, Any]:
        """Fetch credentials for sink plugin."""
        secret_name = f"secops-sink-{sink_id}-credentials"
        try:
            return self.secret_provider.get_secret(secret_name)
        except Exception:
            try:
                return self.secret_provider.get_secret(sink_id)
            except Exception:
                logger.debug("No distinct credentials found for sink '%s'; passing empty credentials.", sink_id)
                return {}

    def run(
        self,
        explicit_time_window: Optional[TimeWindow] = None,
        override_checkpoint: Optional[Dict[str, Any]] = None,
    ) -> PipelineMetrics:
        """Execute the ingestion pipeline."""
        logger.info(
            "Starting ingestion pipeline for source='%s' to sinks=%s",
            self.config.source_type,
            self.config.sink_types,
        )
        self.metrics = PipelineMetrics(source=self.config.source_type)

        try:
            # 1. Resolve secrets
            source_creds = self._resolve_source_credentials()
            self.source.initialize(self.config, source_creds, self.rate_limiter)

            for sink in self.sinks:
                sink_creds = self._resolve_sink_credentials(sink.sink_id)
                sink.initialize(self.config, sink_creds, self.rate_limiter)

            # 2. Determine time window
            time_window = explicit_time_window or self.source.build_time_window()

            # 3. Retrieve checkpoint
            checkpoint = override_checkpoint or self.state_store.get_checkpoint(self.config.source_type)

            # 4. Stream and collect event batches
            batch_count = 0
            event_count = 0
            latest_checkpoint: Optional[Dict[str, Any]] = None

            for batch in self.source.collect(time_window=time_window, checkpoint=checkpoint):
                batch_count += 1
                self.metrics.pages_processed += 1
                batch_events = batch.record_count

                if batch_events > 0:
                    event_count += batch_events

                    # 5. Dispatch batch to all configured sinks
                    for sink in self.sinks:
                        delivered = sink.write(batch)
                        logger.debug("Sink '%s' accepted %d records.", sink.sink_id, delivered)

                    self.metrics.batches_delivered += 1
                    self.metrics.events_collected += batch_events

                # Save incremental checkpoint if available
                if batch.metadata:
                    latest_checkpoint = batch.metadata
                    self.state_store.save_checkpoint(self.config.source_type, latest_checkpoint)

            # 6. Flush and finalize sinks
            for sink in self.sinks:
                sink.flush()
                sink.close()

            self.metrics.mark_completed()
            logger.info(
                "Ingestion completed for source='%s': %d events across %d batches in %.2fs",
                self.config.source_type,
                self.metrics.events_collected,
                self.metrics.batches_delivered,
                self.metrics.duration_seconds,
            )
            return self.metrics

        except Exception as exc:
            self.metrics.mark_failed(exc)
            logger.exception("Ingestion pipeline failed for source '%s': %s", self.config.source_type, exc)
            raise PipelineExecutionError(f"Pipeline execution failed: {exc}") from exc
