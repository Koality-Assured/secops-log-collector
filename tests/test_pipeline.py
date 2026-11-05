"""Unit tests for secops_collector.core.pipeline."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from secops_collector.core.models import CollectorConfig, LogBatch, LogEvent, TimeWindow
from secops_collector.core.pipeline import IngestionPipeline, PipelineExecutionError
from secops_collector.core.rate_limiter import RobustRateLimiter
from secops_collector.core.secrets import DictionarySecretProvider
from secops_collector.core.state import InMemoryStateStore


def test_pipeline_end_to_end_multi_sink(mock_sleep_recorder):
    config = CollectorConfig(
        source_type="okta",
        sink_types=["logscale", "s3"],
        batch_size=10,
        secrets_backend="memory",
        state_backend="memory",
    )

    secrets = DictionarySecretProvider(
        {
            "secops-okta-credentials": {"okta_url": "https://example.okta.com", "okta_token": "tok_123"},
            "secops-sink-logscale-credentials": {"logscale_url": "https://example.logscale.com", "token": "ls_tok"},
            "secops-sink-s3-credentials": {"s3_bucket": "lake-bucket", "s3_prefix": "logs"},
        }
    )
    state = InMemoryStateStore()
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)

    pipeline = IngestionPipeline(
        config=config,
        secret_provider=secrets,
        state_store=state,
        rate_limiter=rate_limiter,
    )

    # Mock source.collect to yield two batches
    now = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)
    batch1 = LogBatch(
        source="okta",
        events=[LogEvent(timestamp=now, source="okta", event_type="login")],
        metadata={"cursor": "cur_1"},
    )
    batch2 = LogBatch(
        source="okta",
        events=[LogEvent(timestamp=now, source="okta", event_type="logout")],
        metadata={"cursor": "cur_2"},
    )

    pipeline.source.collect = MagicMock(return_value=iter([batch1, batch2]))

    # Mock sink writes
    for sink in pipeline.sinks:
        sink.write = MagicMock(return_value=1)

    tw = TimeWindow(start_time=now, end_time=now)
    metrics = pipeline.run(explicit_time_window=tw)

    assert metrics.status == "success"
    assert metrics.events_collected == 2
    assert metrics.batches_delivered == 2

    # Checkpoint should have been updated to cur_2
    saved_cp = state.get_checkpoint("okta")
    assert saved_cp["cursor"] == "cur_2"

    # Both sinks should have received both batches
    for sink in pipeline.sinks:
        assert sink.write.call_count == 2


def test_pipeline_failure_handling(mock_sleep_recorder):
    config = CollectorConfig(
        source_type="okta",
        sink_types=["logscale"],
        secrets_backend="memory",
        state_backend="memory",
    )

    secrets = DictionarySecretProvider(
        {
            "secops-okta-credentials": {"okta_url": "https://example.okta.com", "okta_token": "tok_123"},
            "secops-sink-logscale-credentials": {"token": "ls_tok"},
        }
    )
    state = InMemoryStateStore()

    pipeline = IngestionPipeline(
        config=config,
        secret_provider=secrets,
        state_store=state,
    )

    pipeline.source.collect = MagicMock(side_effect=RuntimeError("API gateway disconnected"))

    with pytest.raises(PipelineExecutionError) as exc_info:
        pipeline.run()

    assert "API gateway disconnected" in str(exc_info.value)
    assert pipeline.metrics.status == "failed"
