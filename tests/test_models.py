"""Unit tests for secops_collector.core.models."""

import json
from datetime import datetime, timezone

from secops_collector.core.models import (
    CollectorConfig,
    LogBatch,
    LogEvent,
    PipelineMetrics,
    TimeWindow,
)


def test_time_window_normalization_and_formatting():
    # Test naive datetime gets UTC assigned
    start = datetime(2026, 11, 5, 12, 0, 0)
    end = datetime(2026, 11, 5, 12, 5, 0)
    tw = TimeWindow(start_time=start, end_time=end)

    assert tw.start_time.tzinfo == timezone.utc
    assert tw.end_time.tzinfo == timezone.utc
    assert tw.duration_seconds == 300.0

    iso_start = tw.to_iso8601_start()
    iso_end = tw.to_iso8601_end()
    assert iso_start.endswith("Z")
    assert iso_end.endswith("Z")

    assert tw.to_unix_ms_end() > tw.to_unix_ms_start()


def test_log_event_creation_and_serialization():
    now = datetime.now(timezone.utc)
    event = LogEvent(
        timestamp=now,
        source="okta",
        event_type="user.authentication.verify",
        raw_payload={"actor": {"alternateId": "alice@example.com"}},
        attributes={"ip": "192.0.2.1"},
    )

    assert event.id is not None
    assert len(event.id) > 10
    assert event.source == "okta"

    event_dict = event.to_dict()
    assert event_dict["source"] == "okta"
    assert event_dict["attributes"]["ip"] == "192.0.2.1"
    assert event_dict["raw_payload"]["actor"]["alternateId"] == "alice@example.com"


def test_log_batch_operations():
    now = datetime.now(timezone.utc)
    events = [
        LogEvent(timestamp=now, source="github", event_type="repo.create", attributes={"repo": f"repo-{i}"})
        for i in range(3)
    ]
    batch = LogBatch(source="github", events=events, metadata={"cursor": "cur_123"})

    assert batch.record_count == 3
    assert batch.metadata["cursor"] == "cur_123"

    ndjson_str = batch.to_ndjson()
    lines = ndjson_str.strip().split("\n")
    assert len(lines) == 3
    first_obj = json.loads(lines[0])
    assert first_obj["source"] == "github"
    assert first_obj["attributes"]["repo"] == "repo-0"

    raw_list = batch.to_raw_json_list()
    assert len(raw_list) == 3


def test_pipeline_metrics():
    metrics = PipelineMetrics(source="crowdstrike")
    assert metrics.status == "running"
    assert metrics.events_collected == 0

    metrics.events_collected += 42
    metrics.batches_delivered += 2
    metrics.mark_completed()

    assert metrics.status == "success"
    assert metrics.end_time is not None
    assert metrics.duration_seconds >= 0.0

    err_metrics = PipelineMetrics(source="sentinelone")
    err_metrics.mark_failed(ValueError("Connection timeout"))
    assert err_metrics.status == "failed"
    assert err_metrics.error_message == "Connection timeout"


def test_collector_config():
    config = CollectorConfig(source_type="okta", sink_types=["logscale", "s3"], batch_size=100)
    assert config.source_type == "okta"
    assert config.batch_size == 100
    assert config.time_window_minutes == 5
    assert config.secrets_backend == "env"
