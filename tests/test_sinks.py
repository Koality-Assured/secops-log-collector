"""Unit tests for secops_collector.sinks plugins."""

import gzip
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import requests

from secops_collector.core.models import CollectorConfig, LogBatch, LogEvent
from secops_collector.core.rate_limiter import RobustRateLimiter
from secops_collector.sinks.logscale import LogScaleSink
from secops_collector.sinks.opensearch import OpenSearchSink
from secops_collector.sinks.s3 import S3DataLakeSink


@pytest.fixture
def sample_batch():
    now = datetime(2026, 11, 5, 12, 30, 0, tzinfo=timezone.utc)
    events = [
        LogEvent(
            id="evt_101",
            timestamp=now,
            source="okta",
            event_type="user.login",
            attributes={"user": "bob"},
        ),
        LogEvent(
            id="evt_102",
            timestamp=now,
            source="okta",
            event_type="user.logout",
            attributes={"user": "bob"},
        ),
    ]
    return LogBatch(batch_id="batch-uuid-1234", source="okta", collected_at=now, events=events)


def test_logscale_sink(sample_batch, mock_sleep_recorder):
    sink = LogScaleSink()
    config = CollectorConfig(source_type="okta", sink_types=["logscale"])
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)
    sink.initialize(
        config,
        {"logscale_url": "https://example.logscale.com/api/v1/ingest/json", "token": "ls_token_abc"},
        rate_limiter,
    )

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    sink.session.post = MagicMock(return_value=mock_resp)

    written = sink.write(sample_batch)
    assert written == 2

    sink.session.post.assert_called_once()
    call_args = sink.session.post.call_args
    headers = call_args[1]["headers"]
    payload = call_args[1]["json"]

    assert headers["Authorization"] == "Bearer ls_token_abc"
    assert len(payload) == 1
    assert payload[0]["tags"]["source"] == "okta"
    assert len(payload[0]["events"]) == 2


def test_logscale_sink_failure(sample_batch, mock_sleep_recorder):
    sink = LogScaleSink()
    config = CollectorConfig(source_type="okta")
    rate_limiter = RobustRateLimiter(max_retries=1, sleep_fn=mock_sleep_recorder)
    sink.initialize(config, {"token": "bad_token"}, rate_limiter)

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"
    sink.session.post = MagicMock(return_value=mock_resp)

    with pytest.raises(RuntimeError):
        sink.write(sample_batch)


def test_s3_data_lake_sink(sample_batch):
    mock_s3 = MagicMock()
    sink = S3DataLakeSink(s3_client=mock_s3)
    config = CollectorConfig(source_type="okta", sink_types=["s3"])
    sink.initialize(
        config,
        {"s3_bucket": "my-sec-lake", "s3_prefix": "raw-logs"},
    )

    written = sink.write(sample_batch)
    assert written == 2

    mock_s3.put_object.assert_called_once()
    call_args = mock_s3.put_object.call_args[1]

    assert call_args["Bucket"] == "my-sec-lake"
    expected_key = "raw-logs/source=okta/year=2026/month=11/day=05/hour=12/batch-uuid-1234.json.gz"
    assert call_args["Key"] == expected_key
    assert call_args["ContentEncoding"] == "gzip"

    # Verify gzip payload decompresses to valid NDJSON
    decompressed = gzip.decompress(call_args["Body"]).decode("utf-8")
    lines = decompressed.strip().split("\n")
    assert len(lines) == 2
    parsed_evt1 = json.loads(lines[0])
    assert parsed_evt1["id"] == "evt_101"


def test_opensearch_sink(sample_batch, mock_sleep_recorder):
    sink = OpenSearchSink()
    config = CollectorConfig(source_type="okta", sink_types=["opensearch"])
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)
    sink.initialize(
        config,
        {
            "opensearch_url": "https://opensearch.example.internal:9200",
            "token": "es_token_xyz",
            "index_pattern": "logs-{source}-{date}",
        },
        rate_limiter,
    )

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "errors": False,
        "items": [{"index": {"_id": "evt_101", "status": 201}}, {"index": {"_id": "evt_102", "status": 201}}],
    }
    sink.session.post = MagicMock(return_value=mock_resp)

    written = sink.write(sample_batch)
    assert written == 2

    sink.session.post.assert_called_once()
    call_args = sink.session.post.call_args
    data_sent = call_args[1]["data"].decode("utf-8")
    lines = data_sent.strip().split("\n")
    assert len(lines) == 4  # 2 metadata + 2 event docs
    meta_action = json.loads(lines[0])
    assert meta_action["index"]["_index"] == "logs-okta-2026.11.05"
    assert meta_action["index"]["_id"] == "evt_101"
