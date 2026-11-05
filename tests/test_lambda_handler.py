"""Unit tests for secops_collector.lambda_handler."""

import json
from unittest.mock import MagicMock, patch

from secops_collector.core.models import PipelineMetrics
from secops_collector.lambda_handler import lambda_handler


@patch("secops_collector.lambda_handler.IngestionPipeline")
def test_lambda_handler_scheduled_event(mock_pipeline_cls):
    mock_pipeline = MagicMock()
    mock_metrics = PipelineMetrics(source="okta")
    mock_metrics.events_collected = 120
    mock_metrics.batches_delivered = 2
    mock_metrics.pages_processed = 2
    mock_metrics.mark_completed()

    mock_pipeline.run.return_value = mock_metrics
    mock_pipeline_cls.return_value = mock_pipeline

    event = {
        "source_type": "okta",
        "sink_types": ["logscale", "s3"],
        "batch_size": 250,
    }

    response = lambda_handler(event, context=None)

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "success"
    assert body["source"] == "okta"
    assert body["events_collected"] == 120
    assert body["batches_delivered"] == 2


@patch("secops_collector.lambda_handler.IngestionPipeline")
def test_lambda_handler_explicit_backfill_window(mock_pipeline_cls):
    mock_pipeline = MagicMock()
    mock_metrics = PipelineMetrics(source="crowdstrike")
    mock_metrics.mark_completed()
    mock_pipeline.run.return_value = mock_metrics
    mock_pipeline_cls.return_value = mock_pipeline

    event = {
        "source": "crowdstrike",
        "start_time": "2026-11-05T00:00:00Z",
        "end_time": "2026-11-05T01:00:00Z",
    }

    response = lambda_handler(event, context=None)
    assert response["statusCode"] == 200

    # Ensure run was called with an explicit_time_window
    mock_pipeline.run.assert_called_once()
    tw_arg = mock_pipeline.run.call_args[1]["explicit_time_window"]
    assert tw_arg is not None
    assert tw_arg.duration_seconds == 3600.0


@patch("secops_collector.lambda_handler.IngestionPipeline")
def test_lambda_handler_failure(mock_pipeline_cls):
    mock_pipeline = MagicMock()
    mock_pipeline.run.side_effect = RuntimeError("Fatal Secrets Manager decryption failure")
    mock_pipeline_cls.return_value = mock_pipeline

    event = {"source_type": "datadog"}
    response = lambda_handler(event, context=None)

    assert response["statusCode"] == 500
    body = json.loads(response["body"])
    assert body["status"] == "error"
    assert "Fatal Secrets Manager decryption failure" in body["message"]
