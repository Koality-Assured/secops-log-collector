"""AWS Lambda entrypoint handler for secops-log-collector.

Receives EventBridge scheduled events or manual execution payloads, parses
collector configurations, executes the ingestion pipeline, and returns
structured execution telemetry.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

from dateutil import parser as dt_parser

from secops_collector.core.models import CollectorConfig, TimeWindow
from secops_collector.core.pipeline import IngestionPipeline

# Configure structured logging
logger = logging.getLogger("secops_collector.lambda")
logger.setLevel(logging.INFO)


def _parse_event_config(event: Optional[Dict[str, Any]]) -> CollectorConfig:
    """Parse configuration from Lambda event payload or fallback to environment variables."""
    payload = event or {}

    source_type = payload.get("source_type") or payload.get("source") or os.environ.get("SOURCE_TYPE") or "okta"

    sink_types_raw = payload.get("sink_types") or payload.get("sinks") or os.environ.get("SINK_TYPES", "logscale")
    if isinstance(sink_types_raw, str):
        sink_types = [s.strip() for s in sink_types_raw.split(",") if s.strip()]
    elif isinstance(sink_types_raw, list):
        sink_types = sink_types_raw
    else:
        sink_types = ["logscale"]

    batch_size = int(payload.get("batch_size") or os.environ.get("BATCH_SIZE", "500"))
    window_minutes = int(payload.get("time_window_minutes") or os.environ.get("TIME_WINDOW_MINUTES", "5"))
    rounding_minutes = int(payload.get("time_rounding_minutes") or os.environ.get("TIME_ROUNDING_MINUTES", "5"))
    max_retries = int(payload.get("max_retries") or os.environ.get("MAX_RETRIES", "5"))
    secrets_backend = payload.get("secrets_backend") or os.environ.get("SECRETS_BACKEND", "secretsmanager")
    state_backend = payload.get("state_backend") or os.environ.get("STATE_BACKEND", "memory")
    state_bucket = payload.get("state_table_or_bucket") or os.environ.get("STATE_BUCKET")

    return CollectorConfig(
        source_type=source_type,
        sink_types=sink_types,
        batch_size=batch_size,
        time_window_minutes=window_minutes,
        time_rounding_minutes=rounding_minutes,
        max_retries=max_retries,
        secrets_backend=secrets_backend,
        state_backend=state_backend,
        state_table_or_bucket=state_bucket,
    )


def _parse_explicit_window(event: Optional[Dict[str, Any]]) -> Optional[TimeWindow]:
    """Parse explicit start and end times for ad-hoc backfills if present in event."""
    if not event:
        return None

    start_str = event.get("start_time") or event.get("since")
    end_str = event.get("end_time") or event.get("until")

    if start_str and end_str:
        try:
            start_dt = dt_parser.isoparse(str(start_str))
            end_dt = dt_parser.isoparse(str(end_str))
            return TimeWindow(start_time=start_dt, end_time=end_dt)
        except Exception as exc:
            logger.warning("Failed to parse explicit start_time/end_time in event: %s", exc)

    return None


def lambda_handler(event: Any, context: Any = None) -> Dict[str, Any]:
    """Main AWS Lambda handler entrypoint."""
    logger.info("Received Lambda invocation event: %s", type(event))

    event_dict: Dict[str, Any] = {}
    if isinstance(event, dict):
        event_dict = event
    elif isinstance(event, str):
        try:
            event_dict = json.loads(event)
        except json.JSONDecodeError:
            pass

    remaining_time_fn = None
    if context is not None and hasattr(context, "get_remaining_time_in_millis"):
        remaining_time_fn = lambda: context.get_remaining_time_in_millis() / 1000.0

    try:
        config = _parse_event_config(event_dict)
        explicit_window = _parse_explicit_window(event_dict)

        pipeline = IngestionPipeline(config=config, remaining_time_fn=remaining_time_fn)
        metrics = pipeline.run(explicit_time_window=explicit_window, remaining_time_fn=remaining_time_fn)

        response_body = {
            "status": metrics.status,
            "source": metrics.source,
            "events_collected": metrics.events_collected,
            "batches_delivered": metrics.batches_delivered,
            "pages_processed": metrics.pages_processed,
            "duration_seconds": round(metrics.duration_seconds, 3),
        }
        if metrics.error_message:
            response_body["message"] = metrics.error_message

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(response_body),
        }

    except Exception as exc:
        logger.exception("Lambda execution failed: %s", exc)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(
                {
                    "status": "error",
                    "message": str(exc),
                }
            ),
        }
