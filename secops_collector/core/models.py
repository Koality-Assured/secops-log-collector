"""Core Pydantic models for secops-log-collector.

Defines standardized data models for events, batches, time windows,
collector configurations, and pipeline execution telemetry.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class TimeWindow(BaseModel):
    """Represents a discrete, closed-open time interval [start_time, end_time) for log queries."""

    start_time: datetime = Field(
        ...,
        description="Inclusive start timestamp (UTC).",
    )
    end_time: datetime = Field(
        ...,
        description="Exclusive end timestamp (UTC).",
    )

    @field_validator("start_time", "end_time", mode="after")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        """Enforce timezone awareness normalized to UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @property
    def duration_seconds(self) -> float:
        """Duration of the time window in seconds."""
        return (self.end_time - self.start_time).total_seconds()

    def to_iso8601_start(self) -> str:
        """Format start time as standard ISO-8601 string (e.g., 2026-11-05T12:00:00Z)."""
        return self.start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"

    def to_iso8601_end(self) -> str:
        """Format end time as standard ISO-8601 string."""
        return self.end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"

    def to_unix_ms_start(self) -> int:
        """Format start time as Unix timestamp in milliseconds."""
        return int(self.start_time.timestamp() * 1000)

    def to_unix_ms_end(self) -> int:
        """Format end time as Unix timestamp in milliseconds."""
        return int(self.end_time.timestamp() * 1000)


class LogEvent(BaseModel):
    """Standardized security log event schema across heterogeneous API sources."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the event (source-provided or UUID4 fallback).",
    )
    timestamp: datetime = Field(
        ...,
        description="Event generation timestamp (UTC).",
    )
    source: str = Field(
        ...,
        description="Log source identifier (e.g., 'okta', 'crowdstrike', 'datadog', 'github', 'sentinelone').",
    )
    event_type: str = Field(
        default="security_audit",
        description="Category or action type of the event.",
    )
    raw_payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Original unmodified JSON payload from source API.",
    )
    attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Normalized key-value attributes extracted or enriched for ingestion.",
    )

    @field_validator("timestamp", mode="after")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "raw_payload": self.raw_payload,
            "attributes": self.attributes,
        }


class LogBatch(BaseModel):
    """A batch container aggregating multiple LogEvents for bulk delivery to sinks."""

    batch_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique batch identifier.",
    )
    source: str = Field(
        ...,
        description="Log source identifier.",
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when batch was collected (UTC).",
    )
    events: List[LogEvent] = Field(
        default_factory=list,
        description="List of LogEvent objects in this batch.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata associated with batch (e.g. partition keys, checkpoint token).",
    )

    @property
    def record_count(self) -> int:
        """Total number of records in this batch."""
        return len(self.events)

    def to_ndjson(self) -> str:
        """Serialize events to newline-delimited JSON string."""
        lines = [json.dumps(evt.to_dict(), default=str) for evt in self.events]
        return "\n".join(lines)

    def to_raw_json_list(self) -> List[Dict[str, Any]]:
        """Return raw event payloads for sinks that expect native source formats."""
        return [evt.raw_payload if evt.raw_payload else evt.to_dict() for evt in self.events]


class PipelineMetrics(BaseModel):
    """Telemetry and performance metrics captured during pipeline execution."""

    source: str
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    events_collected: int = 0
    batches_delivered: int = 0
    bytes_transferred: int = 0
    pages_processed: int = 0
    rate_limit_hits: int = 0
    status: str = "running"
    error_message: Optional[str] = None

    def mark_completed(self) -> None:
        """Mark pipeline execution as completed."""
        self.end_time = datetime.now(timezone.utc)
        self.status = "success"

    def mark_failed(self, error: Exception) -> None:
        """Mark pipeline execution as failed."""
        self.end_time = datetime.now(timezone.utc)
        self.status = "failed"
        self.error_message = str(error)

    @property
    def duration_seconds(self) -> float:
        """Total duration of execution in seconds."""
        if not self.end_time:
            return (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()


class CollectorConfig(BaseModel):
    """Runtime configuration model for the security log collector."""

    source_type: str = Field(..., description="Source collector plugin name (okta, crowdstrike, etc.)")
    sink_types: List[str] = Field(default_factory=lambda: ["logscale"], description="Target sink plugin names")
    batch_size: int = Field(default=500, ge=1, le=10000, description="Max events per batch")
    time_window_minutes: int = Field(default=5, ge=1, le=1440, description="Collection window delta")
    time_rounding_minutes: int = Field(default=5, ge=1, le=60, description="Window boundary rounding in minutes")
    overlap_buffer_minutes: int = Field(default=0, ge=0, le=60, description="Overlap buffer to prevent edge loss")
    max_retries: int = Field(default=5, ge=0, le=10, description="Max HTTP retry attempts")
    backoff_factor: float = Field(default=1.5, ge=0.5, le=10.0, description="Backoff multiplier")
    secrets_backend: str = Field(default="env", description="Secret source: 'env' or 'secretsmanager'")
    secret_name_override: Optional[str] = Field(default=None, description="Explicit secret name in Secrets Manager")
    state_backend: str = Field(default="memory", description="State checkpoint store: 'memory', 's3', or 'ssm'")
    state_table_or_bucket: Optional[str] = Field(default=None, description="S3 bucket or SSM prefix for state")
