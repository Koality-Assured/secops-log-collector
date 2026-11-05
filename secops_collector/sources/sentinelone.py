"""SentinelOne Activity and Alert Log API collector plugin.

Collects telemetry from SentinelOne Management API (/web/api/v2.1/activities
and /web/api/v2.1/alerts) with cursor pagination and ISO 8601 millisecond filters.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, Iterator, List, Optional

from dateutil import parser as dt_parser

from secops_collector.core.models import LogBatch, LogEvent, TimeWindow
from secops_collector.sources.base import BaseSource, SourceAPIError, safe_parse_json

logger = logging.getLogger("secops_collector.sources.sentinelone")


class SentinelOneSource(BaseSource):
    """Collector for SentinelOne Activities and Alerts."""

    def __init__(self):
        super().__init__(source_id="sentinelone")

    def _get_api_url(self) -> str:
        """Resolve SentinelOne activities endpoint."""
        explicit_url = self.credentials.get("s1_activities_url") or self.credentials.get("activities_url")
        if explicit_url:
            return explicit_url.rstrip("/")

        base_url = (
            self.credentials.get("s1_url") or self.credentials.get("base_url", "https://example.sentinelone.net")
        ).rstrip("/")
        return f"{base_url}/web/api/v2.1/activities"

    def _get_token(self) -> str:
        token = self.credentials.get("s1_token") or self.credentials.get("token") or self.credentials.get("api_token")
        if not token:
            raise ValueError("SentinelOne collector requires 's1_token' or 'token' in credentials.")
        return token

    def _build_event(self, raw_record: Dict[str, Any]) -> LogEvent:
        """Map raw SentinelOne activity record to LogEvent."""
        event_id = raw_record.get("id") or ""
        created_at_str = raw_record.get("createdAt") or raw_record.get("updatedAt")

        if created_at_str:
            try:
                event_ts = dt_parser.isoparse(str(created_at_str))
            except Exception:
                event_ts = datetime.datetime.now(datetime.timezone.utc)
        else:
            event_ts = datetime.datetime.now(datetime.timezone.utc)

        activity_type = raw_record.get("activityType", "sentinelone.activity")
        data = raw_record.get("data", {})

        attributes = {
            "user_id": raw_record.get("userId"),
            "user_name": raw_record.get("userName"),
            "agent_id": raw_record.get("agentId"),
            "threat_id": raw_record.get("threatId"),
            "primary_description": raw_record.get("primaryDescription"),
            "description": raw_record.get("description"),
            "agent_computer_name": data.get("computerName"),
        }

        return LogEvent(
            id=str(event_id),
            timestamp=event_ts,
            source=self.source_id,
            event_type=str(activity_type),
            raw_payload=raw_record,
            attributes=attributes,
        )

    def collect(
        self,
        time_window: TimeWindow,
        checkpoint: Optional[Dict[str, Any]] = None,
    ) -> Iterator[LogBatch]:
        token = self._get_token()
        headers = {
            "Authorization": f"ApiToken {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        api_url = self._get_api_url()
        batch_size = self.config.batch_size if self.config else 500

        cursor = None
        if checkpoint and checkpoint.get("cursor"):
            cursor = checkpoint["cursor"]
            logger.info("Resuming SentinelOne collection from cursor: %s", cursor)

        current_events: List[LogEvent] = []
        last_cursor = None

        while True:
            params: Dict[str, Any] = {
                "createdAt__gte": time_window.to_iso8601_start(),
                "createdAt__lte": time_window.to_iso8601_end(),
                "limit": min(batch_size, 1000),
            }
            if cursor:
                params["cursor"] = cursor

            activity_types = self.credentials.get("activity_types")
            if activity_types:
                params["activityTypes"] = activity_types

            def _query_s1(p=params):
                return self.session.get(url=api_url, headers=headers, params=p, timeout=30)

            response = self.rate_limiter.execute(_query_s1, operation_name="SentinelOne Activities query")
            if response.status_code != 200:
                err_msg = f"SentinelOne API returned HTTP {response.status_code}: {response.text[:200]}"
                logger.error(err_msg)
                raise SourceAPIError(err_msg)

            result = safe_parse_json(response)
            records = result.get("data", [])
            if not records:
                logger.info("No records returned by SentinelOne. Finished collection.")
                break

            pagination = result.get("pagination", {})
            next_cursor = pagination.get("nextCursor")

            for rec in records:
                if isinstance(rec, dict):
                    event = self._build_event(rec)
                    current_events.append(event)

                    if len(current_events) >= batch_size:
                        yield LogBatch(
                            source=self.source_id,
                            events=current_events,
                            metadata={"cursor": next_cursor or cursor},
                        )
                        current_events = []

            if not next_cursor or next_cursor == cursor:
                logger.debug("No nextCursor found in SentinelOne response.")
                break

            cursor = next_cursor
            last_cursor = next_cursor

        if current_events:
            yield LogBatch(
                source=self.source_id,
                events=current_events,
                metadata={"cursor": last_cursor or cursor},
            )
