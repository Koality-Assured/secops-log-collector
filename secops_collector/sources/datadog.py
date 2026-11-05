"""Datadog Logs API collector plugin.

Queries Datadog Logs Search API (/api/v2/logs/events/search) with cursor pagination,
DD-API-KEY / DD-APPLICATION-KEY header authentication, and time-bounded filters.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, Iterator, List, Optional

from dateutil import parser as dt_parser

from secops_collector.core.models import LogBatch, LogEvent, TimeWindow
from secops_collector.sources.base import BaseSource

logger = logging.getLogger("secops_collector.sources.datadog")


class DatadogSource(BaseSource):
    """Collector for Datadog Logs API."""

    def __init__(self):
        super().__init__(source_id="datadog")

    def _get_api_url(self) -> str:
        """Resolve Datadog API URL (defaults to Datadog US1)."""
        base_url = self.credentials.get("datadog_url") or self.credentials.get("base_url", "https://api.datadoghq.com")
        base_url = base_url.rstrip("/")
        if not base_url.endswith("/api/v2/logs/events/search"):
            return f"{base_url}/api/v2/logs/events/search"
        return base_url

    def _get_headers(self) -> Dict[str, str]:
        """Construct authentication headers."""
        api_key = (
            self.credentials.get("api_key") or self.credentials.get("apisecret") or self.credentials.get("dd_api_key")
        )
        app_key = (
            self.credentials.get("app_key") or self.credentials.get("appsecret") or self.credentials.get("dd_app_key")
        )

        if not api_key or not app_key:
            raise ValueError("Datadog requires both 'api_key' and 'app_key' in credentials.")

        return {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _build_event(self, raw_record: Dict[str, Any]) -> LogEvent:
        """Map raw Datadog event JSON record into LogEvent."""
        event_id = raw_record.get("id") or ""
        attrs = raw_record.get("attributes", {})

        ts_val = attrs.get("timestamp")
        if ts_val:
            try:
                event_ts = dt_parser.isoparse(str(ts_val))
            except Exception:
                event_ts = datetime.datetime.now(datetime.timezone.utc)
        else:
            event_ts = datetime.datetime.now(datetime.timezone.utc)

        attributes = {
            "service": attrs.get("service"),
            "host": attrs.get("host"),
            "status": attrs.get("status"),
            "message": attrs.get("message"),
            "tags": attrs.get("tags", []),
        }

        return LogEvent(
            id=str(event_id),
            timestamp=event_ts,
            source=self.source_id,
            event_type="datadog.log.event",
            raw_payload=raw_record,
            attributes=attributes,
        )

    def collect(
        self,
        time_window: TimeWindow,
        checkpoint: Optional[Dict[str, Any]] = None,
    ) -> Iterator[LogBatch]:
        headers = self._get_headers()
        api_url = self._get_api_url()

        custom_query = self.credentials.get("filter_query") or self.credentials.get("query", "*")
        batch_size = self.config.batch_size if self.config else 500

        cursor = None
        if checkpoint and checkpoint.get("cursor"):
            cursor = checkpoint["cursor"]
            logger.info("Resuming Datadog log collection from cursor: %s", cursor)

        current_events: List[LogEvent] = []
        last_cursor = None

        while True:
            payload: Dict[str, Any] = {
                "filter": {
                    "query": custom_query,
                    "from": time_window.to_iso8601_start(),
                    "to": time_window.to_iso8601_end(),
                },
                "sort": "timestamp",
                "page": {
                    "limit": min(batch_size, 1000),
                },
            }
            if cursor:
                payload["page"]["cursor"] = cursor

            def _query_datadog(p=payload):
                return self.session.post(url=api_url, headers=headers, json=p, timeout=30)

            response = self.rate_limiter.execute(_query_datadog, operation_name="Datadog Logs search")
            if response.status_code != 200:
                logger.error("Datadog search returned HTTP %d: %s", response.status_code, response.text[:200])
                break

            result = response.json()
            data = result.get("data", [])
            if not data:
                logger.info("No more events returned by Datadog. Pagination complete.")
                break

            for rec in data:
                if isinstance(rec, dict):
                    event = self._build_event(rec)
                    current_events.append(event)

                    if len(current_events) >= batch_size:
                        yield LogBatch(
                            source=self.source_id,
                            events=current_events,
                            metadata={"cursor": last_cursor},
                        )
                        current_events = []

            meta = result.get("meta", {})
            page_info = meta.get("page", {})
            next_cursor = page_info.get("after")

            if not next_cursor or next_cursor == cursor:
                logger.debug("No subsequent cursor returned by Datadog API.")
                break

            cursor = next_cursor
            last_cursor = next_cursor

        if current_events:
            yield LogBatch(
                source=self.source_id,
                events=current_events,
                metadata={"cursor": last_cursor},
            )
