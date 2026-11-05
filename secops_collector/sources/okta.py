"""Okta System Log API collector plugin.

Fetches security audit events from Okta System Log API (/api/v1/logs)
using RFC 5988 Link header pagination, boundary time-window rounding,
and robust rate limit handling.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, Iterator, List, Optional

from dateutil import parser as dt_parser

from secops_collector.core.models import LogBatch, LogEvent, TimeWindow
from secops_collector.sources.base import BaseSource

logger = logging.getLogger("secops_collector.sources.okta")


class OktaSource(BaseSource):
    """Collector for Okta System Log API."""

    def __init__(self):
        super().__init__(source_id="okta")

    def _get_api_url(self) -> str:
        """Resolve base Okta API URL."""
        base_url = self.credentials.get("okta_url") or self.credentials.get("url", "https://example.okta.com")
        base_url = base_url.rstrip("/")
        if not base_url.endswith("/api/v1/logs"):
            return f"{base_url}/api/v1/logs"
        return base_url

    def _get_token(self) -> str:
        """Extract API token."""
        token = self.credentials.get("okta_token") or self.credentials.get("token") or self.credentials.get("api_token")
        if not token:
            raise ValueError("Okta API token ('okta_token' or 'token') is required in credentials.")
        return token

    def _build_event(self, raw_record: Dict[str, Any]) -> LogEvent:
        """Map raw Okta log JSON record into standardized LogEvent."""
        event_id = raw_record.get("eventId") or raw_record.get("uuid") or ""

        # Parse timestamp from 'published' field
        published_str = raw_record.get("published")
        if published_str:
            try:
                event_ts = dt_parser.isoparse(published_str)
            except Exception:
                event_ts = datetime.datetime.now(datetime.timezone.utc)
        else:
            event_ts = datetime.datetime.now(datetime.timezone.utc)

        event_type = raw_record.get("eventType", "okta.system.log")

        actor = raw_record.get("actor", {})
        client = raw_record.get("client", {})
        outcome = raw_record.get("outcome", {})

        attributes = {
            "actor_alternate_id": actor.get("alternateId"),
            "actor_type": actor.get("type"),
            "ip_address": client.get("ipAddress"),
            "outcome_result": outcome.get("result"),
            "outcome_reason": outcome.get("reason"),
            "display_message": raw_record.get("displayMessage"),
        }

        return LogEvent(
            id=str(event_id),
            timestamp=event_ts,
            source=self.source_id,
            event_type=str(event_type),
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
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        next_url = None
        params = None

        if checkpoint and checkpoint.get("next_url"):
            next_url = checkpoint["next_url"]
            logger.info("Resuming Okta collection from checkpoint cursor URL: %s", next_url)
        else:
            # ISO format: YYYY-MM-DDTHH:mm:ss.sssZ
            params = {
                "since": time_window.to_iso8601_start(),
                "until": time_window.to_iso8601_end(),
                "limit": 1000,
            }
            logger.info("Initiating Okta collection for window [%s - %s]", params["since"], params["until"])

        batch_size = self.config.batch_size if self.config else 500
        current_events: List[LogEvent] = []
        last_event_ts = None

        while True:
            target_url = next_url if next_url else self._get_api_url()
            request_params = None if next_url else params

            def _call_api(u=target_url, p=request_params):
                return self.session.get(
                    url=u,
                    headers=headers,
                    params=p,
                    timeout=30,
                )

            response = self.rate_limiter.execute(_call_api, operation_name="Okta Logs API query")

            if response.status_code != 200:
                logger.error("Okta API returned HTTP %d: %s", response.status_code, response.text[:200])
                break

            records = response.json()
            if not isinstance(records, list) or not records:
                logger.info("Okta API returned zero new records. Ending pagination.")
                break

            for rec in records:
                if isinstance(rec, dict):
                    event = self._build_event(rec)
                    current_events.append(event)
                    last_event_ts = event.timestamp

                    if len(current_events) >= batch_size:
                        yield LogBatch(
                            source=self.source_id,
                            events=current_events,
                            metadata={"last_timestamp": last_event_ts.isoformat() if last_event_ts else None},
                        )
                        current_events = []

            # RFC 5988 next link parsing
            links = response.links
            next_link_info = links.get("next")
            if next_link_info and "url" in next_link_info:
                candidate_next = next_link_info["url"]
                # Safeguard against circular or identical self-referencing next links
                if candidate_next == target_url:
                    logger.debug("Next link equals current link; reached end of stream.")
                    break
                next_url = candidate_next
            else:
                logger.debug("No next Link header returned by Okta.")
                break

        # Yield any remaining collected events
        if current_events:
            yield LogBatch(
                source=self.source_id,
                events=current_events,
                metadata={"last_timestamp": last_event_ts.isoformat() if last_event_ts else None},
            )
