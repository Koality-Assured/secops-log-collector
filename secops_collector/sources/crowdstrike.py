"""CrowdStrike Falcon Event and Vulnerability API collector plugin.

Implements OAuth2 token negotiation, Spotlight Vulnerabilities API pagination
via FQL filters and cursor tokens, and standardized telemetry parsing.
"""

from __future__ import annotations

import datetime
import logging
import time
from typing import Any, Dict, Iterator, List, Optional

from dateutil import parser as dt_parser

from secops_collector.core.models import LogBatch, LogEvent, TimeWindow
from secops_collector.sources.base import BaseSource

logger = logging.getLogger("secops_collector.sources.crowdstrike")


class CrowdStrikeSource(BaseSource):
    """Collector for CrowdStrike Falcon API."""

    def __init__(self):
        super().__init__(source_id="crowdstrike")
        self._cached_bearer_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    def _get_base_url(self) -> str:
        """Resolve CrowdStrike API base URL."""
        url = self.credentials.get("base_url") or self.credentials.get("cs_url", "https://api.crowdstrike.com")
        return url.rstrip("/")

    def _ensure_access_token(self) -> str:
        """Authenticate via OAuth2 client credentials and cache token."""
        now = time.time()
        # Allow 60 seconds buffer before expiration
        if self._cached_bearer_token and now < (self._token_expires_at - 60):
            return self._cached_bearer_token

        client_id = self.credentials.get("client_id")
        client_secret = self.credentials.get("client_secret") or self.credentials.get("secret_token")

        if not client_id or not client_secret:
            raise ValueError("CrowdStrike requires 'client_id' and 'client_secret' in credentials.")

        oauth_url = f"{self._get_base_url()}/oauth2/token"
        auth_payload = {
            "client_id": client_id,
            "client_secret": client_secret,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        def _call_oauth():
            return self.session.post(url=oauth_url, data=auth_payload, headers=headers, timeout=30)

        response = self.rate_limiter.execute(_call_oauth, operation_name="CrowdStrike OAuth token negotiation")
        if response.status_code != 201 and response.status_code != 200:
            raise RuntimeError(f"CrowdStrike OAuth failed (HTTP {response.status_code}): {response.text[:200]}")

        data = response.json()
        token = data.get("access_token")
        expires_in = data.get("expires_in", 1800)

        if not token:
            raise RuntimeError("No access_token returned in CrowdStrike OAuth response.")

        self._cached_bearer_token = token
        self._token_expires_at = now + float(expires_in)
        logger.info("Successfully refreshed CrowdStrike Falcon OAuth token (expires in %ds)", expires_in)
        return token

    def _build_event(self, raw_record: Dict[str, Any]) -> LogEvent:
        """Map raw CrowdStrike record to LogEvent."""
        event_id = raw_record.get("id") or raw_record.get("composite_id") or ""
        ts_str = (
            raw_record.get("updated_timestamp") or raw_record.get("created_timestamp") or raw_record.get("timestamp")
        )

        if ts_str:
            try:
                event_ts = dt_parser.isoparse(ts_str)
            except Exception:
                event_ts = datetime.datetime.now(datetime.timezone.utc)
        else:
            event_ts = datetime.datetime.now(datetime.timezone.utc)

        cve = raw_record.get("cve", {})
        host_info = raw_record.get("host_info", {})

        attributes = {
            "cve_id": cve.get("id") if isinstance(cve, dict) else None,
            "severity": cve.get("severity") if isinstance(cve, dict) else raw_record.get("severity"),
            "status": raw_record.get("status"),
            "aid": raw_record.get("aid") or host_info.get("aid"),
            "hostname": host_info.get("hostname"),
            "local_ip": host_info.get("local_ip"),
        }

        return LogEvent(
            id=str(event_id),
            timestamp=event_ts,
            source=self.source_id,
            event_type="crowdstrike.spotlight.vulnerability",
            raw_payload=raw_record,
            attributes=attributes,
        )

    def collect(
        self,
        time_window: TimeWindow,
        checkpoint: Optional[Dict[str, Any]] = None,
    ) -> Iterator[LogBatch]:
        token = self._ensure_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        endpoint = f"{self._get_base_url()}/spotlight/combined/vulnerabilities/v1"
        cursor = None

        if checkpoint and checkpoint.get("after_cursor"):
            cursor = checkpoint["after_cursor"]
            logger.info("Resuming CrowdStrike collection from cursor: %s", cursor)

        iso_start = time_window.to_iso8601_start()
        # FQL filter syntax: updated_timestamp:>'2026-11-05T10:00:00Z'
        fql_filter = f"updated_timestamp:>'{iso_start}'"

        batch_size = self.config.batch_size if self.config else 500
        current_events: List[LogEvent] = []
        last_cursor = None

        while True:
            params: Dict[str, Any] = {
                "filter": fql_filter,
                "limit": 400,
            }
            if cursor:
                params["after"] = cursor

            def _query_endpoint(p=params):
                return self.session.get(url=endpoint, headers=headers, params=p, timeout=30)

            response = self.rate_limiter.execute(_query_endpoint, operation_name="CrowdStrike Spotlight query")
            if response.status_code != 200:
                logger.error("CrowdStrike query failed (HTTP %d): %s", response.status_code, response.text[:200])
                break

            result = response.json()
            resources = result.get("resources", [])
            if not resources:
                logger.info("No more resources returned by CrowdStrike. Ending collection.")
                break

            for rec in resources:
                if isinstance(rec, dict):
                    event = self._build_event(rec)
                    current_events.append(event)

                    if len(current_events) >= batch_size:
                        yield LogBatch(
                            source=self.source_id,
                            events=current_events,
                            metadata={"after_cursor": last_cursor},
                        )
                        current_events = []

            meta = result.get("meta", {})
            pagination = meta.get("pagination", {})
            next_after = pagination.get("after")

            if not next_after or next_after == cursor:
                logger.debug("Reached end of CrowdStrike pagination sequence.")
                break

            cursor = next_after
            last_cursor = next_after

        if current_events:
            yield LogBatch(
                source=self.source_id,
                events=current_events,
                metadata={"after_cursor": last_cursor},
            )
