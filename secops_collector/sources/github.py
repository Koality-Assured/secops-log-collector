"""GitHub Enterprise Audit Log API collector plugin.

Collects organizational and enterprise security audit events from GitHub API
with RFC 5988 Link header cursor pagination and timestamp boundaries.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, Iterator, List, Optional

from dateutil import parser as dt_parser

from secops_collector.core.models import LogBatch, LogEvent, TimeWindow
from secops_collector.sources.base import BaseSource, SourceAPIError, safe_parse_json

logger = logging.getLogger("secops_collector.sources.github")


class GitHubAuditSource(BaseSource):
    """Collector for GitHub Enterprise Audit Log API."""

    def __init__(self):
        super().__init__(source_id="github")

    def _get_api_url(self) -> str:
        """Resolve GitHub audit log endpoint."""
        explicit_url = self.credentials.get("github_url") or self.credentials.get("url")
        if explicit_url:
            return explicit_url.rstrip("/")

        base_api = self.credentials.get("base_url", "https://api.github.com").rstrip("/")
        org = self.credentials.get("org") or self.credentials.get("organization")
        enterprise = self.credentials.get("enterprise")

        if enterprise:
            return f"{base_api}/enterprises/{enterprise}/audit-log"
        if org:
            return f"{base_api}/orgs/{org}/audit-log"

        # Fallback to org endpoint template or default
        return f"{base_api}/orgs/example-org/audit-log"

    def _get_token(self) -> str:
        token = (
            self.credentials.get("github_token")
            or self.credentials.get("token")
            or self.credentials.get("access_token")
        )
        if not token:
            raise ValueError("GitHub collector requires 'github_token' or 'token' in credentials.")
        return token

    def _build_event(self, raw_record: Dict[str, Any]) -> LogEvent:
        """Map raw GitHub audit log entry into LogEvent."""
        event_id = raw_record.get("_document_id") or raw_record.get("id") or ""

        # GitHub audit logs provide '@timestamp' (epoch ms) or 'created_at' (ISO string)
        ts_raw = raw_record.get("@timestamp") or raw_record.get("created_at")
        if ts_raw:
            try:
                if isinstance(ts_raw, (int, float)):
                    event_ts = datetime.datetime.fromtimestamp(ts_raw / 1000.0, tz=datetime.timezone.utc)
                else:
                    event_ts = dt_parser.isoparse(str(ts_raw))
            except Exception:
                event_ts = datetime.datetime.now(datetime.timezone.utc)
        else:
            event_ts = datetime.datetime.now(datetime.timezone.utc)

        action = raw_record.get("action", "github.audit.event")
        attributes = {
            "actor": raw_record.get("actor"),
            "org": raw_record.get("org"),
            "repo": raw_record.get("repo"),
            "user": raw_record.get("user"),
            "action": action,
            "visibility": raw_record.get("visibility"),
            "actor_location": raw_record.get("actor_location", {}),
        }

        return LogEvent(
            id=str(event_id),
            timestamp=event_ts,
            source=self.source_id,
            event_type=str(action),
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
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        next_url = None
        params = None

        if checkpoint:
            if checkpoint.get("next_url"):
                next_url = checkpoint["next_url"]
                logger.info("Resuming GitHub audit log collection from checkpoint cursor URL: %s", next_url)
            elif checkpoint.get("last_timestamp"):
                params = {
                    "phrase": f"created:>={checkpoint['last_timestamp']}",
                    "per_page": 100,
                    "include": "all",
                }
                logger.info("Resuming GitHub audit log collection from checkpoint timestamp: %s", params["phrase"])
        if not next_url and not params:
            start_iso = time_window.to_iso8601_start()
            params = {
                "phrase": f"created:>={start_iso}",
                "per_page": 100,
                "include": "all",
            }
            logger.info("Initiating GitHub audit log collection with query: %s", params["phrase"])

        batch_size = self.config.batch_size if self.config else 500
        current_events: List[LogEvent] = []
        last_event_ts = None

        while True:
            target_url = next_url if next_url else self._get_api_url()
            req_params = None if next_url else params

            def _query_github(u=target_url, p=req_params):
                return self.session.get(url=u, headers=headers, params=p, timeout=30)

            response = self.rate_limiter.execute(_query_github, operation_name="GitHub Audit Log query")
            if response.status_code != 200:
                err_msg = f"GitHub Audit Log query returned HTTP {response.status_code}: {response.text[:200]}"
                logger.error(err_msg)
                raise SourceAPIError(err_msg)

            records = safe_parse_json(response)
            if not isinstance(records, list) or not records:
                logger.info("No audit records returned by GitHub. Collection finished.")
                break

            links = response.links
            next_link_info = links.get("next")
            candidate_next = next_link_info["url"] if (next_link_info and "url" in next_link_info) else None
            if candidate_next == target_url:
                candidate_next = None

            for rec in records:
                if isinstance(rec, dict):
                    event = self._build_event(rec)
                    current_events.append(event)
                    last_event_ts = event.timestamp

                    if len(current_events) >= batch_size:
                        yield LogBatch(
                            source=self.source_id,
                            events=current_events,
                            metadata={
                                "last_timestamp": last_event_ts.isoformat() if last_event_ts else None,
                                "next_url": candidate_next or target_url,
                            },
                        )
                        current_events = []

            if not candidate_next:
                break
            next_url = candidate_next

        if current_events:
            yield LogBatch(
                source=self.source_id,
                events=current_events,
                metadata={
                    "last_timestamp": last_event_ts.isoformat() if last_event_ts else None,
                    "next_url": next_url,
                },
            )
