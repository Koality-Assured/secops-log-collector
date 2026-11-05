"""CrowdStrike LogScale / Humio JSON Ingest API sink plugin.

Delivers structured log batches to LogScale Ingest endpoint (/api/v1/ingest/json)
with Bearer token authentication and payload envelope formatting.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import requests

from secops_collector.core.models import LogBatch
from secops_collector.sinks.base import BaseSink

logger = logging.getLogger("secops_collector.sinks.logscale")


class LogScaleSink(BaseSink):
    """Output sink delivering logs to CrowdStrike LogScale / Humio Ingestion API."""

    def __init__(self):
        super().__init__(sink_id="logscale")
        self.session: requests.Session = requests.Session()

    def _get_ingest_url(self) -> str:
        url = (
            self.credentials.get("logscale_url")
            or self.credentials.get("ls_url")
            or self.credentials.get("ingest_url", "https://cloud.humio.com/api/v1/ingest/json")
        )
        url = url.rstrip("/")
        if not url.endswith("/api/v1/ingest/json"):
            return f"{url}/api/v1/ingest/json"
        return url

    def _get_token(self) -> str:
        token = (
            self.credentials.get("logscale_token")
            or self.credentials.get("ls_token")
            or self.credentials.get("ingest_token")
            or self.credentials.get("token")
        )
        if not token:
            raise ValueError("LogScale sink requires 'logscale_token' or 'token' in credentials.")
        return token

    def _format_payload(self, batch: LogBatch) -> List[Dict[str, Any]]:
        """Construct standard LogScale envelope payload."""
        events_list = []
        for evt in batch.events:
            events_list.append(
                {
                    "timestamp": evt.timestamp.isoformat(),
                    "attributes": evt.to_dict(),
                }
            )

        tags = {
            "source": batch.source,
            "pipeline": "secops-log-collector",
        }
        if "environment" in self.credentials:
            tags["env"] = str(self.credentials["environment"])

        return [
            {
                "tags": tags,
                "events": events_list,
            }
        ]

    def write(self, batch: LogBatch) -> int:
        if not batch.events:
            return 0

        ingest_url = self._get_ingest_url()
        token = self._get_token()

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = self._format_payload(batch)

        def _send():
            return self.session.post(
                url=ingest_url,
                headers=headers,
                json=payload,
                timeout=30,
            )

        response = self.rate_limiter.execute(_send, operation_name="LogScale JSON batch ingest")

        if response.status_code == 200:
            logger.info("Successfully delivered %d records to LogScale (%s)", batch.record_count, ingest_url)
            return batch.record_count

        logger.error(
            "LogScale delivery failed with HTTP %d: %s",
            response.status_code,
            response.text[:200] if response.text else "",
        )
        raise RuntimeError(f"LogScale ingest failed with HTTP {response.status_code}")
