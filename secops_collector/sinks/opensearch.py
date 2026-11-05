"""OpenSearch / Elasticsearch Bulk Ingest sink plugin.

Formats log events into NDJSON bulk indexing requests for OpenSearch / Elasticsearch clusters.
"""

from __future__ import annotations

import json
import logging

import requests

from secops_collector.core.models import LogBatch
from secops_collector.sinks.base import BaseSink

logger = logging.getLogger("secops_collector.sinks.opensearch")


class OpenSearchSink(BaseSink):
    """Output sink indexing events to OpenSearch / Elasticsearch via _bulk API."""

    def __init__(self):
        super().__init__(sink_id="opensearch")
        self.session: requests.Session = requests.Session()

    def _get_bulk_url(self) -> str:
        base_url = (
            self.credentials.get("opensearch_url")
            or self.credentials.get("es_url")
            or self.credentials.get("url", "https://localhost:9200")
        ).rstrip("/")
        if not base_url.endswith("/_bulk"):
            return f"{base_url}/_bulk"
        return base_url

    def _get_index_name(self, batch: LogBatch) -> str:
        pattern = self.credentials.get("index_pattern", "secops-{source}-{date}")
        date_str = batch.collected_at.strftime("%Y.%m.%d")
        return pattern.format(source=batch.source, date=date_str)

    def write(self, batch: LogBatch) -> int:
        if not batch.events:
            return 0

        bulk_url = self._get_bulk_url()
        index_name = self._get_index_name(batch)

        lines = []
        for evt in batch.events:
            action = {"index": {"_index": index_name, "_id": evt.id}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(evt.to_dict(), default=str))

        # Bulk requests require trailing newline
        ndjson_body = "\n".join(lines) + "\n"

        headers = {
            "Content-Type": "application/x-ndjson",
            "Accept": "application/json",
        }

        # Auth setup: Basic auth or Bearer
        auth = None
        username = self.credentials.get("username")
        password = self.credentials.get("password")
        token = self.credentials.get("token") or self.credentials.get("api_key")

        if username and password:
            auth = (username, password)
        elif token:
            headers["Authorization"] = f"Bearer {token}"

        def _send_bulk():
            return self.session.post(
                url=bulk_url,
                headers=headers,
                data=ndjson_body.encode("utf-8"),
                auth=auth,
                timeout=30,
            )

        response = self.rate_limiter.execute(_send_bulk, operation_name="OpenSearch bulk ingest")
        if response.status_code not in (200, 201):
            logger.error("OpenSearch _bulk failed with HTTP %d: %s", response.status_code, response.text[:200])
            raise RuntimeError(f"OpenSearch bulk ingest failed with HTTP {response.status_code}")

        res_json = response.json()
        has_errors = res_json.get("errors", False)
        items = res_json.get("items", [])

        if has_errors:
            error_count = sum(1 for item in items if any(action.get("error") for action in item.values()))
            logger.warning("OpenSearch indexed with %d item-level errors out of %d items.", error_count, len(items))
            return len(items) - error_count

        logger.info("Successfully indexed %d records into OpenSearch (%s)", len(items), index_name)
        return len(items)
