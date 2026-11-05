"""AWS S3 Security Data Lake sink plugin.

Persists log batches as partitioned, gzip-compressed NDJSON objects:
s3://<bucket>/<prefix>/source=<source>/year=YYYY/month=MM/day=DD/hour=HH/<batch_id>.json.gz
"""

from __future__ import annotations

import gzip
import io
import logging
from typing import Any

import boto3

from secops_collector.core.models import LogBatch
from secops_collector.sinks.base import BaseSink

logger = logging.getLogger("secops_collector.sinks.s3")


class S3DataLakeSink(BaseSink):
    """Output sink writing compressed event batches to S3 Security Data Lake."""

    def __init__(self, s3_client: Any = None):
        super().__init__(sink_id="s3")
        self._s3_client = s3_client

    @property
    def s3_client(self) -> Any:
        if self._s3_client is None:
            region = self.credentials.get("aws_region") or self.credentials.get("region", "us-west-2")
            self._s3_client = boto3.client("s3", region_name=region)
        return self._s3_client

    def _get_bucket_name(self) -> str:
        bucket = (
            self.credentials.get("s3_bucket")
            or self.credentials.get("bucket")
            or (self.config.state_table_or_bucket if self.config else None)
        )
        if not bucket:
            raise ValueError("S3 sink requires 's3_bucket' or 'bucket' in credentials/config.")
        return bucket

    def _get_partition_key(self, batch: LogBatch) -> str:
        prefix = self.credentials.get("s3_prefix", "security-data-lake").strip("/")
        dt = batch.collected_at
        year = dt.strftime("%Y")
        month = dt.strftime("%m")
        day = dt.strftime("%d")
        hour = dt.strftime("%H")

        return (
            f"{prefix}/source={batch.source}/year={year}/month={month}/day={day}/hour={hour}/{batch.batch_id}.json.gz"
        )

    def write(self, batch: LogBatch) -> int:
        if not batch.events:
            return 0

        bucket = self._get_bucket_name()
        s3_key = self._get_partition_key(batch)

        ndjson_data = batch.to_ndjson()

        # Compress to gzip in-memory buffer
        gzip_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gzip_buffer, mode="wb") as gz:
            gz.write(ndjson_data.encode("utf-8"))
        compressed_bytes = gzip_buffer.getvalue()

        def _put_object():
            self.s3_client.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=compressed_bytes,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
                Metadata={
                    "source": batch.source,
                    "record_count": str(batch.record_count),
                    "batch_id": batch.batch_id,
                },
            )

        try:
            _put_object()
            logger.info(
                "Delivered %d records to s3://%s/%s (compressed %d bytes)",
                batch.record_count,
                bucket,
                s3_key,
                len(compressed_bytes),
            )
            return batch.record_count
        except Exception as exc:
            logger.error("Failed to write batch to s3://%s/%s: %s", bucket, s3_key, exc)
            raise
