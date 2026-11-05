"""State checkpoint store for secops-log-collector.

Maintains pagination tokens, cursors, and watermarks across ephemeral serverless
executions to guarantee exactly-once or at-least-once log processing without gaps.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger("secops_collector.state")


class BaseStateStore(ABC):
    """Abstract interface for checkpoint storage."""

    @abstractmethod
    def get_checkpoint(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the last saved checkpoint for a source."""
        pass

    @abstractmethod
    def save_checkpoint(self, source_id: str, checkpoint: Dict[str, Any]) -> None:
        """Persist a checkpoint for a source."""
        pass


class InMemoryStateStore(BaseStateStore):
    """In-memory state store for tests, dry-runs, and single-batch pipelines."""

    def __init__(self, initial_state: Optional[Dict[str, Dict[str, Any]]] = None):
        self._state: Dict[str, Dict[str, Any]] = initial_state or {}

    def get_checkpoint(self, source_id: str) -> Optional[Dict[str, Any]]:
        return self._state.get(source_id)

    def save_checkpoint(self, source_id: str, checkpoint: Dict[str, Any]) -> None:
        self._state[source_id] = checkpoint


class S3StateStore(BaseStateStore):
    """Persists checkpoints as JSON objects in an AWS S3 data lake bucket."""

    def __init__(self, bucket_name: str, prefix: str = "secops-checkpoints/", client: Any = None):
        self.bucket_name = bucket_name
        self.prefix = prefix.strip("/") + "/"
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("s3")
        return self._client

    def _get_key(self, source_id: str) -> str:
        return f"{self.prefix}{source_id}.json"

    def get_checkpoint(self, source_id: str) -> Optional[Dict[str, Any]]:
        key = self._get_key(source_id)
        try:
            resp = self.client.get_object(Bucket=self.bucket_name, Key=key)
            body = resp["Body"].read().decode("utf-8")
            return json.loads(body)
        except Exception as exc:
            # S3 NoSuchKey or client error
            logger.debug(
                "No existing checkpoint found for '%s' in s3://%s/%s: %s",
                source_id,
                self.bucket_name,
                key,
                exc,
            )
            return None

    def save_checkpoint(self, source_id: str, checkpoint: Dict[str, Any]) -> None:
        key = self._get_key(source_id)
        body = json.dumps(checkpoint, indent=2)
        try:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=body.encode("utf-8"),
                ContentType="application/json",
            )
            logger.info("Saved checkpoint for '%s' to s3://%s/%s", source_id, self.bucket_name, key)
        except Exception as exc:
            logger.error("Failed to save checkpoint for '%s' to S3: %s", source_id, exc)
            raise


class SSMParameterStateStore(BaseStateStore):
    """Persists checkpoints in AWS Systems Manager Parameter Store."""

    def __init__(self, prefix: str = "/secops/checkpoints/", client: Any = None):
        self.prefix = prefix.rstrip("/") + "/"
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("ssm")
        return self._client

    def _get_param_name(self, source_id: str) -> str:
        return f"{self.prefix}{source_id}"

    def get_checkpoint(self, source_id: str) -> Optional[Dict[str, Any]]:
        param_name = self._get_param_name(source_id)
        try:
            resp = self.client.get_parameter(Name=param_name)
            value = resp["Parameter"]["Value"]
            return json.loads(value)
        except Exception as exc:
            logger.debug("No existing SSM parameter checkpoint for '%s': %s", param_name, exc)
            return None

    def save_checkpoint(self, source_id: str, checkpoint: Dict[str, Any]) -> None:
        param_name = self._get_param_name(source_id)
        value = json.dumps(checkpoint)
        try:
            self.client.put_parameter(
                Name=param_name,
                Value=value,
                Type="String",
                Overwrite=True,
            )
            logger.info("Saved checkpoint for '%s' to SSM parameter %s", source_id, param_name)
        except Exception as exc:
            logger.error("Failed to save checkpoint to SSM: %s", exc)
            raise


def get_state_store(
    backend: str = "memory",
    bucket_or_prefix: Optional[str] = None,
    mock_store: Optional[Dict[str, Dict[str, Any]]] = None,
) -> BaseStateStore:
    """Factory creating configured state store."""
    if backend == "memory":
        return InMemoryStateStore(mock_store)
    if backend == "s3" and bucket_or_prefix:
        return S3StateStore(bucket_name=bucket_or_prefix)
    if backend == "ssm":
        return SSMParameterStateStore(prefix=bucket_or_prefix or "/secops/checkpoints/")
    return InMemoryStateStore(mock_store)
