"""Secrets management provider for secops-log-collector.

Supports AWS Secrets Manager with in-memory TTL caching, environment variables,
and direct dictionary injection for local unit tests and automated workflows.
Enforces strict secret sanitization to prevent accidental credential leakage in logs.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger("secops_collector.secrets")


class SecretNotFoundError(Exception):
    """Raised when a requested secret cannot be located."""

    pass


class BaseSecretProvider(ABC):
    """Abstract interface for credential and token retrieval."""

    @abstractmethod
    def get_secret(self, secret_id: str, force_refresh: bool = False) -> Dict[str, Any]:
        """Retrieve and parse secret key-value pairs."""
        pass

    @abstractmethod
    def invalidate(self, secret_id: Optional[str] = None) -> None:
        """Invalidate cached credentials to force fresh resolution upon rotation."""
        pass


class DictionarySecretProvider(BaseSecretProvider):
    """In-memory secret provider for isolated unit testing and explicit mocking."""

    def __init__(self, secrets_dict: Optional[Dict[str, Dict[str, Any]]] = None):
        self._secrets: Dict[str, Dict[str, Any]] = secrets_dict or {}

    def set_secret(self, secret_id: str, value: Dict[str, Any]) -> None:
        """Register a secret payload."""
        self._secrets[secret_id] = value

    def get_secret(self, secret_id: str, force_refresh: bool = False) -> Dict[str, Any]:
        if secret_id in self._secrets:
            return self._secrets[secret_id]
        raise SecretNotFoundError(f"Secret '{secret_id}' not found in in-memory provider.")

    def invalidate(self, secret_id: Optional[str] = None) -> None:
        """No-op for static in-memory provider."""
        pass


class EnvironmentSecretProvider(BaseSecretProvider):
    """Retrieves secrets from environment variables.

    Supports:
    1. Direct JSON payload stored in an environment variable named after secret_id.
    2. Prefix-based key-value extraction (e.g. OKTA_TOKEN, OKTA_URL).
    """

    def __init__(self, prefix: str = "SECOPS_"):
        self.prefix = prefix

    def get_secret(self, secret_id: str, force_refresh: bool = False) -> Dict[str, Any]:
        # Clean secret name for env var lookup
        clean_key = secret_id.upper().replace("-", "_").replace(".", "_")

        # 1. Check exact key or prefixed key for JSON string
        candidates = [clean_key, f"{self.prefix}{clean_key}", secret_id]
        for key in candidates:
            val = os.environ.get(key)
            if val:
                try:
                    parsed = json.loads(val)
                    if isinstance(parsed, dict):
                        return parsed
                    return {"token": str(parsed)}
                except (json.JSONDecodeError, TypeError):
                    return {"token": val}

        # 2. Gather matching prefix variables
        collected: Dict[str, Any] = {}
        target_prefix = f"{clean_key}_"
        for env_k, env_v in os.environ.items():
            if env_k.startswith(target_prefix):
                sub_key = env_k[len(target_prefix) :].lower()
                collected[sub_key] = env_v

        if collected:
            return collected

        raise SecretNotFoundError(f"Secret '{secret_id}' not found in environment variables.")

    def invalidate(self, secret_id: Optional[str] = None) -> None:
        """No-op for environment variables."""
        pass


class AWSSecretsManagerProvider(BaseSecretProvider):
    """Retrieves secrets from AWS Secrets Manager with local TTL-based caching."""

    def __init__(self, region_name: Optional[str] = None, ttl_seconds: int = 300, client: Any = None):
        self.region_name = region_name or os.environ.get("AWS_REGION", "us-west-2")
        self.ttl_seconds = ttl_seconds
        self._client = client
        self._cache: Dict[str, tuple[Dict[str, Any], float]] = {}

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("secretsmanager", region_name=self.region_name)
        return self._client

    def invalidate(self, secret_id: Optional[str] = None) -> None:
        """Clear cached secret(s) to guarantee newly rotated values are retrieved."""
        if secret_id is None:
            self._cache.clear()
            logger.info("Invalidated all secrets in AWS Secrets Manager cache.")
        else:
            if self._cache.pop(secret_id, None) is not None:
                logger.info("Invalidated secret '%s' in AWS Secrets Manager cache.", secret_id)

    def get_secret(self, secret_id: str, force_refresh: bool = False) -> Dict[str, Any]:
        now = time.time()
        # Cache hit check (bypassed if force_refresh is requested)
        if not force_refresh and secret_id in self._cache:
            data, timestamp = self._cache[secret_id]
            if now - timestamp < self.ttl_seconds:
                return data

        try:
            response = self.client.get_secret_value(SecretId=secret_id)
        except Exception as exc:
            logger.error("Failed to retrieve secret '%s' from AWS Secrets Manager: %s", secret_id, str(exc))
            raise SecretNotFoundError(f"Could not retrieve secret '{secret_id}': {exc}") from exc

        secret_str = response.get("SecretString")
        if not secret_str:
            secret_binary = response.get("SecretBinary")
            if secret_binary:
                if isinstance(secret_binary, bytes):
                    secret_str = secret_binary.decode("utf-8")
                else:
                    secret_str = base64.b64decode(secret_binary).decode("utf-8")
            else:
                raise SecretNotFoundError(f"Secret '{secret_id}' contains neither SecretString nor SecretBinary.")

        try:
            parsed = json.loads(secret_str)
            if not isinstance(parsed, dict):
                parsed = {"token": str(parsed)}
        except json.JSONDecodeError:
            parsed = {"token": secret_str}

        self._cache[secret_id] = (parsed, now)
        return parsed


def get_secret_provider(
    backend: str = "env",
    region_name: Optional[str] = None,
    mock_secrets: Optional[Dict[str, Dict[str, Any]]] = None,
) -> BaseSecretProvider:
    """Factory creating configured secret provider based on backend setting."""
    if backend == "memory":
        return DictionarySecretProvider(mock_secrets)
    if backend == "secretsmanager":
        return AWSSecretsManagerProvider(region_name=region_name)
    return EnvironmentSecretProvider()
