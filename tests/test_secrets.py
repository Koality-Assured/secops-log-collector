"""Unit tests for secops_collector.core.secrets."""

import json
from unittest.mock import MagicMock

import pytest

from secops_collector.core.secrets import (
    AWSSecretsManagerProvider,
    DictionarySecretProvider,
    EnvironmentSecretProvider,
    SecretNotFoundError,
    get_secret_provider,
)


def test_dictionary_secret_provider():
    provider = DictionarySecretProvider({"secops-okta": {"token": "secret123"}})
    assert provider.get_secret("secops-okta") == {"token": "secret123"}

    provider.set_secret("secops-cs", {"client_id": "id1", "client_secret": "sec1"})
    assert provider.get_secret("secops-cs")["client_id"] == "id1"

    with pytest.raises(SecretNotFoundError):
        provider.get_secret("non-existent")


def test_environment_secret_provider(monkeypatch):
    provider = EnvironmentSecretProvider()

    # Test exact JSON in env var
    monkeypatch.setenv("SECOPS_OKTA_TOKEN", json.dumps({"token": "env_tok_123"}))
    creds = provider.get_secret("secops-okta-token")
    assert creds == {"token": "env_tok_123"}

    # Test prefix variables
    monkeypatch.setenv("SECOPS_DD_API_KEY", "dd_api_123")
    monkeypatch.setenv("SECOPS_DD_APP_KEY", "dd_app_123")
    dd_creds = provider.get_secret("secops-dd")
    assert dd_creds["api_key"] == "dd_api_123"
    assert dd_creds["app_key"] == "dd_app_123"

    with pytest.raises(SecretNotFoundError):
        provider.get_secret("unknown_secret_id")


def test_aws_secrets_manager_provider_with_caching():
    mock_boto_client = MagicMock()
    mock_boto_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"token": "aws_token_xyz"}),
    }

    provider = AWSSecretsManagerProvider(client=mock_boto_client, ttl_seconds=60)

    # First fetch: calls client
    creds1 = provider.get_secret("my-sec-secret")
    assert creds1 == {"token": "aws_token_xyz"}
    assert mock_boto_client.get_secret_value.call_count == 1

    # Second fetch within TTL: returns cached
    creds2 = provider.get_secret("my-sec-secret")
    assert creds2 == {"token": "aws_token_xyz"}
    assert mock_boto_client.get_secret_value.call_count == 1

    # Invalidate forces fresh client fetch
    provider.invalidate("my-sec-secret")
    mock_boto_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"token": "rotated_token_456"}),
    }
    creds3 = provider.get_secret("my-sec-secret")
    assert creds3 == {"token": "rotated_token_456"}
    assert mock_boto_client.get_secret_value.call_count == 2

    # force_refresh=True also bypasses cache
    mock_boto_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"token": "force_refreshed_789"}),
    }
    creds4 = provider.get_secret("my-sec-secret", force_refresh=True)
    assert creds4 == {"token": "force_refreshed_789"}
    assert mock_boto_client.get_secret_value.call_count == 3


def test_aws_secrets_manager_provider_binary_secret():
    mock_boto_client = MagicMock()
    mock_boto_client.get_secret_value.return_value = {
        "SecretBinary": json.dumps({"token": "binary_token"}).encode("utf-8"),
    }
    provider = AWSSecretsManagerProvider(client=mock_boto_client, ttl_seconds=60)
    creds = provider.get_secret("binary-secret")
    assert creds == {"token": "binary_token"}


def test_get_secret_provider_factory():
    p1 = get_secret_provider("memory", mock_secrets={"test": {"a": 1}})
    assert isinstance(p1, DictionarySecretProvider)
    assert p1.get_secret("test") == {"a": 1}

    p2 = get_secret_provider("env")
    assert isinstance(p2, EnvironmentSecretProvider)

    p3 = get_secret_provider("secretsmanager")
    assert isinstance(p3, AWSSecretsManagerProvider)
