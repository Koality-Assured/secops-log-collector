"""Unit tests for secops_collector.core.state."""

import json
from unittest.mock import MagicMock

from secops_collector.core.state import (
    InMemoryStateStore,
    S3StateStore,
    SSMParameterStateStore,
    get_state_store,
)


def test_in_memory_state_store():
    store = InMemoryStateStore()
    assert store.get_checkpoint("okta") is None

    store.save_checkpoint("okta", {"cursor": "cur_1", "last_ts": "2026-11-05T12:00:00Z"})
    cp = store.get_checkpoint("okta")
    assert cp["cursor"] == "cur_1"
    assert cp["last_ts"] == "2026-11-05T12:00:00Z"


def test_s3_state_store():
    mock_s3 = MagicMock()
    store = S3StateStore(bucket_name="secops-lake-bucket", prefix="checkpoints", client=mock_s3)

    # Test save
    store.save_checkpoint("crowdstrike", {"after_cursor": "abc"})
    mock_s3.put_object.assert_called_once()
    call_args = mock_s3.put_object.call_args[1]
    assert call_args["Bucket"] == "secops-lake-bucket"
    assert call_args["Key"] == "checkpoints/crowdstrike.json"

    # Test load
    mock_body = MagicMock()
    mock_body.read.return_value = json.dumps({"after_cursor": "abc"}).encode("utf-8")
    mock_s3.get_object.return_value = {"Body": mock_body}

    loaded = store.get_checkpoint("crowdstrike")
    assert loaded["after_cursor"] == "abc"


def test_ssm_parameter_state_store():
    mock_ssm = MagicMock()
    store = SSMParameterStateStore(prefix="/secops/checkpoints", client=mock_ssm)

    # Test save
    store.save_checkpoint("github", {"next_url": "https://api.github.com/page2"})
    mock_ssm.put_parameter.assert_called_once()
    call_args = mock_ssm.put_parameter.call_args[1]
    assert call_args["Name"] == "/secops/checkpoints/github"

    # Test load
    mock_ssm.get_parameter.return_value = {
        "Parameter": {"Value": json.dumps({"next_url": "https://api.github.com/page2"})}
    }
    loaded = store.get_checkpoint("github")
    assert loaded["next_url"] == "https://api.github.com/page2"


def test_get_state_store_factory():
    s1 = get_state_store("memory")
    assert isinstance(s1, InMemoryStateStore)

    s2 = get_state_store("s3", bucket_or_prefix="my-bucket")
    assert isinstance(s2, S3StateStore)

    s3 = get_state_store("ssm", bucket_or_prefix="/custom/path")
    assert isinstance(s3, SSMParameterStateStore)
