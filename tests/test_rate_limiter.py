"""Unit tests for secops_collector.core.rate_limiter."""

from unittest.mock import MagicMock

import pytest
import requests

from secops_collector.core.rate_limiter import (
    ExecutionTimeoutError,
    RateLimitExceededError,
    RobustRateLimiter,
)


def test_parse_retry_after_seconds():
    limiter = RobustRateLimiter()
    assert limiter.parse_retry_after("30") == 30.0
    assert limiter.parse_retry_after(" 12.5 ") == 12.5
    assert limiter.parse_retry_after(None) is None
    assert limiter.parse_retry_after("") is None
    assert limiter.parse_retry_after("invalid-value") is None


def test_parse_retry_after_http_date():
    limiter = RobustRateLimiter()
    # RFC 7231 future date
    future_date_str = "Wed, 21 Oct 2099 07:28:00 GMT"
    parsed_delay = limiter.parse_retry_after(future_date_str)
    assert parsed_delay is not None
    assert parsed_delay > 1000000.0


def test_execute_successful_request():
    limiter = RobustRateLimiter(max_retries=3)
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200

    mock_req = MagicMock(return_value=mock_resp)
    result = limiter.execute(mock_req)

    assert result.status_code == 200
    assert mock_req.call_count == 1
    assert limiter.total_rate_limit_hits == 0


def test_execute_retry_after_429_success(mock_sleep_recorder):
    limiter = RobustRateLimiter(
        max_retries=3,
        base_backoff_seconds=1.0,
        sleep_fn=mock_sleep_recorder,
    )

    resp_429 = MagicMock(spec=requests.Response)
    resp_429.status_code = 429
    resp_429.headers = {"Retry-After": "3"}

    resp_200 = MagicMock(spec=requests.Response)
    resp_200.status_code = 200
    resp_200.headers = {}

    mock_req = MagicMock(side_effect=[resp_429, resp_200])

    result = limiter.execute(mock_req)
    assert result.status_code == 200
    assert mock_req.call_count == 2
    assert limiter.total_rate_limit_hits == 1
    assert len(mock_sleep_recorder.sleeps) == 1
    assert mock_sleep_recorder.sleeps[0] == 3.0


def test_execute_max_retries_exceeded(mock_sleep_recorder):
    limiter = RobustRateLimiter(
        max_retries=2,
        base_backoff_seconds=0.5,
        sleep_fn=mock_sleep_recorder,
    )

    resp_429 = MagicMock(spec=requests.Response)
    resp_429.status_code = 429
    resp_429.headers = {}
    resp_429.text = "Too Many Requests"

    mock_req = MagicMock(return_value=resp_429)

    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.execute(mock_req)

    assert exc_info.value.status_code == 429
    assert mock_req.call_count == 3  # initial + 2 retries
    assert len(mock_sleep_recorder.sleeps) == 2


def test_execute_transient_network_error(mock_sleep_recorder):
    limiter = RobustRateLimiter(
        max_retries=2,
        base_backoff_seconds=0.5,
        sleep_fn=mock_sleep_recorder,
    )

    resp_200 = MagicMock(spec=requests.Response)
    resp_200.status_code = 200

    mock_req = MagicMock(side_effect=[requests.ConnectionError("Connection dropped"), resp_200])

    result = limiter.execute(mock_req)
    assert result.status_code == 200
    assert mock_req.call_count == 2
    assert len(mock_sleep_recorder.sleeps) == 1


def test_execute_timeout_deadline_exceeded(mock_sleep_recorder):
    # Simulated Lambda remaining time = 20 seconds, reserve = 15 seconds
    # Retry-After = 30 seconds -> total required = 45s > 20s -> triggers ExecutionTimeoutError
    remaining_time = 20.0
    limiter = RobustRateLimiter(
        max_retries=3,
        remaining_time_fn=lambda: remaining_time,
        min_reserve_seconds=15.0,
        sleep_fn=mock_sleep_recorder,
    )

    resp_429 = MagicMock(spec=requests.Response)
    resp_429.status_code = 429
    resp_429.headers = {"Retry-After": "30"}
    mock_req = MagicMock(return_value=resp_429)

    with pytest.raises(ExecutionTimeoutError) as exc_info:
        limiter.execute(mock_req)

    assert "Execution deadline imminent" in str(exc_info.value)
    assert exc_info.value.remaining_seconds == 20.0
    assert exc_info.value.required_backoff == 30.0
    assert len(mock_sleep_recorder.sleeps) == 0  # Did not sleep into SIGKILL


def test_execute_pre_execution_deadline_depleted(mock_sleep_recorder):
    # If Lambda has only 10s left and reserve is 15s, reject immediately before initiating request
    limiter = RobustRateLimiter(
        remaining_time_fn=lambda: 10.0,
        min_reserve_seconds=15.0,
        sleep_fn=mock_sleep_recorder,
    )

    mock_req = MagicMock()
    with pytest.raises(ExecutionTimeoutError):
        limiter.execute(mock_req)

    assert mock_req.call_count == 0
