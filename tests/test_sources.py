"""Unit tests for secops_collector.sources plugins."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import requests

from secops_collector.core.models import CollectorConfig, TimeWindow
from secops_collector.core.rate_limiter import RobustRateLimiter
from secops_collector.sources.base import SourceAPIError, round_dt, safe_parse_json
from secops_collector.sources.crowdstrike import CrowdStrikeSource
from secops_collector.sources.datadog import DatadogSource
from secops_collector.sources.github import GitHubAuditSource
from secops_collector.sources.okta import OktaSource
from secops_collector.sources.sentinelone import SentinelOneSource


def test_round_dt():
    dt = datetime(2026, 11, 5, 12, 7, 25, tzinfo=timezone.utc)
    delta_5m = timedelta(minutes=5)
    rounded = round_dt(dt, delta_5m)
    assert rounded == datetime(2026, 11, 5, 12, 5, 0, tzinfo=timezone.utc)

    dt2 = datetime(2026, 11, 5, 12, 8, 45, tzinfo=timezone.utc)
    rounded2 = round_dt(dt2, delta_5m)
    assert rounded2 == datetime(2026, 11, 5, 12, 10, 0, tzinfo=timezone.utc)


def test_okta_source_pagination(mock_sleep_recorder):
    source = OktaSource()
    config = CollectorConfig(source_type="okta", batch_size=2)
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)
    source.initialize(config, {"okta_url": "https://example.okta.com", "okta_token": "token123"}, rate_limiter)

    # Page 1 response
    page1_resp = MagicMock(spec=requests.Response)
    page1_resp.status_code = 200
    page1_resp.links = {"next": {"url": "https://example.okta.com/api/v1/logs?after=page2"}}
    page1_resp.json.return_value = [
        {
            "eventId": "evt_1",
            "published": "2026-11-05T12:01:00.000Z",
            "eventType": "user.session.start",
            "actor": {"alternateId": "alice@example.com"},
        },
        {
            "eventId": "evt_2",
            "published": "2026-11-05T12:02:00.000Z",
            "eventType": "user.authentication.verify",
            "actor": {"alternateId": "bob@example.com"},
        },
    ]

    # Page 2 response
    page2_resp = MagicMock(spec=requests.Response)
    page2_resp.status_code = 200
    page2_resp.links = {}
    page2_resp.json.return_value = [
        {
            "eventId": "evt_3",
            "published": "2026-11-05T12:03:00.000Z",
            "eventType": "policy.rule.modify",
            "actor": {"alternateId": "admin@example.com"},
        }
    ]

    source.session.get = MagicMock(side_effect=[page1_resp, page2_resp])

    tw = TimeWindow(
        start_time=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 11, 5, 12, 5, 0, tzinfo=timezone.utc),
    )

    batches = list(source.collect(time_window=tw))
    assert len(batches) == 2
    assert batches[0].record_count == 2
    assert batches[1].record_count == 1
    assert batches[0].events[0].id == "evt_1"
    assert batches[0].events[0].attributes["actor_alternate_id"] == "alice@example.com"


def test_crowdstrike_source_oauth_and_collection(mock_sleep_recorder):
    source = CrowdStrikeSource()
    config = CollectorConfig(source_type="crowdstrike", batch_size=10)
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)
    source.initialize(
        config,
        {"client_id": "cs_client_id", "client_secret": "cs_client_sec", "base_url": "https://api.crowdstrike.com"},
        rate_limiter,
    )

    # OAuth response
    oauth_resp = MagicMock(spec=requests.Response)
    oauth_resp.status_code = 201
    oauth_resp.json.return_value = {"access_token": "falcon_bearer_tok", "expires_in": 1800}

    # Vuln response
    vuln_resp = MagicMock(spec=requests.Response)
    vuln_resp.status_code = 200
    vuln_resp.json.return_value = {
        "resources": [
            {
                "id": "vuln_1",
                "updated_timestamp": "2026-11-05T12:00:00Z",
                "cve": {"id": "CVE-2026-1234", "severity": "HIGH"},
                "host_info": {"hostname": "sec-workstation-01"},
            }
        ],
        "meta": {"pagination": {"after": None}},
    }

    source.session.post = MagicMock(return_value=oauth_resp)
    source.session.get = MagicMock(return_value=vuln_resp)

    tw = TimeWindow(
        start_time=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 11, 5, 12, 5, 0, tzinfo=timezone.utc),
    )

    batches = list(source.collect(time_window=tw))
    assert len(batches) == 1
    assert batches[0].record_count == 1
    event = batches[0].events[0]
    assert event.id == "vuln_1"
    assert event.attributes["cve_id"] == "CVE-2026-1234"
    assert event.attributes["hostname"] == "sec-workstation-01"


def test_datadog_source_collection(mock_sleep_recorder):
    source = DatadogSource()
    config = CollectorConfig(source_type="datadog", batch_size=5)
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)
    source.initialize(
        config,
        {"api_key": "dd_key", "app_key": "dd_app", "datadog_url": "https://api.datadoghq.com"},
        rate_limiter,
    )

    resp = MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.json.return_value = {
        "data": [
            {
                "id": "dd_event_1",
                "attributes": {
                    "timestamp": "2026-11-05T12:00:00Z",
                    "service": "auth-service",
                    "host": "prod-node-1",
                    "status": "error",
                    "message": "Failed login attempt",
                },
            }
        ],
        "meta": {"page": {"after": None}},
    }

    source.session.post = MagicMock(return_value=resp)

    tw = TimeWindow(
        start_time=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 11, 5, 12, 5, 0, tzinfo=timezone.utc),
    )

    batches = list(source.collect(time_window=tw))
    assert len(batches) == 1
    assert batches[0].record_count == 1
    event = batches[0].events[0]
    assert event.id == "dd_event_1"
    assert event.attributes["service"] == "auth-service"


def test_github_source_collection(mock_sleep_recorder):
    source = GitHubAuditSource()
    config = CollectorConfig(source_type="github", batch_size=10)
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)
    source.initialize(
        config,
        {"github_token": "ghp_tok", "org": "ka-seceng"},
        rate_limiter,
    )

    resp = MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.links = {}
    resp.json.return_value = [
        {
            "_document_id": "gh_doc_1",
            "@timestamp": 1793880000000,
            "action": "repo.create",
            "actor": "dev-user",
            "repo": "ka-seceng/new-repo",
        }
    ]

    source.session.get = MagicMock(return_value=resp)

    tw = TimeWindow(
        start_time=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 11, 5, 12, 5, 0, tzinfo=timezone.utc),
    )

    batches = list(source.collect(time_window=tw))
    assert len(batches) == 1
    assert batches[0].record_count == 1
    event = batches[0].events[0]
    assert event.id == "gh_doc_1"
    assert event.attributes["action"] == "repo.create"
    assert event.attributes["repo"] == "ka-seceng/new-repo"


def test_sentinelone_source_collection(mock_sleep_recorder):
    source = SentinelOneSource()
    config = CollectorConfig(source_type="sentinelone", batch_size=10)
    rate_limiter = RobustRateLimiter(sleep_fn=mock_sleep_recorder)
    source.initialize(
        config,
        {"s1_token": "s1_tok_xyz", "s1_url": "https://example.sentinelone.net"},
        rate_limiter,
    )

    resp = MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.json.return_value = {
        "data": [
            {
                "id": "s1_act_1",
                "createdAt": "2026-11-05T12:00:00.000Z",
                "activityType": "threat.mitigated",
                "userName": "analyst@example.com",
                "threatId": "threat_999",
            }
        ],
        "pagination": {"nextCursor": None},
    }

    source.session.get = MagicMock(return_value=resp)

    tw = TimeWindow(
        start_time=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 11, 5, 12, 5, 0, tzinfo=timezone.utc),
    )

    batches = list(source.collect(time_window=tw))
    assert len(batches) == 1
    assert batches[0].record_count == 1
    event = batches[0].events[0]
    assert event.id == "s1_act_1"
    assert event.attributes["threat_id"] == "threat_999"


def test_sources_raise_on_non_200_http_status(mock_sleep_recorder):
    # Test that Okta raises SourceAPIError on HTTP 400 Bad Request
    okta = OktaSource()
    okta.initialize(CollectorConfig(source_type="okta"), {"okta_token": "tok"}, RobustRateLimiter(max_retries=0))
    resp_400 = MagicMock(spec=requests.Response)
    resp_400.status_code = 400
    resp_400.text = "Bad Request"
    okta.session.get = MagicMock(return_value=resp_400)

    tw = TimeWindow(
        start_time=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 11, 5, 12, 5, 0, tzinfo=timezone.utc),
    )

    import pytest
    with pytest.raises(SourceAPIError) as exc_info:
        list(okta.collect(time_window=tw))
    assert "Okta API returned HTTP 400" in str(exc_info.value)


def test_safe_parse_json_memory_safety():
    resp_oversized = MagicMock(spec=requests.Response)
    resp_oversized.headers = {"Content-Length": "30000000"}  # 30 MB
    import pytest
    with pytest.raises(SourceAPIError) as exc_info:
        safe_parse_json(resp_oversized, max_bytes=1000000)
    assert "exceeds safety ceiling" in str(exc_info.value)
