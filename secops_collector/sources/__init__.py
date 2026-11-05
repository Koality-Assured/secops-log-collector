"""Source plugin registry and factory."""

from __future__ import annotations

from typing import Dict, Type

from secops_collector.sources.base import BaseSource
from secops_collector.sources.crowdstrike import CrowdStrikeSource
from secops_collector.sources.datadog import DatadogSource
from secops_collector.sources.github import GitHubAuditSource
from secops_collector.sources.okta import OktaSource
from secops_collector.sources.sentinelone import SentinelOneSource

SOURCE_REGISTRY: Dict[str, Type[BaseSource]] = {
    "okta": OktaSource,
    "crowdstrike": CrowdStrikeSource,
    "datadog": DatadogSource,
    "github": GitHubAuditSource,
    "sentinelone": SentinelOneSource,
}


def get_source(source_type: str) -> BaseSource:
    """Instantiate a source collector plugin by name."""
    normalized = source_type.strip().lower()
    if normalized not in SOURCE_REGISTRY:
        supported = ", ".join(sorted(SOURCE_REGISTRY.keys()))
        raise ValueError(f"Unknown source type '{source_type}'. Supported sources: {supported}")
    return SOURCE_REGISTRY[normalized]()
