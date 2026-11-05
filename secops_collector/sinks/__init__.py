"""Sink plugin registry and factory."""

from __future__ import annotations

from typing import Dict, Type

from secops_collector.sinks.base import BaseSink
from secops_collector.sinks.logscale import LogScaleSink
from secops_collector.sinks.opensearch import OpenSearchSink
from secops_collector.sinks.s3 import S3DataLakeSink

SINK_REGISTRY: Dict[str, Type[BaseSink]] = {
    "logscale": LogScaleSink,
    "s3": S3DataLakeSink,
    "opensearch": OpenSearchSink,
}


def get_sink(sink_type: str) -> BaseSink:
    """Instantiate an output sink plugin by name."""
    normalized = sink_type.strip().lower()
    if normalized not in SINK_REGISTRY:
        supported = ", ".join(sorted(SINK_REGISTRY.keys()))
        raise ValueError(f"Unknown sink type '{sink_type}'. Supported sinks: {supported}")
    return SINK_REGISTRY[normalized]()
