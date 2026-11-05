"""Configuration parameters for Pulumi infrastructure deployment."""

from typing import Any, Dict

import pulumi

config = pulumi.Config()

# Deployment environment (e.g. prod, staging, dev)
environment = config.get("environment") or "prod"
project_prefix = config.get("project_prefix") or "secops"
aws_region = config.get("region") or "us-west-2"

# Common organizational resource tags
common_tags: Dict[str, str] = {
    "Project": "SecOps-Log-Collector",
    "Environment": environment,
    "ManagedBy": "Pulumi",
    "Owner": "Koality-Assured-SecEng",
}

# Supported collector products and schedule rate intervals
collector_products: Dict[str, Dict[str, Any]] = {
    "okta": {
        "rate_minutes": 5,
        "timeout_seconds": 300,
        "memory_size": 256,
        "sinks": ["logscale", "s3"],
    },
    "crowdstrike": {
        "rate_minutes": 5,
        "timeout_seconds": 600,
        "memory_size": 512,
        "sinks": ["logscale", "s3"],
    },
    "datadog": {
        "rate_minutes": 5,
        "timeout_seconds": 300,
        "memory_size": 256,
        "sinks": ["logscale", "s3"],
    },
    "github": {
        "rate_minutes": 15,
        "timeout_seconds": 300,
        "memory_size": 256,
        "sinks": ["logscale", "s3"],
    },
    "sentinelone": {
        "rate_minutes": 5,
        "timeout_seconds": 300,
        "memory_size": 256,
        "sinks": ["logscale", "s3"],
    },
}
