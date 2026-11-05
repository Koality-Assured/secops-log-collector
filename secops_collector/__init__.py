"""secops-log-collector: Production-grade serverless event-driven security log collection engine."""

__version__ = "1.0.0"

from secops_collector.core.models import CollectorConfig, LogBatch, LogEvent, PipelineMetrics, TimeWindow
from secops_collector.core.pipeline import IngestionPipeline
from secops_collector.lambda_handler import lambda_handler

__all__ = [
    "CollectorConfig",
    "LogBatch",
    "LogEvent",
    "PipelineMetrics",
    "TimeWindow",
    "IngestionPipeline",
    "lambda_handler",
]
