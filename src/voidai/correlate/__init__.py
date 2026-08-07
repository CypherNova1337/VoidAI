"""Correlation: findings into incidents, incidents into an ordered queue."""

from voidai.correlate.incidents import (
    CorrelationConfig,
    IncidentQueue,
    RankedIncident,
    build_queue,
    correlate,
)

__all__ = [
    "CorrelationConfig",
    "IncidentQueue",
    "RankedIncident",
    "build_queue",
    "correlate",
]
