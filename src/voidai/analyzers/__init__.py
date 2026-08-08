"""Detection components. Deterministic, testable, and model-free by contract."""

from voidai.analyzers.base import AnalysisContext, Analyzer, BaseAnalyzer
from voidai.analyzers.beaconing import BeaconingAnalyzer, BeaconingConfig, BeaconScore, score_pair
from voidai.analyzers.dnstunnel import (
    DnsTunnelAnalyzer,
    DnsTunnelConfig,
    DnsTunnelScore,
    score_zone,
)
from voidai.analyzers.fanout import FanoutAnalyzer, FanoutConfig, FanoutScore, score_fanout

#: Analyzers run by `voidai run` unless a subset is requested.
DEFAULT_ANALYZERS: tuple[type[BaseAnalyzer], ...] = (BeaconingAnalyzer, FanoutAnalyzer, DnsTunnelAnalyzer)

__all__ = [
    "DEFAULT_ANALYZERS",
    "AnalysisContext",
    "Analyzer",
    "BaseAnalyzer",
    "BeaconScore",
    "BeaconingAnalyzer",
    "BeaconingConfig",
    "DnsTunnelAnalyzer",
    "DnsTunnelConfig",
    "DnsTunnelScore",
    "FanoutAnalyzer",
    "FanoutConfig",
    "FanoutScore",
    "score_fanout",
    "score_pair",
    "score_zone",
]
