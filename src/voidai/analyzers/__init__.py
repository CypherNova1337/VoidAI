"""Detection components. Deterministic, testable, and model-free by contract."""

from voidai.analyzers.alerts import (
    AlertScore,
    AlertTriageAnalyzer,
    AlertTriageConfig,
    score_alert_cluster,
)
from voidai.analyzers.base import AnalysisContext, Analyzer, BaseAnalyzer
from voidai.analyzers.beaconing import BeaconingAnalyzer, BeaconingConfig, BeaconScore, score_pair
from voidai.analyzers.dnstunnel import (
    DnsTunnelAnalyzer,
    DnsTunnelConfig,
    DnsTunnelScore,
    score_zone,
)
from voidai.analyzers.egress import (
    EgressAnalyzer,
    EgressConfig,
    EgressScore,
    score_transfer,
)
from voidai.analyzers.fanout import FanoutAnalyzer, FanoutConfig, FanoutScore, score_fanout
from voidai.analyzers.intel import (
    IntelConfig,
    IntelScore,
    ThreatIntelAnalyzer,
    score_match,
)

#: Analyzers run by `voidai run` unless a subset is requested.
DEFAULT_ANALYZERS: tuple[type[BaseAnalyzer], ...] = (
    BeaconingAnalyzer,
    FanoutAnalyzer,
    EgressAnalyzer,
    DnsTunnelAnalyzer,
    AlertTriageAnalyzer,
    ThreatIntelAnalyzer,
)

__all__ = [
    "DEFAULT_ANALYZERS",
    "AlertScore",
    "AlertTriageAnalyzer",
    "AlertTriageConfig",
    "AnalysisContext",
    "Analyzer",
    "BaseAnalyzer",
    "BeaconScore",
    "BeaconingAnalyzer",
    "BeaconingConfig",
    "DnsTunnelAnalyzer",
    "DnsTunnelConfig",
    "DnsTunnelScore",
    "EgressAnalyzer",
    "EgressConfig",
    "EgressScore",
    "FanoutAnalyzer",
    "FanoutConfig",
    "FanoutScore",
    "IntelConfig",
    "IntelScore",
    "ThreatIntelAnalyzer",
    "score_alert_cluster",
    "score_fanout",
    "score_match",
    "score_pair",
    "score_transfer",
    "score_zone",
]
