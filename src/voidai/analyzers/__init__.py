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
from voidai.analyzers.host import (
    EstateBaseline,
    HostAnalyzer,
    HostConfig,
    LineageScore,
    ProcessScore,
    estate_baseline,
    host_summary,
    score_lineage,
    score_process,
)
from voidai.analyzers.intel import (
    IntelConfig,
    IntelScore,
    ThreatIntelAnalyzer,
    score_match,
)
from voidai.analyzers.ngrams import improbability, mean_surprise
from voidai.analyzers.tlsdga import (
    DgaScore,
    TlsDgaAnalyzer,
    TlsDgaConfig,
    TlsScore,
    score_domain,
    score_fingerprint,
)

#: Analyzers run by `voidai run` unless a subset is requested.
DEFAULT_ANALYZERS: tuple[type[BaseAnalyzer], ...] = (
    BeaconingAnalyzer,
    FanoutAnalyzer,
    EgressAnalyzer,
    DnsTunnelAnalyzer,
    AlertTriageAnalyzer,
    ThreatIntelAnalyzer,
    TlsDgaAnalyzer,
    HostAnalyzer,
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
    "DgaScore",
    "DnsTunnelAnalyzer",
    "DnsTunnelConfig",
    "DnsTunnelScore",
    "EgressAnalyzer",
    "EgressConfig",
    "EgressScore",
    "EstateBaseline",
    "FanoutAnalyzer",
    "FanoutConfig",
    "FanoutScore",
    "HostAnalyzer",
    "HostConfig",
    "IntelConfig",
    "IntelScore",
    "LineageScore",
    "ProcessScore",
    "ThreatIntelAnalyzer",
    "TlsDgaAnalyzer",
    "TlsDgaConfig",
    "TlsScore",
    "estate_baseline",
    "host_summary",
    "improbability",
    "mean_surprise",
    "score_alert_cluster",
    "score_domain",
    "score_fanout",
    "score_fingerprint",
    "score_lineage",
    "score_match",
    "score_pair",
    "score_process",
    "score_transfer",
    "score_zone",
]
