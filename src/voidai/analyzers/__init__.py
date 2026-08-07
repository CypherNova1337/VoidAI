"""Detection components. Deterministic, testable, and model-free by contract."""

from voidai.analyzers.base import AnalysisContext, Analyzer, BaseAnalyzer
from voidai.analyzers.beaconing import BeaconingAnalyzer, BeaconingConfig, BeaconScore, score_pair

#: Analyzers run by `voidai run` unless a subset is requested.
DEFAULT_ANALYZERS: tuple[type[BaseAnalyzer], ...] = (BeaconingAnalyzer,)

__all__ = [
    "DEFAULT_ANALYZERS",
    "AnalysisContext",
    "Analyzer",
    "BaseAnalyzer",
    "BeaconScore",
    "BeaconingAnalyzer",
    "BeaconingConfig",
    "score_pair",
]
