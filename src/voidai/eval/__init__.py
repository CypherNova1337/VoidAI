"""Reproducible evaluation: labelled corpora, scoring, and energy benchmarks."""

from voidai.eval.benchmark import BenchmarkResult, DetectionScore, run_benchmark
from voidai.eval.synth import Corpus, CorpusGenerator, Implant

__all__ = [
    "BenchmarkResult",
    "Corpus",
    "CorpusGenerator",
    "DetectionScore",
    "Implant",
    "run_benchmark",
]
