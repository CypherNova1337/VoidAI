"""Reproducible evaluation: labelled corpora, scoring, and energy benchmarks."""

from voidai.eval.benchmark import (
    BenchmarkResult,
    DetectionScore,
    DgaBenchmarkResult,
    TlsBenchmarkResult,
    run_benchmark,
    run_dga_benchmark,
    run_tls_benchmark,
)
from voidai.eval.synth import (
    Corpus,
    CorpusGenerator,
    DgaCorpus,
    DgaCorpusGenerator,
    DgaFamily,
    Implant,
    RareClient,
    TlsCorpus,
    TlsCorpusGenerator,
)

__all__ = [
    "BenchmarkResult",
    "Corpus",
    "CorpusGenerator",
    "DetectionScore",
    "DgaBenchmarkResult",
    "DgaCorpus",
    "DgaCorpusGenerator",
    "DgaFamily",
    "Implant",
    "RareClient",
    "TlsBenchmarkResult",
    "TlsCorpus",
    "TlsCorpusGenerator",
    "run_benchmark",
    "run_dga_benchmark",
    "run_tls_benchmark",
]
