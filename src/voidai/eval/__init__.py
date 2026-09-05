"""Reproducible evaluation: labelled corpora, scoring, and energy benchmarks."""

from voidai.eval.benchmark import (
    BenchmarkResult,
    DetectionScore,
    DgaBenchmarkResult,
    HostBenchmarkResult,
    TlsBenchmarkResult,
    run_benchmark,
    run_dga_benchmark,
    run_host_benchmark,
    run_tls_benchmark,
)
from voidai.eval.synth import (
    Corpus,
    CorpusGenerator,
    DgaCorpus,
    DgaCorpusGenerator,
    DgaFamily,
    HostCorpus,
    HostCorpusGenerator,
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
    "HostBenchmarkResult",
    "HostCorpus",
    "HostCorpusGenerator",
    "Implant",
    "RareClient",
    "TlsBenchmarkResult",
    "TlsCorpus",
    "TlsCorpusGenerator",
    "run_benchmark",
    "run_dga_benchmark",
    "run_host_benchmark",
    "run_tls_benchmark",
]
