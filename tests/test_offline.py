"""The offline guarantee.

The README states that VoidAI runs correctly with the network interface down
and that the test suite asserts it. This is that assertion.

Sockets are severed at the module level for the duration of each test, so any
attempt to open a connection — by VoidAI, or by anything it imports and calls
— raises instead of silently succeeding on a developer machine that happens to
have connectivity.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from voidai.analyzers import AnalysisContext, BeaconingAnalyzer
from voidai.eval.benchmark import run_benchmark
from voidai.eval.synth import CorpusGenerator
from voidai.ingest.zeek import read_conn_log


class NetworkAccessError(AssertionError):
    """Raised when code under test reaches for the network."""


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise NetworkAccessError(
            "VoidAI attempted a network connection. Nothing in the detection "
            "path may leave the machine."
        )

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)


@pytest.mark.usefixtures("no_network")
class TestPipelineRunsOffline:
    def test_corpus_generation_is_offline(self) -> None:
        corpus = CorpusGenerator(seed=1337).generate(hours=6.0)
        assert corpus.connections.height > 0

    def test_parsing_is_offline(self, tmp_path: Path) -> None:
        corpus = CorpusGenerator(seed=1337).generate(hours=6.0)
        log = corpus.write_zeek_conn_log(tmp_path / "conn.log")
        assert read_conn_log(log).height > 0

    def test_detection_is_offline(self) -> None:
        corpus = CorpusGenerator(seed=1337).generate(hours=24.0)
        findings = BeaconingAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        assert findings, "detection produced nothing — the test would be vacuous"

    def test_full_benchmark_is_offline(self) -> None:
        """The end-to-end path: generate, write, parse, detect, score, meter."""
        result = run_benchmark(seed=1337, hours=24.0)
        assert result.detection.recall == 1.0
        assert result.detection.precision == 1.0


@pytest.mark.usefixtures("no_network")
def test_the_guard_itself_works() -> None:
    """Confirms the fixture would actually catch a violation."""
    with pytest.raises(NetworkAccessError):
        socket.socket()
