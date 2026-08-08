"""Tests for DNS tunnelling detection.

The benign cases matter more than the malicious ones here. Any detector finds
a tunnel; the difficulty is not firing on content delivery networks and
reputation lookups, which are tunnel-shaped by every measure except the
entropy of what they encode.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from voidai.analyzers import AnalysisContext, DnsTunnelAnalyzer, DnsTunnelConfig
from voidai.analyzers.dnstunnel import registered_domain, score_zone, subdomain_of
from voidai.eval.synth import DnsCorpusGenerator
from voidai.ingest.schema import DNS_SCHEMA, conform
from voidai.lexicon import EntityType, Predicate

BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
HEX = "0123456789abcdef"


def encoded(rng: np.random.Generator, alphabet: str, length: int, count: int) -> list[str]:
    return ["".join(rng.choice(list(alphabet), size=length)) for _ in range(count)]


class TestRegisteredDomain:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("a1b2c3.tunnel.example.com", "example.com"),
            ("example.com", "example.com"),
            ("com", "com"),
            ("deep.nested.sub.example.org", "example.org"),
            ("WWW.Example.COM", "example.com"),
            ("trailing.example.com.", "example.com"),
        ],
    )
    def test_reduces_to_the_zone(self, name: str, expected: str) -> None:
        assert registered_domain(name) == expected

    def test_handles_multipart_suffixes(self) -> None:
        assert registered_domain("data.tunnel.example.co.uk") == "example.co.uk"
        assert registered_domain("shop.example.com.au") == "example.com.au"

    def test_empty(self) -> None:
        assert registered_domain("") == ""


class TestSubdomainOf:
    def test_strips_the_zone(self) -> None:
        assert subdomain_of("abc.def.example.com", "example.com") == "abcdef"

    def test_joins_labels_so_chunking_does_not_lower_entropy(self) -> None:
        """A tunnel that splits payload across labels must not score lower.

        Label framing is a property of the encoder, not of the channel.
        """
        single = subdomain_of("abcdefghijkl.example.com", "example.com")
        chunked = subdomain_of("abcd.efgh.ijkl.example.com", "example.com")
        assert single == chunked

    def test_query_equal_to_the_zone(self) -> None:
        assert subdomain_of("example.com", "example.com") == ""


class TestScoreZone:
    def test_base32_tunnel_scores_high(self) -> None:
        rng = np.random.default_rng(0)
        subs = encoded(rng, BASE32, 58, 600)
        score = score_zone(subs, ["TXT"] * 600, DnsTunnelConfig())
        assert score is not None
        assert score.score >= DnsTunnelConfig().score_threshold
        assert score.mean_entropy > 4.3

    def test_a_record_tunnel_still_scores_high(self) -> None:
        """A tunnel confined to A records has no qtype tell, and is still one."""
        rng = np.random.default_rng(1)
        subs = encoded(rng, BASE32, 40, 450)
        score = score_zone(subs, ["A"] * 450, DnsTunnelConfig())
        assert score is not None
        assert score.score >= DnsTunnelConfig().score_threshold
        assert "qtype_skew" not in score.components  # omitted, not scored zero

    def test_cdn_scores_low_despite_high_cardinality(self) -> None:
        rng = np.random.default_rng(2)
        subs = [f"e{rng.integers(1000, 99999)}-{rng.integers(1, 40)}" for _ in range(300)]
        score = score_zone(subs, ["A"] * 300, DnsTunnelConfig())
        assert score is not None
        assert score.score < DnsTunnelConfig().score_threshold

    def test_hex_reputation_lookups_stay_below_threshold(self) -> None:
        """The nearest false positive, and the margin is thin.

        Reputation services encode hashes into subdomains: high cardinality,
        long names, structured payload. Only entropy separates them, and hex
        tops out at 4.0 bits/char against base32's 5.0. On the synthetic
        corpus this scores 0.57 against a 0.62 threshold — correct, but by
        0.05.

        The threshold is deliberately not widened. There is no real labelled
        DNS-tunnelling corpus here, so tuning it would be calibrating against
        a generator written by the same hand as the detector. The margin is
        pinned instead, so any regression is visible.
        """
        rng = np.random.default_rng(3)
        subs = encoded(rng, HEX, 32, 250)
        score = score_zone(subs, ["A"] * 250, DnsTunnelConfig())
        assert score is not None
        assert score.score < DnsTunnelConfig().score_threshold
        assert score.score > 0.45, "margin has widened unexpectedly; recheck calibration"

    def test_too_few_queries_returns_none(self) -> None:
        rng = np.random.default_rng(4)
        assert score_zone(encoded(rng, BASE32, 40, 10), ["A"] * 10, DnsTunnelConfig()) is None

    def test_low_cardinality_returns_none(self) -> None:
        """One name queried a thousand times is a busy client, not a tunnel."""
        subs = ["staticname"] * 500
        assert score_zone(subs, ["A"] * 500, DnsTunnelConfig()) is None

    def test_short_subdomains_are_not_measured_for_entropy(self) -> None:
        """A five-character label cannot exceed 2.3 bits however random it is."""
        rng = np.random.default_rng(5)
        subs = encoded(rng, BASE32, 4, 300)
        assert score_zone(subs, ["A"] * 300, DnsTunnelConfig()) is None

    def test_basis_names_every_component(self) -> None:
        rng = np.random.default_rng(6)
        score = score_zone(encoded(rng, BASE32, 50, 300), ["TXT"] * 300, DnsTunnelConfig())
        assert score is not None
        for component in score.components:
            assert component in score.basis()


@pytest.fixture(scope="module")
def corpus():  # type: ignore[no-untyped-def]
    return DnsCorpusGenerator(seed=1337).generate()


class TestDnsTunnelAnalyzer:
    def test_finds_every_planted_tunnel(self, corpus) -> None:  # type: ignore[no-untyped-def]
        findings = DnsTunnelAnalyzer().analyze(AnalysisContext(dns=corpus.queries))
        detected = {(f.subject.value, f.object.value) for f in findings}
        for tunnel in corpus.tunnels:
            assert tunnel.key in detected, f"missed {tunnel.label}"

    def test_reports_no_false_positives(self, corpus) -> None:  # type: ignore[no-untyped-def]
        findings = DnsTunnelAnalyzer().analyze(AnalysisContext(dns=corpus.queries))
        truth = corpus.tunnel_keys
        assert [
            (f.subject.value, f.object.value)
            for f in findings
            if (f.subject.value, f.object.value) not in truth
        ] == []

    def test_uses_the_tunnels_dns_over_predicate(self, corpus) -> None:  # type: ignore[no-untyped-def]
        findings = DnsTunnelAnalyzer().analyze(AnalysisContext(dns=corpus.queries))
        assert all(f.predicate is Predicate.TUNNELS_DNS_OVER for f in findings)
        assert all(f.object is not None and f.object.type is EntityType.DOMAIN for f in findings)

    def test_carries_resolvable_evidence(self, corpus) -> None:  # type: ignore[no-untyped-def]
        for finding in DnsTunnelAnalyzer().analyze(AnalysisContext(dns=corpus.queries)):
            for evidence in finding.evidence:
                assert evidence.artifacts
                for artifact in evidence.artifacts:
                    assert artifact.source and artifact.locator

    def test_is_deterministic(self, corpus) -> None:  # type: ignore[no-untyped-def]
        ctx = AnalysisContext(dns=corpus.queries)
        assert [f.id for f in DnsTunnelAnalyzer().analyze(ctx)] == [
            f.id for f in DnsTunnelAnalyzer().analyze(ctx)
        ]

    def test_lazy_and_eager_agree(self, corpus) -> None:  # type: ignore[no-untyped-def]
        eager = DnsTunnelAnalyzer().analyze(AnalysisContext(dns=corpus.queries))
        lazy = DnsTunnelAnalyzer().analyze(AnalysisContext(dns=corpus.queries.lazy()))
        assert [f.id for f in eager] == [f.id for f in lazy]

    def test_empty_input(self) -> None:
        empty = conform(pl.DataFrame(), DNS_SCHEMA)
        assert DnsTunnelAnalyzer().analyze(AnalysisContext(dns=empty)) == []

    def test_no_dns_source_at_all(self) -> None:
        """A capture with only connection logs must not crash this analyzer."""
        assert DnsTunnelAnalyzer().analyze(AnalysisContext()) == []
