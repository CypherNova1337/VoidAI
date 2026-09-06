"""Tests for TLS fingerprint rarity and domain-generation detection.

The cases that matter here are the ones where a measurement is *absent*. Any
detector finds a random string; the difficulty is behaving correctly when the
sensor did not record a response code, when `ja3` is missing because a Zeek
package was never loaded, and when an estate is too small for rarity to mean
anything. Each of those has a wrong answer that looks like a working detector.
"""

from __future__ import annotations

import polars as pl
import pytest

from voidai.analyzers import AnalysisContext, TlsDgaAnalyzer, TlsDgaConfig
from voidai.analyzers.ngrams import WORDS, improbability, mean_surprise
from voidai.analyzers.tlsdga import (
    longest_consonant_run,
    score_domain,
    score_fingerprint,
    split_registered,
)
from voidai.eval.synth import DgaCorpusGenerator, TlsCorpusGenerator
from voidai.ingest.passivedns import read_passivedns
from voidai.ingest.schema import DNS_SCHEMA, SSL_SCHEMA, conform
from voidai.lexicon import EntityType, Predicate

REAL_PASSIVEDNS = "tests/data/real.passivedns"


def dns_frame(rows: list[dict[str, object]]) -> pl.DataFrame:
    return conform(pl.DataFrame(rows), DNS_SCHEMA)


def query(src: str, name: str, rcode: str | None = "NOERROR", ts: float = 0.0) -> dict[str, object]:
    return {
        "ts": ts,
        "uid": "C1",
        "src_ip": src,
        "dst_ip": "10.0.0.53",
        "query": name,
        "qtype": "A",
        "rcode": rcode,
        "answers": "",
        "source_file": "<test>",
        "source_line": 1,
    }


def family(
    src: str,
    labels: list[str],
    suffix: str,
    rcode: str | None = "NOERROR",
) -> list[dict[str, object]]:
    """A family large enough to clear the gates, one query per label."""
    return [
        query(src, f"{label}.{suffix}", rcode, ts=float(index))
        for index, label in enumerate(labels)
    ]


def generated(count: int, length: int = 12, seed: int = 0) -> list[str]:
    import numpy as np

    rng = np.random.default_rng(seed)
    alphabet = list("abcdefghijklmnopqrstuvwxyz")
    return ["".join(rng.choice(alphabet, size=length)) for _ in range(count)]


class TestSplitRegistered:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("www.k7jf2plqx.biz", ("k7jf2plqx", "biz")),
            ("k7jf2plqx.biz", ("k7jf2plqx", "biz")),
            ("deep.sub.example.org", ("example", "org")),
            ("Example.COM.", ("example", "com")),
            ("shop.example.co.uk", ("example", "co.uk")),
        ],
    )
    def test_splits_label_from_suffix(self, name: str, expected: tuple[str, str]) -> None:
        assert split_registered(name) == expected

    @pytest.mark.parametrize("name", ["", "com", "localhost", "."])
    def test_unregistrable_names_have_no_label(self, name: str) -> None:
        """A bare suffix has no second-level label and cannot have been minted."""
        assert split_registered(name) is None


class TestConsonantRun:
    def test_counts_the_longest_run(self) -> None:
        assert longest_consonant_run("crwdcntrl") == 9  # every character
        assert longest_consonant_run("northwind") == 4  # "rthw"

    def test_digits_break_a_run(self) -> None:
        """`wgg4ggefwg` is three, not eight: the digit interrupts it."""
        assert longest_consonant_run("wgg4ggefwg") == 3


class TestCharacterModel:
    def test_the_word_list_carries_no_brand_names(self) -> None:
        """Fitting the model to the corpus it is scored on would be circular.

        `tests/data/real.passivedns` is the specificity measurement, so its
        labels must not be in the model's vocabulary.
        """
        for brand in ("google", "akamai", "mozilla", "microsoft", "facebook", "crwdcntrl"):
            assert brand not in WORDS

    def test_english_labels_score_low_and_random_ones_high(self) -> None:
        english = [improbability(w) for w in ("cloudflare", "northwind", "harborview")]
        machine = [improbability(w) for w in generated(20, length=12)]
        assert max(english) < 0.35
        assert min(machine) > 0.40

    def test_hex_is_the_shape_entropy_gets_backwards(self) -> None:
        """The case that motivated this module replacing `shannon_entropy`.

        Per-character entropy rates a 16-character hex string *below* a real
        English label, because a 16-character alphabet is small. The character
        model rates it at the top, which is the correct direction.
        """
        from voidai.analyzers.statistics import shannon_entropy

        hexed, english = "f25265721e7b4bbc", "googleapis"
        assert shannon_entropy(hexed) / 4.0 < shannon_entropy(english) / 3.32
        assert improbability(hexed) > improbability(english)

    def test_a_single_character_is_unmeasurable_rather_than_natural(self) -> None:
        """No pairs means no measurement, and None is not zero."""
        assert mean_surprise("a") is None
        assert improbability("a") is None

    def test_dictionary_concatenation_is_a_known_miss(self) -> None:
        """Documented in `ngrams.py`, asserted here so it stays documented."""
        assert improbability("stonegatemaplegrove") < 0.35


class TestScoreDomain:
    def test_a_generated_label_in_a_failing_family_scores_high(self) -> None:
        score = score_domain("xkjfhwuebfq", "biz", 0.95, TlsDgaConfig(), family_labels=200)
        assert score is not None
        assert score.score >= TlsDgaConfig().dga_threshold

    @pytest.mark.parametrize("label", ["ml314", "gvt2", "fbcdn", "b-cdn"])
    def test_a_short_label_is_not_scored_at_all(self, label: str) -> None:
        """Below six characters the model stops discriminating.

        Every label here is real, taken from the fixture, and every one scores
        near the top of the character model — four bigrams of an abbreviation
        are genuinely improbable English. No threshold separates them from a
        generated name, so the gate is a refusal to measure rather than a low
        score. Without it these four are the analyzer's only false positives
        on real traffic.
        """
        assert improbability(label) > 0.6
        assert score_domain(label, "net", 0.95, TlsDgaConfig(), family_labels=200) is None

    def test_missing_rcode_omits_the_component_rather_than_defaulting_it(self) -> None:
        """Rule 6, first level. `None` is not zero and is not a midpoint."""
        config = TlsDgaConfig()
        without = score_domain("xkjfhwuebfq", "biz", None, config, family_labels=200)
        assert without is not None
        assert "nxdomain_rate" not in without.components
        assert without.nxdomain_rate is None

        as_zero = score_domain("xkjfhwuebfq", "biz", 0.0, config, family_labels=200)
        assert as_zero is not None
        assert as_zero.components["nxdomain_rate"] == 0.0
        # Substituting zero would be a claim that the family resolves fine,
        # and it sinks the score. Omitting redistributes the weight instead.
        assert without.score > as_zero.score

    def test_the_basis_names_what_was_not_measured(self) -> None:
        score = score_domain("xkjfhwuebfq", "biz", None, TlsDgaConfig(), family_labels=200)
        assert score is not None
        assert "omitted (unmeasured): nxdomain_rate" in score.basis()

    def test_structure_is_a_soft_or_not_a_mean(self) -> None:
        """Digits and consonant runs are alternative tells, not joint ones.

        A generator that emits only digits shows no consonant run, and one
        that emits only letters shows no digits. Averaging would halve both
        for failing to be the other.
        """
        config = TlsDgaConfig()
        # A six-consonant run and no digits; twelve characters half digits and
        # no run. Each shows exactly one tell.
        letters = score_domain("xkjfhwuebfq", "biz", None, config, family_labels=200)
        digits = score_domain("a1b2c3d4e5f6", "biz", None, config, family_labels=200)
        assert letters is not None and digits is not None

        # Under a soft OR each keeps the whole of the tell it does show. Under
        # a mean each would keep half, because the other sub-signal is zero.
        run = (longest_consonant_run("xkjfhwuebfq") - config.consonant_run_floor) / (
            config.consonant_run_ceiling - config.consonant_run_floor
        )
        assert letters.components["structure"] == pytest.approx(run)
        assert digits.components["structure"] == pytest.approx(1.0)
        assert letters.components["structure"] > run / 2


class TestScoreFingerprint:
    def test_a_unique_fingerprint_over_a_real_estate_scores(self) -> None:
        score = score_fingerprint("abc", 1, 60, TlsDgaConfig(), sessions=10)
        assert score is not None
        assert score.score >= TlsDgaConfig().tls_threshold

    def test_rarity_needs_an_estate(self) -> None:
        """On a three-host capture everything is rare, and saying so is noise."""
        assert score_fingerprint("abc", 1, 3, TlsDgaConfig(), sessions=10) is None

    def test_a_single_session_is_not_evidence_the_host_runs_the_client(self) -> None:
        assert score_fingerprint("abc", 1, 60, TlsDgaConfig(), sessions=1) is None

    def test_a_widely_shared_fingerprint_is_not_rare(self) -> None:
        assert score_fingerprint("abc", 30, 60, TlsDgaConfig(), sessions=10) is None

    def test_two_hosts_need_a_larger_estate_than_one(self) -> None:
        """The rule the threshold encodes: two of forty is unremarkable, two
        of five hundred is not."""
        config = TlsDgaConfig()
        small = score_fingerprint("abc", 2, 45, config, sessions=12)
        large = score_fingerprint("abc", 2, 500, config, sessions=12)
        assert small is not None and large is not None
        assert small.score < config.tls_threshold <= large.score


class TestDgaAnalyzer:
    def test_finds_the_planted_families(self) -> None:
        corpus = DgaCorpusGenerator(seed=1337).generate()
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(dns=corpus.queries))
        found = {
            corpus.family_of(f.subject.value, f.object.value).label
            for f in findings
            if corpus.family_of(f.subject.value, f.object.value)
        }
        assert {f.label for f in corpus.detectable_families} <= found

    def test_reports_no_decoy(self) -> None:
        """The three decoys each defeat one component on its own."""
        corpus = DgaCorpusGenerator(seed=1337).generate()
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(dns=corpus.queries))
        for finding in findings:
            pair = (finding.subject.value, finding.object.value)
            assert pair not in corpus.decoys, f"fired on decoy: {corpus.decoys.get(pair)}"

    def test_a_high_nxdomain_rate_alone_does_not_fire(self) -> None:
        """A host with a broken search suffix fails to resolve ordinary names."""
        labels = [
            "northwind", "brightpath", "quicksilver", "cedarline", "harborview",
            "silverleaf", "ironbridge", "bluewater", "stonegate", "redwoodhill",
            "lightfield", "thornbury", "greenmeadow", "whitestone",
        ]
        rows = family("10.0.0.5", labels * 3, "com", rcode="NXDOMAIN")
        for index, row in enumerate(rows):
            row["ts"] = float(index)
        assert TlsDgaAnalyzer().analyze(AnalysisContext(dns=dns_frame(rows))) == []

    def test_generated_names_alone_do_not_reach_the_threshold_without_rcode(self) -> None:
        """Structure without resolution behaviour is a weaker claim, and the
        score says so rather than the predicate hiding it."""
        rows = family("10.0.0.6", generated(30, seed=3), "biz", rcode=None)
        config = TlsDgaConfig()
        findings = TlsDgaAnalyzer(config).analyze(AnalysisContext(dns=dns_frame(rows)))
        with_codes = TlsDgaAnalyzer(config).analyze(
            AnalysisContext(dns=dns_frame(family("10.0.0.6", generated(30, seed=3), "biz", "NXDOMAIN")))
        )
        assert max(f.confidence for f in with_codes) > max(
            (f.confidence for f in findings), default=0.0
        )

    def test_reports_the_domain_that_resolved(self) -> None:
        """A DGA family is hundreds of failures and one success, and the
        success is the C2. Reporting only the highest-scoring names would omit
        it, because the registered name is no stranger than the rest.
        """
        corpus = DgaCorpusGenerator(seed=1337).generate()
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(dns=corpus.queries))
        resolved = {
            f.object.value
            for f in findings
            for e in f.evidence
            if e.kind == "resolution_family" and e.payload["resolved"]
        }
        for planted in corpus.detectable_families:
            assert resolved & planted.domains, f"{planted.label}: live C2 domain not reported"

    def test_caps_findings_per_family(self) -> None:
        corpus = DgaCorpusGenerator(seed=1337).generate()
        config = TlsDgaConfig()
        findings = TlsDgaAnalyzer(config).analyze(AnalysisContext(dns=corpus.queries))
        per_host: dict[str, int] = {}
        for finding in findings:
            per_host[finding.subject.value] = per_host.get(finding.subject.value, 0) + 1
        assert max(per_host.values()) <= config.max_per_family

    def test_a_small_family_is_not_scored(self) -> None:
        """Two failed lookups are not a generation family."""
        rows = family("10.0.0.7", generated(4, seed=5), "biz", rcode="NXDOMAIN")
        assert TlsDgaAnalyzer().analyze(AnalysisContext(dns=dns_frame(rows))) == []

    def test_the_evidence_payload_carries_a_null_rate_not_a_zero(self) -> None:
        rows = family("10.0.0.8", generated(30, seed=7), "biz", rcode=None)
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(dns=dns_frame(rows)))
        payloads = [e.payload for f in findings for e in f.evidence if e.kind == "resolution_family"]
        assert payloads
        for payload in payloads:
            assert payload["nxdomain_rate"] is None

    def test_partial_rcode_coverage_is_treated_as_unmeasured(self) -> None:
        """A sensor that filled in a tenth of the family described that tenth.

        Not the presence of the column: the column exists here and carries
        real values, just not enough of them.
        """
        labels = generated(30, seed=11)
        rows = family("10.0.0.9", labels, "biz", rcode="NXDOMAIN")
        for index, row in enumerate(rows):
            if index % 10:
                row["rcode"] = None
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(dns=dns_frame(rows)))
        payloads = [e.payload for f in findings for e in f.evidence if e.kind == "resolution_family"]
        assert payloads
        for payload in payloads:
            assert payload["nxdomain_rate"] is None

    def test_findings_are_grammatical_and_attributed(self) -> None:
        corpus = DgaCorpusGenerator(seed=1337).generate()
        for finding in TlsDgaAnalyzer().analyze(AnalysisContext(dns=corpus.queries)):
            assert finding.predicate is Predicate.RESOLVES_ALGORITHMIC_DOMAIN
            assert finding.object is not None
            assert finding.object.type is EntityType.DOMAIN
            assert finding.analyzer == "tlsdga@0.1.0"
            assert finding.evidence


class TestRealTraffic:
    """Specificity, on the only real DNS this project has.

    400 records from one host of a Stratosphere malware capture: Akamai CNAME
    chains, Microsoft telemetry, update services and certificate status
    lookups. It carries no `rcode`, so this measures the analyzer **without**
    its heaviest component — which makes a clean result conservative and a
    dirty one worse than it looks.
    """

    def test_emits_nothing_on_real_benign_dns(self) -> None:
        dns = read_passivedns(REAL_PASSIVEDNS)
        assert dns.height > 300, "fixture did not load; the assertion would be vacuous"
        assert TlsDgaAnalyzer().analyze(AnalysisContext(dns=dns)) == []

    def test_the_real_margin_is_thin_and_pinned(self) -> None:
        """The closest real label is `crwdcntrl.net` at 0.546 against a 0.65
        threshold. Pinned so that a change which erodes it is visible in a
        diff rather than discovered on a customer's network.
        """
        dns = read_passivedns(REAL_PASSIVEDNS)
        rows = dns.select(["src_ip", "query"]).drop_nulls().rows()
        best = 0.0
        for _src, name in rows:
            split = split_registered(name)
            if split is None:
                continue
            score = score_domain(split[0], split[1], None, TlsDgaConfig(), family_labels=44)
            if score is not None:
                best = max(best, score.score)
        assert 0.50 < best < 0.60, f"real-traffic ceiling moved to {best:.3f}"


class TestTlsAnalyzer:
    def test_finds_the_planted_clients(self) -> None:
        corpus = TlsCorpusGenerator(seed=1337).generate()
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(ssl=corpus.sessions))
        found = {(f.subject.value, f.object.value) for f in findings}
        assert corpus.client_keys <= found

    def test_reports_no_decoy(self) -> None:
        corpus = TlsCorpusGenerator(seed=1337).generate()
        for finding in TlsDgaAnalyzer().analyze(AnalysisContext(ssl=corpus.sessions)):
            pair = (finding.subject.value, finding.object.value)
            assert pair not in corpus.decoys, f"fired on decoy: {corpus.decoys.get(pair)}"

    def test_an_ssl_log_without_ja3_produces_nothing(self) -> None:
        """The stock-Zeek deployment. Silence, not a crash and not a finding.

        This is the known trap: `ja3` comes from a Zeek
        package, so the column is frequently absent.
        """
        corpus = TlsCorpusGenerator(seed=1337).generate()
        stripped = corpus.sessions.drop("ja3")
        assert TlsDgaAnalyzer().analyze(AnalysisContext(ssl=stripped)) == []

    def test_a_wholly_unpopulated_ja3_column_produces_nothing(self) -> None:
        """The half-configured sensor: the column exists and is never filled."""
        corpus = TlsCorpusGenerator(seed=1337).generate()
        blanked = corpus.sessions.with_columns(pl.lit(None, dtype=pl.Utf8).alias("ja3"))
        assert TlsDgaAnalyzer().analyze(AnalysisContext(ssl=blanked)) == []

    def test_sessions_without_a_fingerprint_do_not_form_one(self) -> None:
        """The sharp version of the case above, and the one that bites.

        A *partially* populated column is the realistic failure: a package
        loaded late, a log rotated mid-deployment, handshakes the sensor could
        not parse. If null rows are grouped rather than dropped, the hosts
        missing a fingerprint become a group of their own — and because they
        are few, that group is *rare*, so the analyzer reports the sensor's
        own gap as a rare TLS client on exactly the hosts it knows least
        about.

        One host, not several, because that is where the harm is maximal: a
        null group spanning one host of forty-five is as rare as a bespoke
        implant and scores identically to one.

        Blanking the *whole* column does not catch this — one fingerprint on
        every host is common, so no finding appears however the nulls are
        handled.
        """
        corpus = TlsCorpusGenerator(seed=1337).generate()
        blind = "10.0.3.10"
        gapped = corpus.sessions.with_columns(
            pl.when(pl.col("src_ip") == blind)
            .then(pl.lit(None, dtype=pl.Utf8))
            .otherwise(pl.col("ja3"))
            .alias("ja3")
        )
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(ssl=gapped))
        assert findings, "estate produced nothing at all — the assertion would be vacuous"
        for finding in findings:
            assert finding.subject.value != blind

    def test_findings_are_grammatical(self) -> None:
        corpus = TlsCorpusGenerator(seed=1337).generate()
        for finding in TlsDgaAnalyzer().analyze(AnalysisContext(ssl=corpus.sessions)):
            assert finding.predicate is Predicate.PRESENTS_RARE_TLS_FINGERPRINT
            assert finding.object is not None
            assert finding.object.type is EntityType.TLS_FINGERPRINT


class TestBothHalves:
    def test_each_half_is_silent_on_its_own_account(self) -> None:
        """DNS with no TLS yields the DGA findings, not nothing."""
        dga = DgaCorpusGenerator(seed=1337).generate()
        tls = TlsCorpusGenerator(seed=1337).generate()
        dns_only = TlsDgaAnalyzer().analyze(AnalysisContext(dns=dga.queries))
        tls_only = TlsDgaAnalyzer().analyze(AnalysisContext(ssl=tls.sessions))
        both = TlsDgaAnalyzer().analyze(AnalysisContext(dns=dga.queries, ssl=tls.sessions))
        assert dns_only and tls_only
        assert len(both) == len(dns_only) + len(tls_only)

    def test_a_netflow_shaped_capture_is_silent(self) -> None:
        """CTU-13 is NetFlow: connections, no query names, no TLS sessions.

        Section 2's real-capture figures were measured before this analyzer
        existed, and they stand only if adding it changes nothing there. It
        has no connection-derived signal at all, so it must contribute exactly
        zero findings to a capture of that shape — asserted rather than
        assumed, because "it probably does nothing" is how a benchmark
        silently stops being comparable.
        """
        from voidai.eval.synth import CorpusGenerator

        corpus = CorpusGenerator(seed=1337).generate(hours=24.0)
        assert corpus.connections.height > 1_000
        assert TlsDgaAnalyzer().analyze(AnalysisContext(connections=corpus.connections)) == []

    def test_an_empty_context_is_silent(self) -> None:
        assert TlsDgaAnalyzer().analyze(AnalysisContext()) == []

    def test_a_frame_with_no_usable_columns_is_silent(self) -> None:
        assert TlsDgaAnalyzer().analyze(
            AnalysisContext(dns=pl.DataFrame({"ts": [1.0]}), ssl=pl.DataFrame({"ts": [1.0]}))
        ) == []

    def test_the_same_capture_produces_the_same_finding_ids(self) -> None:
        """Determinism is load-bearing: finding IDs are content-addressed, and
        an archived report cites them.

        The failure this guards is specific. A generated family has hundreds
        of names scoring an identical 1.0, and only three are reported — so
        without a total order the exemplars are chosen by whatever order
        `group_by` happened to return, which Polars does not promise to keep
        stable between runs.
        """
        dga = DgaCorpusGenerator(seed=1337).generate()
        tls = TlsCorpusGenerator(seed=1337).generate()
        ctx = AnalysisContext(dns=dga.queries, ssl=tls.sessions)
        runs = [[f.id for f in TlsDgaAnalyzer().analyze(ctx)] for _ in range(3)]
        assert runs[0] == runs[1] == runs[2]
        assert len(runs[0]) == len(set(runs[0]))


class TestSslIngest:
    def test_reads_a_zeek_tsv_ssl_log(self, tmp_path) -> None:
        from voidai.eval.synth import write_zeek_ssl_log
        from voidai.ingest.zeek import load_ssl, read_ssl_log

        corpus = TlsCorpusGenerator(seed=1337).generate()
        path = write_zeek_ssl_log(corpus.sessions, tmp_path / "ssl.log")
        frame = read_ssl_log(path)
        assert frame.height == corpus.sessions.height
        assert set(frame.columns) == set(SSL_SCHEMA)
        assert frame["ja3"].drop_nulls().n_unique() == corpus.sessions["ja3"].n_unique()
        assert load_ssl(tmp_path).height == frame.height

    def test_the_tsv_boolean_survives_the_parser(self) -> None:
        """Zeek writes `T`/`F`, which cast to null rather than to False."""
        import tempfile
        from pathlib import Path

        from voidai.eval.synth import write_zeek_ssl_log
        from voidai.ingest.zeek import read_ssl_log

        corpus = TlsCorpusGenerator(seed=1337).generate()
        with tempfile.TemporaryDirectory() as tmp:
            path = write_zeek_ssl_log(corpus.sessions, Path(tmp) / "ssl.log")
            frame = read_ssl_log(path)
        assert frame["established"].null_count() == 0
        assert frame["established"].all()

    def test_a_stock_zeek_log_parses_with_a_null_ja3_column(self, tmp_path) -> None:
        from voidai.eval.synth import write_zeek_ssl_log
        from voidai.ingest.zeek import read_ssl_log

        corpus = TlsCorpusGenerator(seed=1337).generate()
        path = write_zeek_ssl_log(corpus.sessions, tmp_path / "ssl.log", with_ja3=False)
        frame = read_ssl_log(path)
        assert frame.height == corpus.sessions.height
        assert frame["ja3"].null_count() == frame.height

    def test_a_missing_ssl_log_yields_an_empty_frame(self, tmp_path) -> None:
        from voidai.ingest.zeek import load_ssl

        assert load_ssl(tmp_path).is_empty()


class TestCorrelation:
    def test_a_rare_fingerprint_does_not_corroborate(self) -> None:
        """An implant beaconing over TLS earns a beaconing finding and a
        fingerprint finding from the same connection. That is one behaviour
        measured twice, and the multiplier counts behaviours.
        """
        from voidai.correlate import CorrelationConfig

        assert (
            Predicate.PRESENTS_RARE_TLS_FINGERPRINT
            in CorrelationConfig().non_corroborating
        )

    def test_a_generation_family_does_corroborate(self) -> None:
        """A host running a DGA is doing a second thing, not restating the
        first — the conjunction the multiplier exists to surface."""
        from voidai.correlate import CorrelationConfig

        assert (
            Predicate.RESOLVES_ALGORITHMIC_DOMAIN
            not in CorrelationConfig().non_corroborating
        )
