"""Host and endpoint analysis.

The most important tests here are the ones that assert *nothing* is emitted.
Both predicates are estate-relative, so the failure mode that matters is not a
missed detection — it is the analyzer speaking confidently over an estate too
small to support the claim, where every binary ever run is rare exactly once.

`TestTheGate` covers that against real attack telemetry containing a real true
positive, and the assertions are deliberately paired: zero findings *and* 447
records parsed, because "the analyzer declined" and "the parser returned
nothing" look identical from the outside and only one of them is correct.
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import polars as pl
import pytest

from voidai.analyzers import AnalysisContext, HostAnalyzer, HostConfig
from voidai.analyzers.host import (
    _name_expr,
    estate_baseline,
    host_summary,
    image_name,
    path_anomaly,
    score_lineage,
    score_process,
)
from voidai.eval.synth import HostCorpusGenerator
from voidai.ingest.schema import CONNECTION_SCHEMA, PROCESS_SCHEMA, conform, empty
from voidai.ingest.sysmon import read_sysmon
from voidai.lexicon import EntityType, Predicate

REAL = Path(__file__).parent / "data" / "real.sysmon.jsonl.gz"


@pytest.fixture(scope="module")
def corpus():
    return HostCorpusGenerator().generate()


@pytest.fixture(scope="module")
def findings(corpus):
    return HostAnalyzer().analyze(AnalysisContext(processes=corpus.events))


def _keys(findings, predicate: Predicate) -> set[tuple[str, str]]:
    return {
        (f.subject.value, f.object.value) for f in findings if f.predicate is predicate
    }


def _events(rows: list[dict[str, object]]) -> pl.DataFrame:
    frame = conform(pl.DataFrame(rows), PROCESS_SCHEMA)
    return frame.with_columns(
        pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
    )


def _row(host: str, parent: str, image: str, ts: float, guid: str = "", parent_guid: str = ""):
    return {
        "ts": ts,
        "host": host,
        "user": "EX\\u",
        "image": image,
        "command_line": f'"{image}"',
        "current_directory": "C:\\",
        "integrity_level": "Medium",
        "process_guid": guid or f"{{g-{host}-{image}-{ts}}}",
        "process_id": 100,
        "parent_image": parent,
        "parent_command_line": f'"{parent}"' if parent else None,
        "parent_guid": parent_guid or None,
        "parent_process_id": 99,
        "sha256": None,
        "source_file": "<test>",
        "source_line": 0,
    }


class TestTheGate:
    """An estate too small cannot support either verb, so neither is said."""

    def test_the_real_corpus_parses(self) -> None:
        assert read_sysmon(REAL).height == 447

    def test_and_the_analyzer_emits_nothing_on_it(self) -> None:
        """Real attack telemetry, a real true positive, and no finding.

        The APT29 emulation's day-1 payload is in this file. The analyzer does
        not report it, and that is correct rather than a miss: four hosts over
        half an hour is not an estate, and a rarity score computed over it
        ranks `lsass.exe` identically with the payload. Emitting the payload
        here would mean emitting `lsass.exe` too.
        """
        assert HostAnalyzer().analyze(AnalysisContext(processes=read_sysmon(REAL))) == []

    def test_the_reason_is_the_host_count(self) -> None:
        baseline = estate_baseline(host_summary(read_sysmon(REAL)))
        assert baseline.hosts == 4
        assert "4 host(s)" in (baseline.gate(HostConfig()) or "")

    def test_and_it_fails_the_convergence_gate_independently(self) -> None:
        """Lowering the host floor to four does not unlock it, and must not.

        This is the gate that host count alone would miss: 74% of the images
        in this capture are seen on exactly one host, `lsass.exe`,
        `explorer.exe`, `csrss.exe` and `services.exe` among them. An estate
        can be wide and still shallow, and then prevalence measures how long
        the sensor ran rather than how unusual the image is.
        """
        config = HostConfig(min_baseline_hosts=4, min_executions=100)
        baseline = estate_baseline(host_summary(read_sysmon(REAL)))
        assert baseline.singleton_share > config.max_singleton_share
        assert "have not converged" in (baseline.gate(config) or "").replace(
            "has not converged", "have not converged"
        )
        assert HostAnalyzer(config).analyze(AnalysisContext(processes=read_sysmon(REAL))) == []

    def test_a_single_host_capture_says_nothing(self) -> None:
        rows = [
            _row("SOLO", "C:\\Windows\\explorer.exe", f"C:\\Users\\a\\Temp\\p{i}.exe", 1000.0 + i)
            for i in range(400)
        ]
        assert HostAnalyzer().analyze(AnalysisContext(processes=_events(rows))) == []

    def test_the_gate_names_which_floor_was_missed(self) -> None:
        thin = estate_baseline(
            host_summary(
                _events(
                    [
                        _row(f"H{i}", "C:\\Windows\\explorer.exe", "C:\\Windows\\a.exe", 1.0 + i)
                        for i in range(10)
                    ]
                )
            )
        )
        assert "process creations" in (thin.gate(HostConfig()) or "")

    def test_an_empty_context_is_silent(self) -> None:
        assert HostAnalyzer().analyze(AnalysisContext()) == []

    def test_a_network_only_capture_is_silent(self) -> None:
        """The shape of every CTU-13 scenario, asserted rather than assumed.

        NetFlow and passivedns carry no process telemetry, so both predicates
        return before the gate is even reached and the real-capture ranking in
        `docs/benchmarks.md` cannot move. If it moves, something reached the
        queue that this test says cannot.
        """
        connections = pl.DataFrame(
            {"ts": [1.0, 2.0], "src_ip": ["10.0.0.1"] * 2, "dst_ip": ["8.8.8.8"] * 2},
        )
        ctx = AnalysisContext(connections=conform(connections, CONNECTION_SCHEMA))
        assert HostAnalyzer().analyze(ctx) == []
        assert ctx.processes.is_empty()


class TestDetection:
    def test_every_planted_rare_execution_is_found(self, corpus, findings) -> None:
        found = _keys(findings, Predicate.EXECUTES_RARE_PROCESS)
        assert corpus.process_keys <= found

    def test_every_planted_lineage_is_found(self, corpus, findings) -> None:
        found = _keys(findings, Predicate.EXHIBITS_ANOMALOUS_LINEAGE)
        assert {(host, child) for host, _parent, child in corpus.lineage_keys} <= found

    def test_the_only_false_positive_is_the_one_that_cannot_be_fixed_here(
        self, corpus, findings
    ) -> None:
        """A legitimate installer in a user's Downloads folder, run once.

        Rare image, writable path, single execution — indistinguishable from a
        dropped payload by everything this analyzer measures. It is planted
        deliberately and counted, rather than tuned away: a threshold moved
        until the corpus looks clean is a threshold fitted to the corpus.
        """
        planted = corpus.process_keys | {(h, c) for h, _p, c in corpus.lineage_keys}
        spurious = (
            _keys(findings, Predicate.EXECUTES_RARE_PROCESS)
            | _keys(findings, Predicate.EXHIBITS_ANOMALOUS_LINEAGE)
        ) - planted
        assert spurious == {("WS019.contoso.local", "7z2301-x64.exe")}

    def test_a_toolchain_only_one_machine_runs_is_not_reported(self, findings) -> None:
        """Perfect host rarity, and correctly rejected anyway.

        `msbuild.exe` on one host out of forty scores 1.0 on prevalence. It
        lives under `Program Files` and runs a hundred times, and the other
        two components are what stop a rarity measure from reporting every
        developer in the estate.
        """
        reported = {image for _host, image in _keys(findings, Predicate.EXECUTES_RARE_PROCESS)}
        assert "msbuild.exe" not in reported
        assert "node.exe" not in reported

    def test_a_toolchain_lineage_is_not_reported_either(self, findings) -> None:
        """`cmd.exe -> msbuild.exe` is the *only* way msbuild ever starts.

        Raw edge rarity cannot tell it from `winword.exe -> cmd.exe`: both are
        one host out of forty. Conditioning on how widespread each end is
        separates them completely — msbuild runs on one machine, so its
        parentage is entirely typical of msbuild.
        """
        reported = {i for _h, i in _keys(findings, Predicate.EXHIBITS_ANOMALOUS_LINEAGE)}
        assert "msbuild.exe" not in reported

    def test_an_administrator_tool_on_two_machines_is_not_reported(self, findings) -> None:
        both = _keys(findings, Predicate.EXECUTES_RARE_PROCESS) | _keys(
            findings, Predicate.EXHIBITS_ANOMALOUS_LINEAGE
        )
        assert not any(image == "psexec64.exe" for _host, image in both)

    def test_a_lineage_finding_needs_no_unusual_image(self, findings) -> None:
        """The half that rarity cannot see.

        Every image in `winword.exe -> cmd.exe -> powershell.exe` runs on
        every machine in the estate. If the two predicates measured the same
        thing this finding could not exist.
        """
        lineage = _keys(findings, Predicate.EXHIBITS_ANOMALOUS_LINEAGE)
        assert ("WS031.contoso.local", "cmd.exe") in lineage
        assert not any(image == "cmd.exe" for _h, image in
                       _keys(findings, Predicate.EXECUTES_RARE_PROCESS))

    def test_the_ancestry_is_resolved_and_reported(self, findings) -> None:
        """`explorer -> winword -> cmd` rather than `winword -> cmd`."""
        finding = next(
            f
            for f in findings
            if f.predicate is Predicate.EXHIBITS_ANOMALOUS_LINEAGE
            and f.object.value == "cmd.exe"
        )
        payload = finding.evidence[0].payload
        assert payload["chain"] == ["explorer.exe", "winword.exe", "cmd.exe"]
        assert payload["chain_truncated"] is False


class TestSubsumption:
    def test_one_execution_never_earns_both_predicates(self, findings) -> None:
        """Two findings about one event would be two behaviours to the correlator.

        `correlate.incidents` counts independent behaviours of a host and
        cannot know that a rare binary and its novel parent edge are one
        process creation. This analyzer can, and resolves it here.
        """
        rare = _keys(findings, Predicate.EXECUTES_RARE_PROCESS)
        lineage = _keys(findings, Predicate.EXHIBITS_ANOMALOUS_LINEAGE)
        assert rare & lineage == set()

    def test_the_rare_claim_wins_for_a_novel_binary(self, corpus, findings) -> None:
        """Not because it is more severe — it is the MEDIUM one — but because
        it names what is actually unusual. A binary the estate has never run
        trivially arrives on an edge the estate has never seen."""
        rare = _keys(findings, Predicate.EXECUTES_RARE_PROCESS)
        assert ("WS023.contoso.local", "svchost-update.exe") in rare


class TestRule12Determinism:
    """A top-N over equal scores needs a total order.

    Ties here are not rare, they are the norm: every singleton image sits at
    an identical prevalence of 1.0 and every one-off execution at an identical
    execution prevalence.
    """

    def test_shuffling_the_input_rows_changes_nothing(self, corpus) -> None:
        """The test the rule asks for, and the one that finds a leak.

        Running the same frame twice catches an ordering unstable across
        processes. It cannot catch an ordering that is deterministic for a
        given input order and changes when the rows arrive differently, which
        is what a `group_by` result leaking into a cap actually looks like.
        """
        analyzer = HostAnalyzer()
        first = analyzer.analyze(AnalysisContext(processes=corpus.events))
        shuffled = corpus.events.sample(fraction=1.0, shuffle=True, seed=99)
        second = analyzer.analyze(AnalysisContext(processes=shuffled))
        assert [f.id for f in first] == [f.id for f in second]

    def test_two_runs_agree(self, corpus) -> None:
        analyzer = HostAnalyzer()
        first = analyzer.analyze(AnalysisContext(processes=corpus.events))
        second = analyzer.analyze(AnalysisContext(processes=corpus.events))
        assert [(f.id, f.confidence) for f in first] == [(f.id, f.confidence) for f in second]

    def test_the_cap_keeps_the_same_findings_under_a_shuffle(self, corpus) -> None:
        """The cap is where an unstable order does real damage.

        Above the limit the order only changes the display; at the limit it
        changes which findings exist at all, and therefore which
        content-addressed IDs a report cites.
        """
        config = HostConfig(max_findings=2, max_findings_per_host=1)
        analyzer = HostAnalyzer(config)
        first = analyzer.analyze(AnalysisContext(processes=corpus.events))
        shuffled = corpus.events.sample(fraction=1.0, shuffle=True, seed=7)
        second = analyzer.analyze(AnalysisContext(processes=shuffled))
        assert len(first) <= 4  # two per predicate
        assert [f.id for f in first] == [f.id for f in second]

    def test_lazy_and_eager_contexts_agree(self, corpus) -> None:
        analyzer = HostAnalyzer()
        eager = analyzer.analyze(AnalysisContext(processes=corpus.events))
        lazy = analyzer.analyze(AnalysisContext(processes=corpus.events.lazy()))
        assert [f.id for f in eager] == [f.id for f in lazy]


class TestRule4Caps:
    def test_the_overall_cap_is_honoured(self, corpus) -> None:
        config = HostConfig(max_findings=1)
        findings = HostAnalyzer(config).analyze(AnalysisContext(processes=corpus.events))
        for predicate in (Predicate.EXECUTES_RARE_PROCESS, Predicate.EXHIBITS_ANOMALOUS_LINEAGE):
            assert len([f for f in findings if f.predicate is predicate]) <= 1

    def test_one_host_cannot_consume_the_whole_budget(self) -> None:
        """The flood mechanism a connection log does not have.

        A compromised machine can run thousands of distinct binaries by
        itself. Without a per-host ceiling it takes every slot and the rest of
        the estate is invisible — which is the alert flood this project exists
        to prevent, arriving from inside it.
        """
        # The estate needs more ordinary images than dropped ones, or the
        # convergence gate fires first and there is no cap left to test.
        rows: list[dict[str, object]] = []
        for host in range(12):
            for index in range(70):
                rows.append(
                    _row(
                        f"WS{host:03d}",
                        "C:\\Windows\\explorer.exe",
                        f"C:\\Windows\\System32\\common{index}.exe",
                        1000.0 + index,
                    )
                )
        for index in range(40):
            rows.append(
                _row(
                    "WS000",
                    "C:\\Windows\\explorer.exe",
                    f"C:\\Users\\v\\AppData\\Local\\Temp\\drop{index}.exe",
                    2000.0 + index,
                )
            )
        config = HostConfig(max_findings_per_host=3, max_findings=60)
        findings = HostAnalyzer(config).analyze(AnalysisContext(processes=_events(rows)))
        assert findings, "the estate should support a claim"
        for predicate in (
            Predicate.EXECUTES_RARE_PROCESS,
            Predicate.EXHIBITS_ANOMALOUS_LINEAGE,
        ):
            capped = [
                f for f in findings if f.subject.value == "WS000" and f.predicate is predicate
            ]
            assert len(capped) <= 3

    def test_a_capped_rare_finding_does_not_reappear_as_lineage(self) -> None:
        """The hole between the cap and the subsumption rule.

        Suppressing the lineage twin using the *capped* rare-process list
        means every novel binary the ceiling dropped comes back under the
        other predicate — and to the correlator that is a second independent
        behaviour of the host, which is the promotion the subsumption exists
        to prevent. Scoring is completed for both before either is capped.
        """
        rows: list[dict[str, object]] = []
        for host in range(12):
            for index in range(70):
                rows.append(
                    _row(
                        f"WS{host:03d}",
                        "C:\\Windows\\explorer.exe",
                        f"C:\\Windows\\System32\\common{index}.exe",
                        1000.0 + index,
                    )
                )
        for index in range(40):
            rows.append(
                _row(
                    "WS000",
                    "C:\\Windows\\explorer.exe",
                    f"C:\\Users\\v\\AppData\\Local\\Temp\\drop{index}.exe",
                    2000.0 + index,
                )
            )
        findings = HostAnalyzer(HostConfig(max_findings_per_host=1)).analyze(
            AnalysisContext(processes=_events(rows))
        )
        dropped = {
            f.object.value
            for f in findings
            if f.predicate is Predicate.EXHIBITS_ANOMALOUS_LINEAGE
        }
        assert not any(name.startswith("drop") for name in dropped)


class TestRule6UnmeasurableComponents:
    """Omit, never substitute. A missing measurement is not a measurement of zero."""

    def test_an_absent_image_path_omits_its_component(self) -> None:
        baseline = estate_baseline(
            host_summary(
                _events(
                    [
                        _row(f"H{i}", "C:\\Windows\\explorer.exe", "C:\\Windows\\a.exe", 1.0)
                        for i in range(8)
                    ]
                )
            )
        )
        assert path_anomaly(None) is None
        scored = score_process("", 1, 1, 1, baseline, HostConfig())
        assert scored is None

    def test_a_child_seen_on_one_host_omits_its_breadth(self) -> None:
        """Its parentage cannot be atypical: it has only ever had one."""
        baseline = estate_baseline(
            host_summary(
                _events(
                    [
                        _row(f"H{i}", "C:\\Windows\\explorer.exe", "C:\\Windows\\a.exe", 1.0)
                        for i in range(8)
                    ]
                )
            )
        )
        scored = score_lineage(
            child_path="C:\\Users\\a\\Temp\\x.exe",
            parent_name="explorer.exe",
            pair_hosts=1,
            pair_executions=1,
            parent_hosts=40,
            child_hosts=1,
            child_given_parent=None,
            chain=(),
            chain_truncated=True,
            observed=1,
            baseline=baseline,
            config=HostConfig(),
        )
        assert scored is not None
        assert "child_breadth" not in scored.components
        assert "parent_breadth" in scored.components

    def test_with_neither_end_measurable_the_verb_is_unsayable(self) -> None:
        baseline = estate_baseline(
            host_summary(
                _events(
                    [
                        _row(f"H{i}", "C:\\Windows\\explorer.exe", "C:\\Windows\\a.exe", 1.0)
                        for i in range(8)
                    ]
                )
            )
        )
        assert (
            score_lineage(
                child_path="C:\\x.exe",
                parent_name="p.exe",
                pair_hosts=1,
                pair_executions=1,
                parent_hosts=1,
                child_hosts=1,
                child_given_parent=0.5,
                chain=(),
                chain_truncated=True,
                observed=1,
                baseline=baseline,
                config=HostConfig(),
            )
            is None
        )

    def test_a_parent_with_too_few_children_omits_the_frequency(self, findings) -> None:
        """`winword.exe` spawned one process, so it spawned 100% of them once.

        1.0 there is not the observation "this is what it always does". It is
        the sample size, and reporting it as a measurement is the mistake this
        project has made three times.
        """
        finding = next(
            f
            for f in findings
            if f.predicate is Predicate.EXHIBITS_ANOMALOUS_LINEAGE
            and f.object.value == "cmd.exe"
        )
        payload = finding.evidence[0].payload
        assert payload["p_child_given_parent"] is None
        assert "child_surprisal" not in payload["components"]

    def test_a_system_path_is_low_rather_than_zero(self) -> None:
        """A flag would annihilate the geometric mean for anything in System32.

        The binaries most often abused live exactly there, so the band is
        graded: low enough to demand support from the other components, not so
        low that nothing under it can ever be reported.
        """
        assert path_anomaly("C:\\Windows\\System32\\cmd.exe") == pytest.approx(0.15)
        assert path_anomaly("C:\\Users\\a\\Downloads\\x.exe") == pytest.approx(1.0)
        assert path_anomaly("C:\\Program Files\\App\\app.exe") == pytest.approx(0.55)


class TestRule13Basis:
    def test_every_finding_says_why_it_is_in_the_queue(self, findings) -> None:
        for finding in findings:
            assert finding.basis
            assert "geometric mean" in finding.basis
            for component in finding.evidence[0].payload["components"]:
                assert component in finding.basis

    def test_every_finding_carries_a_retrievable_artifact(self, findings) -> None:
        for finding in findings:
            artifacts = [a for e in finding.evidence for a in e.artifacts]
            assert artifacts
            assert all(a.source and a.locator.startswith("line:") for a in artifacts)

    def test_the_estate_the_rarity_was_measured_over_is_recorded(self, findings) -> None:
        """A prevalence claim is only as good as its denominator.

        The TLS analyzer weights rarity by how much estate it was measured
        over; here the denominator is printed instead, because the gate
        already refuses the cases where it would be too small to weight.
        """
        for finding in findings:
            assert finding.evidence[0].payload["estate_hosts"] >= 5


class TestGrammar:
    def test_the_subject_is_a_host_and_the_object_a_process(self, findings) -> None:
        for finding in findings:
            assert finding.subject.type is EntityType.HOST
            assert finding.object is not None
            assert finding.object.type is EntityType.PROCESS

    def test_the_two_image_normalisers_agree(self, corpus) -> None:
        """One rule, two spellings — a Python function and a Polars expression.

        `dnstunnel` keeps `registered_domain` and `registered_domain_expr` in
        step with a test for exactly this reason: two implementations that
        drifted would split one image two ways inside one analyzer.
        """
        frame = corpus.events.with_columns(_name_expr("image").alias("expr"))
        for path, expression in zip(
            frame["image"].to_list(), frame["expr"].to_list(), strict=True
        ):
            assert image_name(path) == expression

    def test_the_normaliser_handles_both_separators(self) -> None:
        assert image_name("C:\\Windows\\System32\\CMD.EXE") == "cmd.exe"
        assert image_name("\\device\\harddiskvolume2\\windows\\explorer.exe") == "explorer.exe"
        assert image_name("/usr/bin/env") == "env"
        assert image_name(None) is None
        assert image_name("") is None


class TestAncestry:
    def test_a_cycle_does_not_fabricate_a_repeating_chain(self) -> None:
        """A collector replaying a spool writes the same record twice.

        The depth bound alone stops the walk, so a test that only asserts
        termination passes with the guard removed — it was one of two here
        that did, which is why rule 8 asks for the fix to be broken. What the
        visited set actually buys is the *content*: without it a two-node
        cycle reports `a -> b -> a -> b`, an ancestry that never happened, in
        an evidence payload an analyst is meant to trust.
        """
        analyzer = HostAnalyzer(HostConfig(max_chain_depth=4))
        tree = nx.DiGraph()
        tree.add_node("A", image_name="a.exe")
        tree.add_node("B", image_name="b.exe")
        tree.add_edge("A", "B")
        tree.add_edge("B", "A")

        chain, truncated = analyzer._chain(tree, "B")
        assert chain == ("a.exe", "b.exe")
        assert len(set(chain)) == len(chain), "an ancestry must not name a process twice"
        assert truncated

    def test_a_root_process_is_not_dropped_by_the_candidate_join(self) -> None:
        """`parent_image` is null at the root, and a default join deletes it.

        A process whose parent started before the capture window has no parent
        record — which is exactly the shape of the first execution on a host
        the sensor started watching mid-intrusion. Pass two joins on
        (host, parent, image), so without `nulls_equal` every one of those
        rows silently disappears between the two passes and the analyzer
        reports a clean estate.
        """
        rows: list[dict[str, object]] = []
        for host in range(10):
            for index in range(40):
                rows.append(
                    _row(
                        f"WS{host:03d}",
                        "C:\\Windows\\explorer.exe",
                        f"C:\\Windows\\System32\\common{index}.exe",
                        1000.0 + index,
                    )
                )
        orphan = _row(
            "WS000",
            "",
            "C:\\Users\\v\\AppData\\Local\\Temp\\orphan.exe",
            5000.0,
        )
        orphan["parent_image"] = None
        orphan["parent_command_line"] = None
        rows.append(orphan)

        findings = HostAnalyzer().analyze(AnalysisContext(processes=_events(rows)))
        assert any(f.object.value == "orphan.exe" for f in findings)

    def test_a_chain_reaching_the_capture_boundary_says_so(self) -> None:
        rows = [
            _row(f"WS{h:03d}", "C:\\Windows\\explorer.exe", image, 1000.0 + i,
                 guid=f"{{g-{h}-{i}}}", parent_guid="{outside-the-window}")
            for h in range(10)
            for i, image in enumerate(
                ["C:\\Windows\\System32\\cmd.exe", "C:\\Program Files\\O\\WINWORD.EXE"] * 12
            )
        ]
        rows.append(
            _row("WS000", "C:\\Program Files\\O\\WINWORD.EXE",
                 "C:\\Windows\\System32\\cmd.exe", 9000.0,
                 guid="{macro}", parent_guid="{outside-the-window}")
        )
        findings = HostAnalyzer().analyze(AnalysisContext(processes=_events(rows)))
        lineage = [f for f in findings if f.predicate is Predicate.EXHIBITS_ANOMALOUS_LINEAGE]
        assert lineage
        assert any(f.evidence[0].payload["chain_truncated"] for f in lineage)


class TestBaselineReporting:
    def test_the_summary_is_readable(self, corpus) -> None:
        baseline = estate_baseline(host_summary(corpus.events))
        assert baseline.gate(HostConfig()) is None
        assert "hosts" in baseline.summary()
        assert "seen on one host only" in baseline.summary()

    def test_an_empty_frame_describes_an_empty_estate(self) -> None:
        baseline = estate_baseline(host_summary(empty(PROCESS_SCHEMA)))
        assert baseline.hosts == 0
        assert baseline.singleton_share == 1.0
        assert baseline.gate(HostConfig()) is not None


class TestBenchmarkScoring:
    """How a plant is counted decides what the accuracy figure means."""

    def test_a_plant_is_scored_only_against_its_own_predicate(self) -> None:
        """The two halves cannot see each other's plants, by design.

        An image the estate has never run cannot be found by a measure of how
        unusual its parentage is — it has no other parentage to compare
        against. Counting every plant against both predicates would report a
        50% miss rate for a detector behaving exactly as specified, which is
        the shape section 9 avoided by counting a dictionary generator as a
        miss and saying so rather than dropping it from the denominator.
        """
        from voidai.eval.benchmark import score_host

        corpus = HostCorpusGenerator().generate()
        findings = HostAnalyzer().analyze(AnalysisContext(processes=corpus.events))
        score = score_host(findings, corpus)

        assert score.true_positives == len(corpus.implants)
        assert score.false_negatives == 0
        assert score.recall == 1.0

    def test_the_planted_false_positive_is_counted_not_excused(self) -> None:
        from voidai.eval.benchmark import score_host

        corpus = HostCorpusGenerator().generate()
        findings = HostAnalyzer().analyze(AnalysisContext(processes=corpus.events))
        score = score_host(findings, corpus)

        assert score.false_positives == 1
        assert score.precision < 1.0
        assert "expected false positive" in score.false_positive_pairs[0]

    def test_the_benchmark_reads_through_the_production_parser(self) -> None:
        """Not the frame. The parser prefers `UtcTime` over `@timestamp` and
        reads Sysmon's PascalCase rather than the normalised schema's, and a
        benchmark handed a ready-made frame exercises neither."""
        import inspect

        from voidai.eval.benchmark import run_host_benchmark

        source = inspect.getsource(run_host_benchmark)
        assert "write_sysmon_jsonl" in source
        assert "read_sysmon" in source


class TestRule3TwoPasses:
    """Peak memory must track candidates, not records."""

    def test_pass_two_gathers_a_small_fraction_of_the_capture(self) -> None:
        """The gate the two-pass split exists to enforce.

        Pass one groups to scalars and streams; pass two collects arrays only
        for triples that could still qualify. Written as a row count rather
        than as a memory measurement because an RSS assertion is flaky and
        this is the property that actually decides the memory: if pass two
        ever collects the capture, the arrays hold every execution in it.
        """
        rows: list[dict[str, object]] = []
        for host in range(20):
            for index in range(60):
                for repeat in range(20):
                    rows.append(
                        _row(
                            f"WS{host:03d}",
                            "C:\\Windows\\explorer.exe",
                            f"C:\\Windows\\System32\\common{index}.exe",
                            1000.0 + repeat,
                        )
                    )
        rows.append(
            _row(
                "WS000",
                "C:\\Windows\\explorer.exe",
                "C:\\Users\\v\\AppData\\Local\\Temp\\drop.exe",
                9000.0,
            )
        )
        events = _events(rows)

        analyzer = HostAnalyzer()
        collected: list[int] = []
        original = analyzer._collect_series

        def spy(scan, candidates):  # type: ignore[no-untyped-def]
            gathered = original(scan, candidates)
            collected.append(int(gathered["n"].sum()) if not gathered.is_empty() else 0)
            return gathered

        analyzer._collect_series = spy  # type: ignore[method-assign]
        findings = analyzer.analyze(AnalysisContext(processes=events))

        assert findings, "the planted execution should be found"
        assert collected, "pass two never ran"
        assert collected[0] < events.height / 100, (
            f"pass two gathered {collected[0]} of {events.height} executions; "
            "the candidate gate is not pruning"
        )
