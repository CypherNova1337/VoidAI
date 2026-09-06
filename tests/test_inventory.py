"""Tests for the asset inventory parser and the join it performs.

Rule 7: **this is entirely synthetic, and there is nothing here to detect.**
No mapping is discovered, no detector is scored, and no precision or recall
figure comes out of this file. The correctness questions are narrower and they
are the ones a join actually fails at: whether the right mapping wins, whether
a stale or partial inventory degrades honestly rather than silently, whether
provenance reaches the evidence payload, and whether a capture without an
inventory produces byte-identical findings to one analysed before this module
existed.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from voidai.analyzers import AnalysisContext, BeaconingAnalyzer, HostAnalyzer
from voidai.eval.synth import CorpusGenerator, HostCorpusGenerator
from voidai.ingest.inventory import (
    MAX_AGE_DAYS,
    CaptureWindow,
    Inventory,
    load_inventory,
    read_inventory_file,
)
from voidai.ingest.schema import CONNECTION_SCHEMA, conform
from voidai.lexicon import EntityType

#: The demo capture's epoch, so a window here means what it means there.
CAPTURE_EPOCH = 1_750_000_000.0
WINDOW = CaptureWindow(start=date(2025, 6, 15), end=date(2025, 6, 16))


def write(tmp_path: Path, text: str, name: str = "assets.inv") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestParsing:
    def test_header_configures_the_register(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "# name: corp-register\n"
            "# updated: 2025-06-11\n"
            "# reference: https://netbox.internal/\n"
            "# tlp: amber\n"
            "\n"
            "10.0.1.14  FINANCE-WS04\n",
        )
        register, mappings, rejected = read_inventory_file(path)
        assert register.name == "corp-register"
        assert register.updated == date(2025, 6, 11)
        assert register.reference == "https://netbox.internal/"
        assert register.tlp == "amber"
        assert not rejected
        # The register's date is the fallback for a mapping that states none.
        assert mappings[0].stated == date(2025, 6, 11)

    def test_a_comment_below_the_first_mapping_cannot_restate_provenance(
        self, tmp_path: Path
    ) -> None:
        path = write(
            tmp_path,
            "# name: corp-register\n"
            "10.0.1.14  FINANCE-WS04\n"
            "# name: something-else\n"
            "10.0.1.20  HR-WS02\n",
        )
        register, mappings, _ = read_inventory_file(path)
        assert register.name == "corp-register"
        assert len(mappings) == 2

    def test_attributes_are_read_and_unknown_ones_kept(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "10.0.1.14  FINANCE-WS04  stated=2025-06-11  note=static lease  owner=finance\n",
        )
        _, mappings, _ = read_inventory_file(path)
        assert mappings[0].stated == date(2025, 6, 11)
        assert mappings[0].note == "static lease"
        # A field this parser did not anticipate survives into the payload.
        assert mappings[0].attributes["owner"] == "finance"

    def test_a_single_label_hostname_is_accepted(self, tmp_path: Path) -> None:
        _, mappings, rejected = read_inventory_file(write(tmp_path, "10.0.1.14  WS04\n"))
        assert not rejected
        assert mappings[0].hostname == "WS04"

    @pytest.mark.parametrize(
        "line",
        [
            "10.0.1.14\n",  # an address with no name is a typo, not half a mapping
            "not-an-address  FINANCE-WS04\n",
            "10.0.1.14  10.0.1.15\n",  # a second address is not a hostname
            "10.0.1.14  bad!name\n",
        ],
    )
    def test_an_implausible_line_is_rejected_and_reported(self, tmp_path: Path, line: str) -> None:
        path = write(tmp_path, f"{line}10.0.1.20  HR-WS02\n")
        _, mappings, rejected = read_inventory_file(path)
        # One bad entry must not cost the good one, and it is reported as
        # written so an operator can recognise what they typed.
        assert [m.hostname for m in mappings] == ["HR-WS02"]
        assert len(rejected) == 1 and rejected[0][2] == line.strip()

    def test_only_the_inv_extension_is_read(self, tmp_path: Path) -> None:
        write(tmp_path, "10.0.1.14  FINANCE-WS04\n", name="hosts.txt")
        assert load_inventory(tmp_path).is_empty()

    def test_a_missing_path_is_an_empty_inventory_not_an_error(self, tmp_path: Path) -> None:
        assert load_inventory(tmp_path / "nope").is_empty()


class TestDuplicates:
    def test_the_more_recent_statement_wins(self, tmp_path: Path) -> None:
        write(tmp_path, "10.0.1.14  OLD-NAME  stated=2025-01-01\n", name="a.inv")
        write(tmp_path, "10.0.1.14  NEW-NAME  stated=2025-06-01\n", name="b.inv")
        assert load_inventory(tmp_path).by_address["10.0.1.14"].hostname == "NEW-NAME"

    def test_a_dated_statement_beats_an_undated_one(self, tmp_path: Path) -> None:
        write(tmp_path, "10.0.1.14  DATED  stated=2025-01-01\n", name="a.inv")
        write(tmp_path, "10.0.1.14  UNDATED\n", name="b.inv")
        assert load_inventory(tmp_path).by_address["10.0.1.14"].hostname == "DATED"

    def test_indistinguishable_statements_resolve_by_file_and_line(self, tmp_path: Path) -> None:
        """Rule 12. Without this the winner depends on iteration order, and a
        finding's subject — and its content-addressed ID — moves between runs."""
        write(tmp_path, "10.0.1.14  FIRST  stated=2025-06-01\n", name="a.inv")
        write(tmp_path, "10.0.1.14  SECOND stated=2025-06-01\n", name="z.inv")
        assert load_inventory(tmp_path).by_address["10.0.1.14"].hostname == "FIRST"

    def test_insertion_order_does_not_decide(self, tmp_path: Path) -> None:
        _, first, _ = read_inventory_file(
            write(tmp_path, "10.0.1.14  A  stated=2025-06-01\n", name="a.inv")
        )
        _, second, _ = read_inventory_file(
            write(tmp_path, "10.0.1.14  B  stated=2025-06-01\n", name="z.inv")
        )
        forwards, backwards = Inventory(), Inventory()
        for mapping in first + second:
            forwards.add(mapping)
        for mapping in second + first:
            backwards.add(mapping)
        assert (
            forwards.by_address["10.0.1.14"].hostname == backwards.by_address["10.0.1.14"].hostname
        )


class TestStaleness:
    def mapping(self, tmp_path: Path, stated: str):  # type: ignore[no-untyped-def]
        line = f"10.0.1.14  FINANCE-WS04{stated}\n"
        _, mappings, _ = read_inventory_file(write(tmp_path, line))
        return mappings[0]

    def test_a_recent_statement_is_current_and_unremarked(self, tmp_path: Path) -> None:
        mapping = self.mapping(tmp_path, "  stated=2025-06-11")
        assert mapping.staleness(WINDOW) == "current"
        assert mapping.age_days(WINDOW) == 4
        assert mapping.applies(WINDOW)

    def test_an_old_statement_is_applied_and_flagged(self, tmp_path: Path) -> None:
        mapping = self.mapping(tmp_path, "  stated=2024-06-11")
        assert mapping.staleness(WINDOW) == "stale"
        assert mapping.applies(WINDOW)

    def test_a_statement_past_the_horizon_is_not_applied_at_all(self, tmp_path: Path) -> None:
        mapping = self.mapping(tmp_path, "  stated=2020-01-01")
        assert mapping.age_days(WINDOW) > MAX_AGE_DAYS
        assert mapping.staleness(WINDOW) == "expired"
        assert not mapping.applies(WINDOW)

    def test_a_statement_made_after_the_capture_is_flagged(self, tmp_path: Path) -> None:
        """The sharp case. A fresh file reads as the safe kind, and says
        nothing reliable about who held the address when the traffic ran."""
        mapping = self.mapping(tmp_path, "  stated=2025-09-01")
        assert mapping.staleness(WINDOW) == "stated_after_capture"
        assert mapping.applies(WINDOW)

    def test_an_undated_statement_is_flagged_rather_than_assumed_recent(
        self, tmp_path: Path
    ) -> None:
        mapping = self.mapping(tmp_path, "")
        assert mapping.stated is None
        assert mapping.staleness(WINDOW) == "undated"
        assert mapping.applies(WINDOW)

    def test_an_undatable_capture_judges_nothing(self, tmp_path: Path) -> None:
        mapping = self.mapping(tmp_path, "  stated=2020-01-01")
        assert mapping.staleness(CaptureWindow()) == "unknown_window"
        assert mapping.applies(CaptureWindow())

    def test_age_is_measured_against_the_capture_not_the_clock(self, tmp_path: Path) -> None:
        """Two windows, one mapping, two verdicts — which is the point. An age
        taken from `datetime.now()` would also give one run a different
        evidence ID every day."""
        mapping = self.mapping(tmp_path, "  stated=2023-01-01")
        assert mapping.staleness(CaptureWindow(start=date(2023, 2, 1))) == "current"
        assert mapping.staleness(CaptureWindow(start=date(2024, 1, 1))) == "stale"
        assert mapping.staleness(CaptureWindow(start=date(2025, 6, 15))) == "expired"

    def test_an_expired_mapping_is_absent_from_the_applied_map(self, tmp_path: Path) -> None:
        write(
            tmp_path, "10.0.1.14  GONE  stated=2018-01-01\n10.0.1.20  HR-WS02  stated=2025-06-01\n"
        )
        inventory = load_inventory(tmp_path)
        assert inventory.applied(WINDOW) == {"10.0.1.20": "HR-WS02"}
        assert inventory.resolve("10.0.1.14", WINDOW) is None


class TestCoverage:
    def test_coverage_reports_the_fraction_not_the_count(self, tmp_path: Path) -> None:
        """A mapping count cannot distinguish a complete inventory from one
        covering 3% of an estate. `docs/roadmap.md` §6."""
        write(tmp_path, "10.0.1.14  FINANCE-WS04  stated=2025-06-01\n")
        observed = {f"10.0.1.{n}" for n in range(10, 110)}
        coverage = load_inventory(tmp_path).coverage(WINDOW, observed)
        assert (coverage.loaded, coverage.applied, coverage.matched) == (1, 1, 1)
        assert coverage.observed == 100
        assert coverage.fraction == pytest.approx(0.01)

    def test_mappings_for_addresses_never_seen_do_not_count_as_covered(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "192.168.99.5  ELSEWHERE  stated=2025-06-01\n")
        coverage = load_inventory(tmp_path).coverage(WINDOW, {"10.0.1.14"})
        assert coverage.loaded == 1 and coverage.matched == 0
        assert coverage.fraction == 0.0

    def test_dropped_mappings_are_counted_separately(self, tmp_path: Path) -> None:
        write(tmp_path, "10.0.1.14  A  stated=2016-01-01\n10.0.1.20  B  stated=2025-06-01\n")
        coverage = load_inventory(tmp_path).coverage(WINDOW, {"10.0.1.14", "10.0.1.20"})
        assert (coverage.loaded, coverage.applied, coverage.dropped) == (2, 1, 1)
        assert coverage.matched == 1


@pytest.fixture(scope="module")
def corpus():  # type: ignore[no-untyped-def]
    return CorpusGenerator(seed=1337).generate(hours=24.0)


@pytest.fixture(scope="module")
def events():  # type: ignore[no-untyped-def]
    return HostCorpusGenerator(seed=1337).generate(hours=6.0, start_epoch=CAPTURE_EPOCH).events


def context(corpus, inventory: Inventory) -> AnalysisContext:  # type: ignore[no-untyped-def]
    return AnalysisContext(connections=corpus.connections, inventory=inventory)


class TestTheJoin:
    def test_a_loaded_mapping_renames_the_subject(self, tmp_path: Path, corpus) -> None:  # type: ignore[no-untyped-def]
        write(tmp_path, "10.0.1.14  FINANCE-WS04  stated=2025-06-11\n")
        findings = BeaconingAnalyzer().analyze(context(corpus, load_inventory(tmp_path)))
        renamed = [f for f in findings if f.subject.value == "FINANCE-WS04"]
        assert len(renamed) == 1
        assert renamed[0].subject.type is EntityType.HOST

    def test_the_window_is_measured_from_the_telemetry(self, tmp_path: Path, corpus) -> None:  # type: ignore[no-untyped-def]
        write(tmp_path, "10.0.1.14  FINANCE-WS04\n")
        ctx = context(corpus, load_inventory(tmp_path))
        assert ctx.capture.known
        assert ctx.ip_to_host == {"10.0.1.14": "FINANCE-WS04"}

    def test_an_expired_mapping_renames_nothing(self, tmp_path: Path, corpus) -> None:  # type: ignore[no-untyped-def]
        write(tmp_path, "10.0.1.14  FINANCE-WS04  stated=2015-01-01\n")
        ctx = context(corpus, load_inventory(tmp_path))
        assert ctx.ip_to_host == {}
        findings = BeaconingAnalyzer().analyze(ctx)
        assert all(f.subject.type is EntityType.IP for f in findings)

    def test_a_caller_supplied_map_still_wins(self, tmp_path: Path, corpus) -> None:  # type: ignore[no-untyped-def]
        write(tmp_path, "10.0.1.14  FROM-FILE  stated=2025-06-11\n")
        ctx = AnalysisContext(
            connections=corpus.connections,
            inventory=load_inventory(tmp_path),
            ip_to_host={"10.0.1.14": "FROM-CALLER"},
        )
        findings = BeaconingAnalyzer().analyze(ctx)
        renamed = [f for f in findings if f.subject.value == "FROM-CALLER"]
        assert len(renamed) == 1
        # And it cites nothing, because no line of any file stated it.
        assert not [e for e in renamed[0].evidence if e.kind == "asset_inventory"]


class TestProvenanceInTheEvidence:
    def evidence(self, tmp_path: Path, corpus, line: str):  # type: ignore[no-untyped-def]
        write(tmp_path, line)
        findings = BeaconingAnalyzer().analyze(context(corpus, load_inventory(tmp_path)))
        renamed = [f for f in findings if f.subject.type is EntityType.HOST]
        assert len(renamed) == 1
        found = [e for e in renamed[0].evidence if e.kind == "asset_inventory"]
        assert len(found) == 1
        return found[0]

    def test_the_mapping_is_a_link_in_the_chain_of_custody(self, tmp_path: Path, corpus) -> None:
        evidence = self.evidence(
            tmp_path, corpus, "10.0.1.14  FINANCE-WS04  stated=2025-06-11  note=static lease\n"
        )
        assert evidence.payload["address"] == "10.0.1.14"
        assert evidence.payload["hostname"] == "FINANCE-WS04"
        assert evidence.payload["stated_on"] == "2025-06-11"
        assert evidence.payload["note"] == "static lease"
        # Where it came from, and when it was stated: both, per §6.
        assert evidence.payload["staleness"] == "current"
        assert evidence.payload["age_days"] == 4
        # An analyst can open the statement and read it as it was written.
        artifact = evidence.artifacts[0]
        assert artifact.source.endswith("assets.inv")
        assert artifact.locator == "line:1"
        assert "FINANCE-WS04" in (artifact.excerpt or "")

    def test_a_stale_mapping_says_so_rather_than_resolving_silently(
        self, tmp_path: Path, corpus
    ) -> None:
        evidence = self.evidence(tmp_path, corpus, "10.0.1.14  FINANCE-WS04  stated=2024-01-01\n")
        assert evidence.payload["staleness"] == "stale"
        assert "stale" in evidence.summary

    def test_an_undated_mapping_says_so(self, tmp_path: Path, corpus) -> None:
        evidence = self.evidence(tmp_path, corpus, "10.0.1.14  FINANCE-WS04\n")
        assert evidence.payload["stated_on"] is None
        assert evidence.payload["staleness"] == "undated"
        assert "undated" in evidence.summary

    def test_a_mapping_stated_after_the_capture_says_so(self, tmp_path: Path, corpus) -> None:
        evidence = self.evidence(tmp_path, corpus, "10.0.1.14  FINANCE-WS04  stated=2030-01-01\n")
        assert evidence.payload["staleness"] == "stated_after_capture"
        assert "after the capture" in evidence.summary


class TestNoInventoryIsAByteIdenticalNoOp:
    """The property the CTU-13 captures depend on. They ship no `.inv`, so
    every figure in `docs/benchmarks.md` must be reproduced unchanged — not
    approximately, but with the same content-addressed IDs."""

    def test_findings_are_identical_with_an_empty_inventory(self, corpus) -> None:  # type: ignore[no-untyped-def]
        plain = BeaconingAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        with_empty = BeaconingAnalyzer().analyze(context(corpus, Inventory()))
        assert [f.id for f in plain] == [f.id for f in with_empty]

    def test_an_inventory_naming_nobody_here_changes_no_id(self, tmp_path: Path, corpus) -> None:
        plain = BeaconingAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        write(tmp_path, "192.168.99.5  ELSEWHERE  stated=2025-06-01\n")
        loaded = BeaconingAnalyzer().analyze(context(corpus, load_inventory(tmp_path)))
        assert [f.id for f in plain] == [f.id for f in loaded]

    def test_unresolved_findings_keep_their_ids_when_one_host_resolves(
        self, tmp_path: Path, corpus
    ) -> None:
        """The inventory may only move the findings it actually renames."""
        plain = BeaconingAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        write(tmp_path, "10.0.1.14  FINANCE-WS04  stated=2025-06-11\n")
        loaded = BeaconingAnalyzer().analyze(context(corpus, load_inventory(tmp_path)))
        untouched = {f.id for f in plain if f.subject.value != "10.0.1.14"}
        assert untouched <= {f.id for f in loaded}


class TestHostFindingsDoNotChurn:
    """`host.py` never calls `actor()`, so it never calls
    `resolution_evidence()` and cannot pick up a citation it did not rely on.
    That is structural rather than a guard, and this asserts the property
    anyway: a Sysmon-derived finding's ID must not move because a file
    appeared on disk beside the capture."""

    def test_a_sysmon_finding_keeps_its_id(self, tmp_path: Path, events) -> None:  # type: ignore[no-untyped-def]
        plain = HostAnalyzer().analyze(AnalysisContext(processes=events))
        assert plain, "the fixture must produce host findings for this to mean anything"
        named = {f.subject.value for f in plain}
        # Name every machine the host analyzer spoke about, so the inventory
        # would attach to all of them if the mechanism let it.
        write(
            tmp_path,
            "".join(
                f"10.0.9.{index + 1}  {host}  stated=2025-06-11\n"
                for index, host in enumerate(sorted(named))
            ),
        )
        loaded = HostAnalyzer().analyze(
            AnalysisContext(processes=events, inventory=load_inventory(tmp_path))
        )
        assert [f.id for f in plain] == [f.id for f in loaded]
        assert not [e for f in loaded for e in f.evidence if e.kind == "asset_inventory"]


class TestRowOrderDoesNotLeak:
    def test_shuffling_the_input_changes_nothing(self, tmp_path: Path, corpus) -> None:  # type: ignore[no-untyped-def]
        """Rule 12's stronger test: the same rows in a different order."""
        write(tmp_path, "10.0.1.14  FINANCE-WS04  stated=2025-06-11\n")
        inventory = load_inventory(tmp_path)
        shuffled = conform(
            corpus.connections.sample(fraction=1.0, shuffle=True, seed=99), CONNECTION_SCHEMA
        )
        first = BeaconingAnalyzer().analyze(context(corpus, inventory))
        second = BeaconingAnalyzer().analyze(
            AnalysisContext(connections=shuffled, inventory=inventory)
        )
        assert [f.id for f in first] == [f.id for f in second]


class TestOffline:
    def test_loading_an_inventory_opens_no_socket(self, tmp_path: Path) -> None:
        """Rule 11. The tempting shortcut in this cluster is not an HTTP call
        but a lookup service, and both are the same commitment."""
        import socket

        write(tmp_path, "10.0.1.14  FINANCE-WS04  stated=2025-06-11\n")
        original = socket.socket

        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("the inventory parser must not open a socket")

        socket.socket = refuse  # type: ignore[assignment]
        try:
            assert len(load_inventory(tmp_path)) == 1
        finally:
            socket.socket = original  # type: ignore[assignment]
