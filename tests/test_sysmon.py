"""Sysmon JSON-lines ingest.

Two halves. The first reads the committed real corpus — 447 process creations
from the OTRF APT29 emulation — because a parser validated only against
telemetry this repository generated has been validated against its author's
beliefs about the format. The second covers the shapes real collectors emit
that the corpus happens not to contain.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import polars as pl
import pytest

from voidai.ingest.schema import PROCESS_SCHEMA
from voidai.ingest.sysmon import load_processes, read_sysmon

REAL = Path(__file__).parent / "data" / "real.sysmon.jsonl.gz"


def _record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "EventID": 1,
        "SourceName": "Microsoft-Windows-Sysmon",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": "2024-03-01 09:15:00.123",
        "Hostname": "WS001.example.local",
        "User": "EXAMPLE\\jsmith",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": '"cmd.exe" /c whoami',
        "ProcessGuid": "{aaaa-1}",
        "ProcessId": 4242,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentProcessGuid": "{aaaa-0}",
    }
    record.update(overrides)
    return {k: v for k, v in record.items() if v is not None}


def _write(tmp_path: Path, records: list[dict[str, object]], name: str = "sysmon.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return path


class TestRealCorpus:
    """The committed OTRF excerpt. See its in-band header for provenance."""

    def test_reads_every_process_creation(self) -> None:
        frame = read_sysmon(REAL)
        assert frame.height == 447

    def test_conforms_to_the_schema(self) -> None:
        frame = read_sysmon(REAL)
        assert frame.columns == list(PROCESS_SCHEMA)

    def test_the_estate_is_four_hosts(self) -> None:
        """The number the analyzer's gate acts on. See `test_host.py`."""
        frame = read_sysmon(REAL)
        assert frame["host"].n_unique() == 4

    def test_every_record_has_a_timestamp_and_a_host(self) -> None:
        frame = read_sysmon(REAL)
        assert frame["ts"].null_count() == 0
        assert frame["host"].null_count() == 0

    def test_a_root_process_keeps_its_null_parent(self) -> None:
        """One record in the capture has no parent image, and it must survive.

        A process whose parent started before the capture window is exactly
        what a freshly compromised host produces, and a parser that dropped
        the row — or a join that dropped it later — would delete the first
        execution of an intrusion.
        """
        frame = read_sysmon(REAL)
        assert frame["parent_image"].null_count() == 1

    def test_the_attribution_header_is_carried_in_band(self) -> None:
        """Provenance travels with the data, as `real.passivedns` does.

        A licence recorded only in a document is a licence that goes missing
        the first time the file is copied somewhere else.
        """
        with gzip.open(REAL, "rt", encoding="utf-8") as handle:
            text = handle.read()
        header = "\n".join(line for line in text.splitlines() if line.startswith("#"))
        assert "MIT Licence" in header
        assert "Open Threat Research Forge" in header
        assert "github.com/OTRF/Security-Datasets" in header
        assert "Message" in header, "the dropped field must be declared"

    def test_the_payload_the_analyzer_reads_survived(self) -> None:
        frame = read_sysmon(REAL)
        payload = frame.filter(pl.col("image").str.contains("cod.3aka3.scr"))
        assert payload.height == 1
        assert payload["parent_image"][0].endswith("explorer.exe")
        assert payload["sha256"][0] is not None


class TestFiltering:
    def test_only_event_id_one_is_read(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            [_record(), _record(EventID=3, Image="C:\\Windows\\System32\\net.exe")],
        )
        assert read_sysmon(path).height == 1

    def test_event_id_one_from_another_provider_is_ignored(self, tmp_path: Path) -> None:
        """`EventID` 1 means something else in every other Windows channel.

        The line-level pre-filter is a substring test on the provider name, so
        a record naming Sysmon in its *text* still reaches the structured
        check — and that check is what must reject it.
        """
        impostor = _record(
            SourceName="Microsoft-Windows-PowerShell",
            Channel="Microsoft-Windows-PowerShell/Operational",
            CommandLine="Get-WinEvent Microsoft-Windows-Sysmon/Operational",
        )
        path = _write(tmp_path, [_record(), impostor])
        assert read_sysmon(path).height == 1

    def test_a_channel_only_record_is_accepted(self, tmp_path: Path) -> None:
        """Some pipelines write `Channel` and drop `SourceName`."""
        path = _write(tmp_path, [_record(SourceName=None)])
        assert read_sysmon(path).height == 1

    def test_comment_lines_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "sysmon.jsonl"
        path.write_text("# provenance\n#\n" + json.dumps(_record()) + "\n")
        assert read_sysmon(path).height == 1

    def test_a_malformed_line_does_not_lose_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "sysmon.jsonl"
        path.write_text(
            json.dumps(_record())
            + '\n{"EventID": 1, "SourceName": "Microsoft-Windows-Sysmon", tru\n'
            + json.dumps(_record(ProcessGuid="{aaaa-2}"))
            + "\n"
        )
        assert read_sysmon(path).height == 2


class TestFields:
    def test_field_names_are_matched_case_insensitively(self, tmp_path: Path) -> None:
        lowered = {
            "EventID": 1,
            "SourceName": "Microsoft-Windows-Sysmon",
            "utctime": "2024-03-01 09:15:00.123",
            "hostname": "WS002.example.local",
            "image": "C:\\Windows\\System32\\cmd.exe",
            "commandline": "cmd",
            "parentimage": "C:\\Windows\\explorer.exe",
        }
        frame = read_sysmon(_write(tmp_path, [lowered]))
        assert frame["host"][0] == "WS002.example.local"
        assert frame["parent_image"][0].endswith("explorer.exe")

    def test_computer_is_accepted_as_the_host(self, tmp_path: Path) -> None:
        frame = read_sysmon(_write(tmp_path, [_record(Hostname=None, Computer="DC1.example")]))
        assert frame["host"][0] == "DC1.example"

    def test_sha256_is_pulled_from_the_combined_hash_field(self, tmp_path: Path) -> None:
        digest = "F" * 64
        record = _record(Hashes=f"SHA1={'A' * 40},MD5={'B' * 32},SHA256={digest}")
        assert read_sysmon(_write(tmp_path, [record]))["sha256"][0] == digest

    def test_a_hash_field_without_sha256_yields_null(self, tmp_path: Path) -> None:
        """Never another algorithm's digest under the wrong name.

        `HashAlgorithms` is configurable, and a positional slice of the field
        would silently label an MD5 as a SHA256 on any sensor that omits it.
        """
        record = _record(Hashes=f"SHA1={'A' * 40},MD5={'B' * 32}")
        assert read_sysmon(_write(tmp_path, [record]))["sha256"][0] is None


class TestTimestamps:
    def test_the_sensor_clock_wins_over_the_shipper_clock(self, tmp_path: Path) -> None:
        """`@timestamp` is when the collector saw it, not when it happened.

        On the committed corpus the two differ by a median of 34 seconds and
        a maximum of 84 — well past the one-second floor the correlator uses
        to order two behaviours from a single source. Taking the shipper's
        clock would not blur an ordering; it would invent one.
        """
        record = _record(**{"@timestamp": "2024-03-01T09:16:30.000Z"})
        frame = read_sysmon(_write(tmp_path, [record]))
        assert frame["ts"][0] == pytest.approx(1_709_284_500.123, abs=0.01)

    def test_the_shipper_clock_is_used_when_the_sensor_clock_is_absent(
        self, tmp_path: Path
    ) -> None:
        record = _record(UtcTime=None, **{"@timestamp": "2024-03-01T09:16:30.000Z"})
        frame = read_sysmon(_write(tmp_path, [record]))
        assert frame["ts"][0] == pytest.approx(1_709_284_590.0, abs=0.01)

    def test_whole_second_timestamps_parse(self, tmp_path: Path) -> None:
        frame = read_sysmon(_write(tmp_path, [_record(UtcTime="2024-03-01 09:15:00")]))
        assert frame["ts"][0] == pytest.approx(1_709_284_500.0, abs=0.01)

    def test_a_file_with_no_shipper_column_at_all_still_reads(self, tmp_path: Path) -> None:
        """A column no record populates infers as Null, not as empty strings.

        The string parser rejects that dtype outright rather than yielding
        nulls, so a collector writing only `UtcTime` — which is every
        collector this project's own generator imitates — took the whole read
        down until the cast was added.
        """
        assert read_sysmon(_write(tmp_path, [_record()])).height == 1


class TestDiscovery:
    def test_gzip_is_transparent(self, tmp_path: Path) -> None:
        path = tmp_path / "sysmon.jsonl.gz"
        with gzip.open(path, "wt") as handle:
            handle.write(json.dumps(_record()) + "\n")
        assert read_sysmon(path).height == 1

    @pytest.mark.parametrize(
        "name",
        ["sysmon.jsonl", "sysmon.json", "host.sysmon.json", "sysmon-01.jsonl.gz"],
    )
    def test_recognised_filenames(self, tmp_path: Path, name: str) -> None:
        if name.endswith(".gz"):
            with gzip.open(tmp_path / name, "wt") as handle:
                handle.write(json.dumps(_record()) + "\n")
        else:
            _write(tmp_path, [_record()], name=name)
        assert load_processes(tmp_path).height == 1

    def test_suricata_output_is_not_read_as_host_telemetry(self, tmp_path: Path) -> None:
        """`eve.json` belongs to Suricata and the patterns must not claim it.

        A directory holding both is the normal case for an estate with a
        sensor and an endpoint agent.
        """
        (tmp_path / "eve.json").write_text(
            json.dumps({"event_type": "alert", "src_ip": "10.0.0.1"}) + "\n"
        )
        assert load_processes(tmp_path).is_empty()

    def test_a_missing_directory_is_empty_rather_than_an_error(self, tmp_path: Path) -> None:
        assert load_processes(tmp_path / "absent").is_empty()

    def test_an_unreadable_file_is_empty_rather_than_an_error(self, tmp_path: Path) -> None:
        assert read_sysmon(tmp_path / "absent.jsonl").is_empty()

    def test_a_file_of_other_json_is_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "sysmon.jsonl"
        path.write_text('{"hello": "world"}\n')
        assert read_sysmon(path).is_empty()

    def test_source_lines_point_at_real_file_lines(self, tmp_path: Path) -> None:
        """An Artifact locator that is an index into a filtered subset is a lie.

        The header and the discarded events shift every line number, and an
        analyst following `line:3` to line 3 of the file must find the record
        the finding was about.
        """
        path = tmp_path / "sysmon.jsonl"
        path.write_text(
            "# header\n"
            + json.dumps(_record(EventID=3))
            + "\n"
            + json.dumps(_record(ProcessGuid="{aaaa-9}"))
            + "\n"
        )
        frame = read_sysmon(path)
        assert frame["source_line"].to_list() == [3]
