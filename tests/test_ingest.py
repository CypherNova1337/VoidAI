"""Parser tests.

Zeek's TSV dialect has enough quirks — comment headers, `-` as null, dotted
field names, optional gzip — that a round-trip test through a real file is
worth more than any number of hand-built DataFrames.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import polars as pl
import pytest

from voidai.ingest import CONNECTION_SCHEMA, conform, empty
from voidai.ingest.zeek import discover, load_connections, read_conn_log, read_dns_log

TSV_CONN = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring
1750000000.100000\tCabc1\t10.0.0.5\t51234\t93.184.216.34\t443\ttcp\tssl\t0.412\t517\t4096\tSF
1750000060.200000\tCabc2\t10.0.0.5\t51235\t93.184.216.34\t443\ttcp\tssl\t0.388\t512\t3980\tSF
1750000120.300000\tCabc3\t10.0.0.5\t51236\t93.184.216.34\t443\ttcp\t-\t-\t-\t-\tS0
"""

JSON_CONN = (
    '{"ts":1750000000.1,"uid":"Cabc1","id.orig_h":"10.0.0.5","id.orig_p":51234,'
    '"id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp","service":"ssl",'
    '"duration":0.412,"orig_bytes":517,"resp_bytes":4096,"conn_state":"SF"}\n'
    '{"ts":1750000060.2,"uid":"Cabc2","id.orig_h":"10.0.0.5","id.orig_p":51235,'
    '"id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp","service":"ssl",'
    '"duration":0.388,"orig_bytes":512,"resp_bytes":3980,"conn_state":"SF"}\n'
)


class TestReadConnLog:
    def test_parses_tsv(self, tmp_path: Path) -> None:
        path = tmp_path / "conn.log"
        path.write_text(TSV_CONN)
        frame = read_conn_log(path)

        assert frame.height == 3
        assert frame["src_ip"].to_list() == ["10.0.0.5"] * 3
        assert frame["dst_port"].to_list() == [443, 443, 443]
        assert frame["orig_bytes"].to_list() == [517, 512, None]

    def test_parses_json(self, tmp_path: Path) -> None:
        path = tmp_path / "conn.log"
        path.write_text(JSON_CONN)
        frame = read_conn_log(path)

        assert frame.height == 2
        assert frame["dst_ip"].to_list() == ["93.184.216.34"] * 2

    def test_tsv_and_json_agree(self, tmp_path: Path) -> None:
        """The same records in either dialect must normalise identically."""
        tsv = read_conn_log_from(tmp_path / "a.log", TSV_CONN).head(2)
        js = read_conn_log_from(tmp_path / "b.log", JSON_CONN)
        columns = ["ts", "src_ip", "dst_ip", "dst_port", "orig_bytes"]
        assert tsv.select(columns).to_dicts() == js.select(columns).to_dicts()

    def test_unset_field_becomes_null(self, tmp_path: Path) -> None:
        frame = read_conn_log_from(tmp_path / "conn.log", TSV_CONN)
        assert frame["service"].to_list()[2] is None

    def test_line_numbers_point_at_the_real_file_line(self, tmp_path: Path) -> None:
        """An artifact locator is worthless if it is off by the header length."""
        frame = read_conn_log_from(tmp_path / "conn.log", TSV_CONN)
        # Seven header lines precede the first record.
        assert frame["source_line"].to_list() == [8, 9, 10]

    def test_records_its_source_file(self, tmp_path: Path) -> None:
        path = tmp_path / "conn.log"
        frame = read_conn_log_from(path, TSV_CONN)
        assert frame["source_file"].to_list() == [str(path)] * 3

    def test_reads_gzip(self, tmp_path: Path) -> None:
        path = tmp_path / "conn.log.gz"
        with gzip.open(path, "wt") as fh:
            fh.write(TSV_CONN)
        assert read_conn_log(path).height == 3

    def test_empty_file_yields_conformant_empty_frame(self, tmp_path: Path) -> None:
        path = tmp_path / "conn.log"
        path.write_text("")
        frame = read_conn_log(path)
        assert frame.height == 0
        assert set(frame.columns) == set(CONNECTION_SCHEMA)

    def test_header_only_file(self, tmp_path: Path) -> None:
        path = tmp_path / "conn.log"
        path.write_text("\n".join(TSV_CONN.splitlines()[:7]) + "\n")
        assert read_conn_log(path).height == 0

    def test_missing_columns_are_filled_with_nulls(self, tmp_path: Path) -> None:
        """A sensor that omits a field must degrade, not crash."""
        minimal = (
            "#fields\tts\tid.orig_h\tid.resp_h\n"
            "1750000000.0\t10.0.0.5\t93.184.216.34\n"
        )
        frame = read_conn_log_from(tmp_path / "conn.log", minimal)
        assert frame.height == 1
        assert frame["orig_bytes"].to_list() == [None]
        assert set(frame.columns) == set(CONNECTION_SCHEMA)


class TestReadDnsLog:
    def test_parses_and_joins_answers(self, tmp_path: Path) -> None:
        content = (
            '{"ts":1750000000.0,"uid":"C1","id.orig_h":"10.0.0.5","id.resp_h":"8.8.8.8",'
            '"query":"example.com","qtype":"A","rcode":"NOERROR",'
            '"answers":["93.184.216.34","93.184.216.35"]}\n'
        )
        path = tmp_path / "dns.log"
        path.write_text(content)
        frame = read_dns_log(path)
        assert frame["query"].to_list() == ["example.com"]
        assert frame["answers"].to_list() == ["93.184.216.34;93.184.216.35"]


class TestDiscovery:
    def test_groups_logs_by_type(self, tmp_path: Path) -> None:
        for name in ("conn.log", "dns.log", "conn.14:00:00-15:00:00.log.gz"):
            (tmp_path / name).write_text("")
        groups = discover(tmp_path)
        assert len(groups["conn"]) == 2
        assert len(groups["dns"]) == 1

    def test_ignores_non_logs(self, tmp_path: Path) -> None:
        (tmp_path / "notes.txt").write_text("")
        assert discover(tmp_path) == {}

    def test_missing_directory_is_not_an_error(self, tmp_path: Path) -> None:
        assert discover(tmp_path / "absent") == {}

    def test_load_connections_concatenates_and_sorts(self, tmp_path: Path) -> None:
        (tmp_path / "conn.log").write_text(TSV_CONN)
        (tmp_path / "conn.2.log").write_text(TSV_CONN)
        frame = load_connections(tmp_path)
        assert frame.height == 6
        assert frame["ts"].to_list() == sorted(frame["ts"].to_list())

    def test_load_connections_on_empty_directory(self, tmp_path: Path) -> None:
        frame = load_connections(tmp_path)
        assert frame.height == 0
        assert set(frame.columns) == set(CONNECTION_SCHEMA)


class TestConform:
    def test_adds_absent_columns(self) -> None:
        frame = conform(pl.DataFrame({"ts": [1.0]}), CONNECTION_SCHEMA)
        assert set(frame.columns) == set(CONNECTION_SCHEMA)
        assert frame["src_ip"].to_list() == [None]

    def test_drops_unknown_columns(self) -> None:
        frame = conform(pl.DataFrame({"ts": [1.0], "vendor_junk": ["x"]}), CONNECTION_SCHEMA)
        assert "vendor_junk" not in frame.columns

    def test_casts_types(self) -> None:
        frame = conform(pl.DataFrame({"dst_port": ["443"]}), CONNECTION_SCHEMA)
        assert frame["dst_port"].dtype == pl.Int32
        assert frame["dst_port"].to_list() == [443]

    def test_uncastable_values_become_null_rather_than_raising(self) -> None:
        frame = conform(pl.DataFrame({"dst_port": ["not-a-port"]}), CONNECTION_SCHEMA)
        assert frame["dst_port"].to_list() == [None]

    def test_empty_helper_matches_schema(self) -> None:
        frame = empty(CONNECTION_SCHEMA)
        assert frame.height == 0
        assert set(frame.columns) == set(CONNECTION_SCHEMA)


def read_conn_log_from(path: Path, content: str) -> pl.DataFrame:
    path.write_text(content)
    return read_conn_log(path)


@pytest.fixture(autouse=True)
def _quiet_polars() -> None:
    pl.Config.set_tbl_hide_dataframe_shape(True)
