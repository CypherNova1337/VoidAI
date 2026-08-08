"""PassiveDNS parser tests, and the DNS analyzer's behaviour on real traffic.

`tests/data/real.passivedns` is a genuine excerpt from a Stratosphere malware
capture: Akamai chains, Mozilla update services, Google notifications,
OneNote CDN endpoints. It is here because the false-positive half of DNS
tunnelling detection is the half a generator cannot honestly test — real DNS
is stranger than anything worth writing by hand, and staying quiet across it
is the property that decides whether the analyzer is usable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voidai.analyzers import AnalysisContext, DnsTunnelAnalyzer
from voidai.ingest import load_passivedns, read_passivedns
from voidai.ingest.schema import DNS_SCHEMA

FIXTURE = Path(__file__).parent / "data" / "real.passivedns"

SAMPLE = """\
[*] PassiveDNS 1.2.0
[*] By Edward Bjarte Fjellskaal

13.721865||10.0.0.5||10.0.0.1||IN||dns.msftncsi.com.||A||131.107.255.255||30||1
637.117691||10.0.0.5||10.0.0.1||IN||www.download.windowsupdate.com.||CNAME||cdx.cedexis.net.||3600||1
900.000000||10.0.0.6||10.0.0.1||IN||example.org.||AAAA||2606:2800:220::1||300||1
malformed line without delimiters
"""


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "capture.passivedns"
    path.write_text(SAMPLE)
    return path


class TestParsing:
    def test_reads_records_and_skips_the_banner(self, sample: Path) -> None:
        frame = read_passivedns(sample)
        assert frame.height == 3  # banner and malformed line dropped

    def test_conforms_to_the_dns_schema(self, sample: Path) -> None:
        assert set(read_passivedns(sample).columns) == set(DNS_SCHEMA)

    def test_strips_the_trailing_dot_from_names(self, sample: Path) -> None:
        queries = read_passivedns(sample)["query"].to_list()
        assert "dns.msftncsi.com" in queries
        assert not any(q.endswith(".") for q in queries)

    def test_splits_on_the_double_pipe(self, sample: Path) -> None:
        row = read_passivedns(sample).sort("ts").row(0, named=True)
        assert row["src_ip"] == "10.0.0.5"
        assert row["dst_ip"] == "10.0.0.1"
        assert row["qtype"] == "A"

    def test_timestamps_are_capture_relative(self, sample: Path) -> None:
        """passivedns writes an offset from capture start, not an epoch."""
        plain = read_passivedns(sample).sort("ts")
        offset = read_passivedns(sample, capture_start=1_700_000_000.0).sort("ts")
        assert plain["ts"][0] == pytest.approx(13.721865)
        assert offset["ts"][0] == pytest.approx(1_700_000_013.721865)

    def test_records_source_line_numbers(self, sample: Path) -> None:
        """Line numbers must index the real file, banner included."""
        assert read_passivedns(sample).sort("ts")["source_line"][0] == 4

    def test_missing_file(self, tmp_path: Path) -> None:
        assert read_passivedns(tmp_path / "absent.passivedns").height == 0

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.passivedns"
        path.write_text("[*] PassiveDNS 1.2.0\n")
        assert read_passivedns(path).height == 0

    def test_load_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.passivedns").write_text(SAMPLE)
        (tmp_path / "b.passivedns").write_text(SAMPLE)
        frame = load_passivedns(tmp_path)
        assert frame.height == 6
        assert frame["ts"].to_list() == sorted(frame["ts"].to_list())

    def test_load_missing_directory(self, tmp_path: Path) -> None:
        assert load_passivedns(tmp_path / "absent").height == 0


@pytest.fixture(scope="module")
def real():  # type: ignore[no-untyped-def]
    return read_passivedns(FIXTURE)


class TestAgainstRealTraffic:
    def test_fixture_parses(self, real) -> None:  # type: ignore[no-untyped-def]
        assert real.height >= 300
        assert real["query"].n_unique() >= 100

    def test_no_false_positives_on_real_dns(self, real) -> None:  # type: ignore[no-untyped-def]
        """The property that decides whether this analyzer is deployable.

        Real DNS is full of tunnel-shaped traffic that is nothing of the sort:
        CDN chains with high-cardinality machine-generated subdomains,
        certificate status responders, telemetry endpoints. Measured across
        3,655 records from 18 hosts in the full captures, the analyzer emits
        nothing; this fixture pins the same result.
        """
        assert DnsTunnelAnalyzer().analyze(AnalysisContext(dns=real)) == []

    def test_real_traffic_contains_cdn_subdomains(self, real) -> None:  # type: ignore[no-untyped-def]
        """Guards the test above from becoming vacuous.

        If the fixture were ever reduced to a handful of plain lookups, the
        false-positive test would pass for the wrong reason.
        """
        queries = real["query"].to_list()
        assert any("akamai" in q for q in queries)
        assert max(len(q) for q in queries) > 30
