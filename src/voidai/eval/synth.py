"""Synthetic telemetry with ground truth.

Public labelled beaconing corpora barely exist, and the ones that do are
small, stale, and mostly unencrypted. So VoidAI generates its own: a
reproducible network of benign traffic with implants planted in known places,
seeded so that any reviewer can regenerate the exact corpus a benchmark ran on.

The generator is deliberately adversarial toward VoidAI. Benign traffic
includes the categories that produce false positives in every published
beaconing detector:

  * monitoring agents polling on a fixed schedule with variable payloads
  * software update checks — periodic, low-volume, long-lived
  * chatty API clients whose arrivals are regular but bursty

and the implants include a low-and-slow profile with 50% jitter that any
naive MAD threshold will miss. A detector that scores well here has earned it.

Synthetic data proves the mathematics, not the product. It is a floor under
the benchmark, and `docs/benchmarks.md` reports real-capture results
alongside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import polars as pl

from voidai.ingest.schema import CONNECTION_SCHEMA, DNS_SCHEMA, conform

_ZEEK_CONN_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
]


@dataclass(frozen=True)
class Implant:
    """A planted beacon, and the label a detector is scored against."""

    src_ip: str
    dst_ip: str
    dst_port: int
    period_seconds: float
    jitter_fraction: float
    payload_bytes: int
    label: str
    #: "symmetric" for uniform jitter either side of the period; "scheduled"
    #: for the hard-floor, right-tailed shape real captures exhibit.
    jitter_model: str = "symmetric"

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.src_ip, self.dst_ip, self.dst_port)


@dataclass
class Corpus:
    """Generated telemetry plus the ground truth needed to score against it."""

    connections: pl.DataFrame
    implants: list[Implant]
    benign_pairs: set[tuple[str, str, int]] = field(default_factory=set)

    @property
    def implant_keys(self) -> set[tuple[str, str, int]]:
        return {i.key for i in self.implants}

    def write_zeek_conn_log(self, path: str | Path) -> Path:
        """Serialise to Zeek TSV so the real parser is exercised end to end.

        Tests that build a DataFrame directly would never catch a parser
        regression, so the benchmark writes a genuine log and reads it back.
        """
        return write_zeek_conn_log(self.connections, path)


def write_zeek_conn_log(connections: pl.DataFrame, path: str | Path) -> Path:
    """Write a connection frame as a Zeek `conn.log`.

    A free function because more than one corpus needs it and none of them
    should own it. Every generated corpus goes to disk in the sensor's real
    format and comes back through the production parser, so a benchmark
    cannot pass over data the parser could not have produced.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    frame = connections.sort("ts")
    header = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#fields\t" + "\t".join(_ZEEK_CONN_FIELDS),
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring",
    ]

    rows = []
    for r in frame.iter_rows(named=True):
        rows.append(
            "\t".join(
                [
                    f"{r['ts']:.6f}",
                    r["uid"] or "-",
                    r["src_ip"],
                    str(r["src_port"]),
                    r["dst_ip"],
                    str(r["dst_port"]),
                    r["proto"] or "tcp",
                    r["service"] or "-",
                    f"{r['duration']:.6f}" if r["duration"] is not None else "-",
                    str(r["orig_bytes"]) if r["orig_bytes"] is not None else "-",
                    str(r["resp_bytes"]) if r["resp_bytes"] is not None else "-",
                    r["conn_state"] or "SF",
                ]
            )
        )

    path.write_text("\n".join(header + rows) + "\n")
    return path


class CorpusGenerator:
    """Builds a labelled network capture from a seed."""

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)
        self._uid = 0

    def _next_uid(self) -> str:
        self._uid += 1
        return f"C{self._uid:08x}"

    def _browsing(self, duration: float, sessions: int) -> np.ndarray:
        """Bursty human browsing: idle gaps punctuated by clusters of requests."""
        starts = self.rng.uniform(0, duration, size=sessions)
        timestamps: list[np.ndarray] = []
        for start in starts:
            count = int(self.rng.integers(4, 40))
            # Within a session, arrivals are exponential with a short mean.
            offsets = np.cumsum(self.rng.exponential(2.5, size=count))
            timestamps.append(start + offsets)
        if not timestamps:
            return np.array([])
        return np.sort(np.concatenate(timestamps))

    def _scheduled(
        self,
        duration: float,
        period: float,
        jitter: float,
        miss_rate: float = 0.03,
    ) -> np.ndarray:
        """Arrivals from a real implant: a hard floor with a right tail.

        Modelled on the CTU-13 Menti channel, whose observed intervals sit at
        q1=33.0s, q2=33.3s, q3=42.4s — an extremely tight lower edge with a
        long tail running out to five times the base period.

        The shape follows from how implants actually work. A beacon told to
        sleep thirty seconds cannot wake in twenty; scheduler slack, network
        latency and a dropped check-in only ever push the next arrival later.
        The symmetric `uniform(+/-jitter)` model in `_periodic` cannot produce
        that asymmetry, and a detector validated only against it learns a
        property of the generator rather than a property of malware.
        """
        timestamps: list[float] = []
        t = 0.0
        while t < duration:
            timestamps.append(t)
            t += period * (1.0 + abs(self.rng.normal(0.0, jitter)))
            if self.rng.random() < miss_rate:
                t += period  # a missed check-in doubles the gap
        return np.array(timestamps)

    def _periodic(self, duration: float, period: float, jitter: float) -> np.ndarray:
        """Regular arrivals with symmetric uniform jitter.

        Kept alongside `_scheduled` deliberately: some implant families do
        jitter symmetrically, and the detector has to handle both shapes.
        """
        count = max(int(duration / period), 1)
        base = np.arange(count) * period
        if jitter > 0:
            base = base + self.rng.uniform(-jitter * period, jitter * period, size=count)
        base = base[(base >= 0) & (base < duration)]
        return np.sort(base)

    def _rows(
        self,
        timestamps: np.ndarray,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        sizes: np.ndarray,
        service: str,
        start_epoch: float,
    ) -> list[dict[str, object]]:
        rows = []
        for ts, size in zip(timestamps, sizes, strict=True):
            rows.append(
                {
                    "ts": start_epoch + float(ts),
                    "uid": self._next_uid(),
                    "src_ip": src_ip,
                    "src_port": int(self.rng.integers(32768, 60999)),
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": "tcp",
                    "service": service,
                    "duration": float(abs(self.rng.normal(0.4, 0.2))),
                    "orig_bytes": int(max(size, 0)),
                    "resp_bytes": int(max(size * self.rng.uniform(1.5, 8.0), 0)),
                    "orig_pkts": int(max(size // 500 + 2, 2)),
                    "resp_pkts": int(max(size // 300 + 2, 2)),
                    "conn_state": "SF",
                    "source_file": "<synthetic>",
                    "source_line": 0,
                }
            )
        return rows

    def generate(
        self,
        hours: float = 24.0,
        benign_hosts: int = 12,
        start_epoch: float = 1_750_000_000.0,
    ) -> Corpus:
        duration = hours * 3600
        rows: list[dict[str, object]] = []
        benign_pairs: set[tuple[str, str, int]] = set()

        # Benign: human browsing
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            for site_index in range(int(self.rng.integers(3, 8))):
                dst = f"93.184.{site_index}.{self.rng.integers(1, 250)}"
                timestamps = self._browsing(duration, sessions=int(self.rng.integers(6, 25)))
                if timestamps.size == 0:
                    continue
                # Heavy-tailed request sizes — the opposite of a beacon.
                sizes = self.rng.lognormal(6.2, 1.4, size=timestamps.size)
                rows += self._rows(timestamps, src, dst, 443, sizes, "ssl", start_epoch)
                benign_pairs.add((src, dst, 443))

        # Benign: monitoring agent (periodic, variable payload)
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "10.0.0.50"
            timestamps = self._periodic(duration, period=60.0, jitter=0.05)
            # Regular schedule, but the payload carries live metrics and varies
            # widely. This is the classic beaconing false positive.
            sizes = self.rng.lognormal(7.0, 0.9, size=timestamps.size)
            rows += self._rows(timestamps, src, dst, 9100, sizes, "http", start_epoch)
            benign_pairs.add((src, dst, 9100))

        # Benign: software update check (periodic, uniform, sparse)
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "151.101.1.55"
            timestamps = self._periodic(duration, period=3600.0, jitter=0.35)
            sizes = self.rng.normal(820, 120, size=timestamps.size)
            rows += self._rows(timestamps, src, dst, 443, sizes, "ssl", start_epoch)
            benign_pairs.add((src, dst, 443))

        # Benign: NTP (regular, uniform — suppressed by port)
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "216.239.35.0"
            timestamps = self._periodic(duration, period=64.0, jitter=0.02)
            sizes = np.full(timestamps.size, 76.0)
            rows += self._rows(timestamps, src, dst, 123, sizes, "ntp", start_epoch)
            benign_pairs.add((src, dst, 123))

        # Malicious: implants
        implants = [
            Implant("10.0.1.14", "45.83.220.17", 443, 60.0, 0.00, 512, "textbook-60s"),
            Implant("10.0.1.17", "185.220.101.9", 8443, 300.0, 0.10, 1024, "jittered-5m"),
            Implant("10.0.1.11", "141.98.11.4", 443, 900.0, 0.25, 380, "jittered-15m"),
            Implant("10.0.1.19", "194.26.29.87", 80, 1800.0, 0.50, 256, "low-and-slow-30m"),
            Implant(
                "10.0.1.13", "45.129.14.22", 443, 33.0, 0.18, 640,
                "scheduled-33s-menti-like", jitter_model="scheduled",
            ),
            Implant(
                "10.0.1.16", "179.43.160.8", 8080, 600.0, 0.30, 900,
                "scheduled-10m", jitter_model="scheduled",
            ),
        ]
        for implant in implants:
            timestamps = (
                self._scheduled(duration, implant.period_seconds, implant.jitter_fraction)
                if implant.jitter_model == "scheduled"
                else self._periodic(
                    duration, implant.period_seconds, implant.jitter_fraction
                )
            )
            # Check-in payloads vary only slightly: a task poll plus framing.
            sizes = self.rng.normal(implant.payload_bytes, implant.payload_bytes * 0.06, size=timestamps.size)
            rows += self._rows(
                timestamps,
                implant.src_ip,
                implant.dst_ip,
                implant.dst_port,
                sizes,
                "ssl" if implant.dst_port != 80 else "http",
                start_epoch,
            )

        frame = conform(pl.DataFrame(rows), CONNECTION_SCHEMA).sort("ts")
        # Assign line numbers matching the order they will be written out in.
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return Corpus(connections=frame, implants=implants, benign_pairs=benign_pairs)




@dataclass(frozen=True)
class Transfer:
    """A planted exfiltration, and the label a detector is scored against."""

    src_ip: str
    dst_ip: str
    dst_port: int
    total_bytes: int
    flows: int
    #: Fraction of the capture elapsed before the first flow to this
    #: destination. The novelty signal is measured against exactly this.
    starts_at: float
    label: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.src_ip, self.dst_ip)


@dataclass
class EgressCorpus:
    """Generated transfer telemetry plus the ground truth needed to score it."""

    connections: pl.DataFrame
    transfers: list[Transfer]
    #: Benign destinations that are *meant* to be hard, keyed the same way, so
    #: a scoring run can name which decoy it fell for rather than reporting an
    #: anonymous false positive.
    decoys: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def transfer_keys(self) -> set[tuple[str, str]]:
        return {t.key for t in self.transfers}

    def write_zeek_conn_log(self, path: str | Path) -> Path:
        return write_zeek_conn_log(self.connections, path)


class EgressCorpusGenerator:
    """Builds labelled bulk-transfer traffic from a seed.

    Separate from `CorpusGenerator` rather than folded into it. That generator
    and its seed back the published beaconing figures in `docs/benchmarks.md`,
    and quietly adding traffic to it would invalidate results the same
    document calls reproducible. `DnsCorpusGenerator` set the precedent.

    Adversarial by design. The benign traffic here is not filler — it is the
    four categories that break volume detectors, and three of them are
    *indistinguishable from exfiltration* on volume and direction alone:

      * a nightly backup: enormous, almost entirely outbound, on a schedule
      * a cloud sync: large, outbound, and reached by the whole estate
      * a software mirror: large, but inbound, which is the one thing
        exfiltration never is
      * a lone backup target used by exactly one host, which is the case
        estate-wide rarity cannot help with and which is left in deliberately

    A detector that clears the first three has separated *where the bytes went
    and to whom* from *how many there were*, which is the whole difficulty.
    The fourth is here to be reported, not to be passed — see
    `docs/benchmarks.md`.
    """

    #: Reached by every host in the estate, and reached from the first hour.
    _BACKUP = "10.0.2.60"
    _CLOUD_SYNC = "52.216.10.5"
    _MIRROR = "151.101.1.55"
    _MAIL = "10.0.2.25"
    #: Reached by one host only. Rarity says "unique", novelty says "always
    #: been there", and only the second is right.
    _LONE_BACKUP = "10.0.2.61"

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)
        self._uid = 0

    def _next_uid(self) -> str:
        self._uid += 1
        return f"E{self._uid:08x}"

    def _flows(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamps: np.ndarray,
        orig_bytes: np.ndarray,
        resp_bytes: np.ndarray,
        service: str,
        start_epoch: float,
    ) -> list[dict[str, object]]:
        return [
            {
                "ts": start_epoch + float(ts),
                "uid": self._next_uid(),
                "src_ip": src_ip,
                "src_port": int(self.rng.integers(32768, 60999)),
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": "tcp",
                "service": service,
                "duration": float(abs(self.rng.normal(2.0, 0.8))),
                "orig_bytes": int(max(out, 0)),
                "resp_bytes": int(max(back, 0)),
                "orig_pkts": int(max(out // 1400 + 2, 2)),
                "resp_pkts": int(max(back // 1400 + 2, 2)),
                "conn_state": "SF",
                "source_file": "<synthetic>",
                "source_line": 0,
            }
            for ts, out, back in zip(timestamps, orig_bytes, resp_bytes, strict=True)
        ]

    def _spread(self, duration: float, count: int, start: float = 0.0) -> np.ndarray:
        """`count` arrivals scattered over the window from `start` onward."""
        span = max(duration * (1.0 - start), 1.0)
        return np.sort(duration * start + self.rng.uniform(0.0, span, size=count))

    def _regular(self, duration: float, count: int, start: float) -> np.ndarray:
        """`count` arrivals on a fixed cadence, the first at `start` exactly.

        Backups, syncs and mirror pulls run on a timer, and where the first
        one lands is not a coin toss. It matters because it is precisely what
        the novelty signal measures: a scheduled job is already running when
        the sensor starts recording, and scattering its first arrival
        somewhere random inside the window would hand the detector a
        different — and easier — problem on every seed.
        """
        first = duration * start
        return np.linspace(first, duration, num=count, endpoint=False)

    def generate(
        self,
        hours: float = 24.0,
        benign_hosts: int = 12,
        start_epoch: float = 1_760_000_000.0,
    ) -> EgressCorpus:
        duration = hours * 3600
        rows: list[dict[str, object]] = []
        decoys: dict[tuple[str, str], str] = {}
        hosts = [f"10.0.2.{index + 10}" for index in range(benign_hosts)]

        for host in hosts:
            # Browsing: many small conversations, and inbound-heavy, because
            # a page is pulled. Six of them, so every host has a baseline
            # wide enough for a robust deviation to mean something.
            for site in range(6):
                dst = f"93.184.{site}.{self.rng.integers(1, 250)}"
                count = int(self.rng.integers(60, 200))
                timestamps = self._spread(duration, count)
                out = self.rng.lognormal(6.6, 0.8, size=count)
                rows += self._flows(
                    host, dst, 443, timestamps, out, out * self.rng.uniform(6.0, 30.0, size=count),
                    "ssl", start_epoch,
                )

            # Nightly backup: the hardest benign case on volume and direction.
            timestamps = self._regular(duration, 24, start=0.02)
            out = self.rng.normal(90_000_000, 6_000_000, size=24)
            rows += self._flows(
                host, self._BACKUP, 22, timestamps, out, out * 0.002, "ssh", start_epoch
            )
            decoys[(host, self._BACKUP)] = "nightly-backup"

            # Cloud sync: outbound, large, and reached by the whole estate.
            timestamps = self._regular(duration, 140, start=0.015)
            out = self.rng.lognormal(14.4, 0.7, size=140)
            rows += self._flows(
                host, self._CLOUD_SYNC, 443, timestamps, out, out * 0.01, "ssl", start_epoch
            )
            decoys[(host, self._CLOUD_SYNC)] = "cloud-sync"

            # Software mirror: just as much volume, travelling the other way.
            timestamps = self._regular(duration, 20, start=0.03)
            back = self.rng.normal(120_000_000, 20_000_000, size=20)
            rows += self._flows(
                host, self._MIRROR, 443, timestamps, back * 0.002, back, "ssl", start_epoch
            )
            decoys[(host, self._MIRROR)] = "software-mirror"

            # Mail: modest, outbound, unremarkable.
            timestamps = self._spread(duration, 90)
            out = self.rng.lognormal(11.0, 0.9, size=90)
            rows += self._flows(
                host, self._MAIL, 25, timestamps, out, out * 0.01, "smtp", start_epoch
            )

        # One host keeps its own backup target. Nothing else in the estate
        # touches it, so estate-wide rarity scores it 1.0 — the one benign
        # shape rarity cannot defend against.
        lone = hosts[3]
        timestamps = self._regular(duration, 24, start=0.02)
        out = self.rng.normal(70_000_000, 5_000_000, size=24)
        rows += self._flows(
            lone, self._LONE_BACKUP, 22, timestamps, out, out * 0.002, "ssh", start_epoch
        )
        decoys[(lone, self._LONE_BACKUP)] = "lone-host-backup"

        # Planted exfiltration. Each is on a host that also browses, backs up
        # and syncs, so its baseline and its observation window are those of
        # an ordinary machine rather than of a machine that only exfiltrates.
        transfers = [
            Transfer(hosts[0], "45.83.220.17", 443, 800_000_000, 3, 0.70, "bulk-single-archive"),
            Transfer(hosts[5], "185.220.101.9", 8443, 600_000_000, 120, 0.40, "staged-chunked"),
            Transfer(hosts[9], "141.98.11.4", 443, 12_000_000, 40, 0.55, "slow-and-small"),
            # Below the byte floor for a volume claim, so the strongest thing
            # sayable about it is that something went somewhere rare. It is
            # here to exercise that band, and to prove the band is reachable
            # by something other than noise.
            Transfer(hosts[2], "179.43.160.8", 443, 600_000, 25, 0.62, "trickle-upload"),
        ]
        for transfer in transfers:
            timestamps = self._spread(duration, transfer.flows, start=transfer.starts_at)
            share = self.rng.dirichlet(np.full(transfer.flows, 6.0))
            out = share * transfer.total_bytes
            rows += self._flows(
                transfer.src_ip,
                transfer.dst_ip,
                transfer.dst_port,
                timestamps,
                out,
                out * self.rng.uniform(0.004, 0.02, size=transfer.flows),
                "ssl",
                start_epoch,
            )

        frame = conform(pl.DataFrame(rows), CONNECTION_SCHEMA).sort("ts")
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return EgressCorpus(connections=frame, transfers=transfers, decoys=decoys)


_BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
_WORDS = ["www", "api", "cdn", "static", "assets", "mail", "smtp", "imap", "login", "auth", "account", "portal", "shop", "news", "blog", "media", "images", "video", "docs", "help", "support", "status", "admin", "dev", "stage", "prod", "eu", "us", "asia", "edge", "node", "cluster", "db", "cache", "queue", "search", "maps", "drive"]


@dataclass(frozen=True)
class DnsTunnel:
    """A planted DNS tunnel, and the label a detector is scored against."""

    src_ip: str
    zone: str
    label: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.src_ip, self.zone)


@dataclass
class DnsCorpus:
    """Generated DNS telemetry plus its ground truth."""

    queries: pl.DataFrame
    tunnels: list[DnsTunnel]
    benign_zones: set[tuple[str, str]] = field(default_factory=set)

    @property
    def tunnel_keys(self) -> set[tuple[str, str]]:
        return {t.key for t in self.tunnels}


class DnsCorpusGenerator:
    """Builds labelled DNS traffic from a seed.

    Adversarial by design. The benign traffic includes the two categories that
    break naive entropy detectors:

      * content delivery networks, which mint thousands of subdomains
      * reputation and blocklist lookups, which encode hashes and reversed
        addresses into subdomains and are tunnel-shaped by every measure
        except entropy

    A detector that clears this corpus has separated encoding from mere
    cardinality, which is the whole difficulty.
    """

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)

    def _encoded(self, length: int) -> str:
        return "".join(self.rng.choice(list(_BASE32), size=length))

    def _hexed(self, length: int) -> str:
        return "".join(self.rng.choice(list("0123456789abcdef"), size=length))

    def _rows(
        self,
        src_ip: str,
        names: list[str],
        qtype: str,
        start_epoch: float,
        interval: float,
    ) -> list[dict[str, object]]:
        return [
            {
                "ts": start_epoch + index * interval,
                "uid": f"D{index:08x}",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.53",
                "query": name,
                "qtype": qtype,
                "rcode": "NOERROR",
                "answers": "",
                "source_file": "<synthetic>",
                "source_line": index + 1,
            }
            for index, name in enumerate(names)
        ]

    def generate(
        self,
        hours: float = 6.0,
        benign_hosts: int = 10,
        start_epoch: float = 1_750_000_000.0,
    ) -> DnsCorpus:
        rows: list[dict[str, object]] = []
        benign: set[tuple[str, str]] = set()

        # Benign: ordinary lookups, low cardinality, natural names
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                f"{self.rng.choice(_WORDS)}.{self.rng.choice(['example', 'acme', 'globex'])}.com"
                for _ in range(int(self.rng.integers(80, 200)))
            ]
            rows += self._rows(src, names, "A", start_epoch, 11.0)
            benign.add((src, "example.com"))

        # Benign: a CDN — very high cardinality, structured names
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                f"e{self.rng.integers(1000, 99999)}-{self.rng.integers(1, 40)}"
                f".dscx.akamaiedge.net"
                for _ in range(300)
            ]
            rows += self._rows(src, names, "A", start_epoch, 7.0)
            benign.add((src, "akamaiedge.net"))

        # Benign: reputation lookups — encoded, but hex, not base32
        # The hardest benign case: high cardinality, long names, structured
        # payload in the subdomain. Only entropy separates it from a tunnel.
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [f"{self._hexed(32)}.avqs.reputation-example.net" for _ in range(250)]
            rows += self._rows(src, names, "A", start_epoch, 9.0)
            benign.add((src, "reputation-example.net"))

        # Benign: DNSBL — reversed addresses, numeric, long
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                ".".join(str(self.rng.integers(1, 254)) for _ in range(4)) + ".zen.blocklist-example.org"
                for _ in range(200)
            ]
            rows += self._rows(src, names, "A", start_epoch, 13.0)
            benign.add((src, "blocklist-example.org"))

        # Malicious: tunnels
        tunnels = [
            DnsTunnel("10.0.1.21", "tunnel-example.com", "iodine-like-long-txt"),
            DnsTunnel("10.0.1.22", "c2-example.net", "dnscat2-like-a-records"),
            DnsTunnel("10.0.1.23", "exfil-example.org", "chunked-multi-label"),
        ]

        # iodine: long single label, TXT for return capacity
        rows += self._rows(
            tunnels[0].src_ip,
            [f"{self._encoded(58)}.{tunnels[0].zone}" for _ in range(600)],
            "TXT",
            start_epoch,
            3.0,
        )
        # dnscat2 in A-record mode: no qtype tell at all
        rows += self._rows(
            tunnels[1].src_ip,
            [f"{self._encoded(40)}.{tunnels[1].zone}" for _ in range(450)],
            "A",
            start_epoch,
            4.0,
        )
        # payload chunked across several labels
        rows += self._rows(
            tunnels[2].src_ip,
            [
                f"{self._encoded(20)}.{self._encoded(20)}.{self._encoded(18)}.{tunnels[2].zone}"
                for _ in range(380)
            ],
            "CNAME",
            start_epoch,
            5.0,
        )

        frame = conform(pl.DataFrame(rows), DNS_SCHEMA).sort("ts")
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return DnsCorpus(queries=frame, tunnels=tunnels, benign_zones=benign)



_PATIENT_ZERO = "10.0.1.14"


def write_eve_json(path: str | Path, alerts: list[dict[str, object]]) -> Path:
    """Serialise alert records as Suricata EVE JSON."""
    import json
    from datetime import datetime, timezone

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for alert in sorted(alerts, key=lambda a: a["ts"]):
        stamp = datetime.fromtimestamp(float(alert["ts"]), tz=timezone.utc)
        lines.append(
            json.dumps(
                {
                    "timestamp": stamp.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000",
                    "event_type": "alert",
                    "src_ip": alert["src_ip"],
                    "dest_ip": alert["dst_ip"],
                    "dest_port": alert.get("dst_port", 443),
                    "proto": "TCP",
                    "alert": {
                        "signature_id": alert["signature_id"],
                        "signature": alert["signature"],
                        "category": alert["category"],
                        "severity": alert["severity"],
                    },
                }
            )
        )
    path.write_text("\n".join(lines) + "\n")
    return path


def write_passivedns(path: str | Path, queries: pl.DataFrame) -> Path:
    """Serialise DNS queries in passivedns' pipe-delimited format."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = ["[*] PassiveDNS 1.2.0", "[*] Synthetic capture generated by voidai demo"]
    base = float(queries["ts"].min()) if queries.height else 0.0
    rows = [
        "||".join(
            [
                f"{float(r['ts']) - base:.6f}",
                r["src_ip"],
                r["dst_ip"] or "10.0.0.53",
                "IN",
                f"{r['query']}.",
                r["qtype"] or "A",
                "203.0.113.1",
                "300",
                "1",
            ]
        )
        for r in queries.sort("ts").iter_rows(named=True)
    ]
    path.write_text("\n".join(header + rows) + "\n")
    return path


def build_demo_capture(directory: str | Path, seed: int = 1337) -> Path:
    """Write a complete multi-source capture: connections, DNS, and alerts.

    One host — `10.0.1.14` — exhibits all four behaviours VoidAI can detect,
    hidden in benign traffic of each kind. Nothing about it is flagged in the
    data; it is only distinguishable by measuring it, which is the point of
    the demonstration.

    Written as three real files in the three real formats, so `voidai run`
    exercises the production parsers rather than a shortcut.
    """
    import numpy as np

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)

    # Connections: beaconing and fan-out
    corpus = CorpusGenerator(seed=seed).generate(hours=24.0)
    start = float(corpus.connections["ts"].min())

    # Patient zero also sweeps port 445 across the estate.
    sweep = []
    for index in range(420):
        sweep.append(
            {
                "ts": start + index * 4.0,
                "uid": f"S{index:08x}",
                "src_ip": _PATIENT_ZERO,
                "src_port": int(rng.integers(1024, 5000)),
                "dst_ip": f"10.0.{index // 250}.{index % 250 + 1}",
                "dst_port": 445,
                "proto": "tcp",
                "service": None,
                "duration": 0.05,
                "orig_bytes": 320,
                "resp_bytes": 0,
                "orig_pkts": 2,
                "resp_pkts": 0,
                "conn_state": "S0",
                "source_file": "<synthetic>",
                "source_line": 0,
            }
        )
    connections = pl.concat(
        [corpus.connections, conform(pl.DataFrame(sweep), CONNECTION_SCHEMA)],
        how="vertical",
    ).sort("ts")
    connections = connections.with_columns(
        pl.int_range(1, connections.height + 1, dtype=pl.Int64).alias("source_line")
    )
    Corpus(connections=connections, implants=corpus.implants).write_zeek_conn_log(
        directory / "conn.log"
    )

    # DNS: a tunnel on the same host, among benign lookups
    dns = DnsCorpusGenerator(seed=seed).generate(hours=6.0)
    tunnel = dns.queries.with_columns(
        pl.when(pl.col("src_ip") == dns.tunnels[0].src_ip)
        .then(pl.lit(_PATIENT_ZERO))
        .otherwise(pl.col("src_ip"))
        .alias("src_ip")
    )
    write_passivedns(directory / "capture.passivedns", tunnel)

    # Alerts: estate-wide noise plus two rare severe rules
    alerts: list[dict[str, object]] = []
    noise = [
        (2013028, "ET POLICY curl User-Agent Outbound", "Not Suspicious Traffic", 3),
        (2001569, "ET SCAN Behavioral Unusual Port 445 traffic", "Misc activity", 3),
    ]
    for host in range(55):
        src = f"10.0.1.{host + 10}"
        for sid, signature, category, severity in noise:
            for index in range(int(rng.integers(30, 70))):
                alerts.append(
                    {
                        "ts": start + index * 11,
                        "src_ip": src,
                        "dst_ip": "93.184.216.34",
                        "signature_id": sid,
                        "signature": signature,
                        "category": category,
                        "severity": severity,
                    }
                )
    for sid, signature, category in (
        (2018000, "ET TROJAN Observed Malicious SSL Certificate", "A Network Trojan was detected"),
        (2022000, "ET EXPLOIT Possible CVE-2017-0144 SMB Exploit Attempt",
         "Attempted Administrator Privilege Gain"),
    ):
        for index in range(14):
            alerts.append(
                {
                    "ts": start + index * 420,
                    "src_ip": _PATIENT_ZERO,
                    "dst_ip": "45.83.220.17",
                    "signature_id": sid,
                    "signature": signature,
                    "category": category,
                    "severity": 1,
                }
            )
    write_eve_json(directory / "eve.json", alerts)

    return directory
