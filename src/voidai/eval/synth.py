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
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        frame = self.connections.sort("ts")
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

    # --- traffic profiles -------------------------------------------------

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

    # --- corpus assembly --------------------------------------------------

    def generate(
        self,
        hours: float = 24.0,
        benign_hosts: int = 12,
        start_epoch: float = 1_750_000_000.0,
    ) -> Corpus:
        duration = hours * 3600
        rows: list[dict[str, object]] = []
        benign_pairs: set[tuple[str, str, int]] = set()

        # --- benign: human browsing --------------------------------------
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

        # --- benign: monitoring agent (periodic, variable payload) --------
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "10.0.0.50"
            timestamps = self._periodic(duration, period=60.0, jitter=0.05)
            # Regular schedule, but the payload carries live metrics and varies
            # widely. This is the classic beaconing false positive.
            sizes = self.rng.lognormal(7.0, 0.9, size=timestamps.size)
            rows += self._rows(timestamps, src, dst, 9100, sizes, "http", start_epoch)
            benign_pairs.add((src, dst, 9100))

        # --- benign: software update check (periodic, uniform, sparse) ----
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "151.101.1.55"
            timestamps = self._periodic(duration, period=3600.0, jitter=0.35)
            sizes = self.rng.normal(820, 120, size=timestamps.size)
            rows += self._rows(timestamps, src, dst, 443, sizes, "ssl", start_epoch)
            benign_pairs.add((src, dst, 443))

        # --- benign: NTP (regular, uniform — suppressed by port) ----------
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "216.239.35.0"
            timestamps = self._periodic(duration, period=64.0, jitter=0.02)
            sizes = np.full(timestamps.size, 76.0)
            rows += self._rows(timestamps, src, dst, 123, sizes, "ntp", start_epoch)
            benign_pairs.add((src, dst, 123))

        # --- malicious: implants -----------------------------------------
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


# --- DNS corpora -----------------------------------------------------------

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

        # --- benign: ordinary lookups, low cardinality, natural names -----
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                f"{self.rng.choice(_WORDS)}.{self.rng.choice(['example', 'acme', 'globex'])}.com"
                for _ in range(int(self.rng.integers(80, 200)))
            ]
            rows += self._rows(src, names, "A", start_epoch, 11.0)
            benign.add((src, "example.com"))

        # --- benign: a CDN — very high cardinality, structured names ------
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                f"e{self.rng.integers(1000, 99999)}-{self.rng.integers(1, 40)}"
                f".dscx.akamaiedge.net"
                for _ in range(300)
            ]
            rows += self._rows(src, names, "A", start_epoch, 7.0)
            benign.add((src, "akamaiedge.net"))

        # --- benign: reputation lookups — encoded, but hex, not base32 ----
        # The hardest benign case: high cardinality, long names, structured
        # payload in the subdomain. Only entropy separates it from a tunnel.
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [f"{self._hexed(32)}.avqs.reputation-example.net" for _ in range(250)]
            rows += self._rows(src, names, "A", start_epoch, 9.0)
            benign.add((src, "reputation-example.net"))

        # --- benign: DNSBL — reversed addresses, numeric, long ------------
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                ".".join(str(self.rng.integers(1, 254)) for _ in range(4)) + ".zen.blocklist-example.org"
                for _ in range(200)
            ]
            rows += self._rows(src, names, "A", start_epoch, 13.0)
            benign.add((src, "blocklist-example.org"))

        # --- malicious: tunnels -------------------------------------------
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
