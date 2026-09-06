"""TLS fingerprints and algorithmically generated domains.

Two claims about the same stage of an intrusion — how an implant finds its
controller, and what it looks like when it gets there — sharing one analyzer
because they share a shape: **both are measurements of rarity and structure
over telemetry that is frequently not there at all.**

    resolves_algorithmic_domain    a host resolving names a program invented
    presents_rare_tls_fingerprint  a host running a TLS client nothing else runs

## The domain-generation half

A domain generation algorithm exists because a hard-coded C2 address is one
takedown away from being worthless. The implant computes a few hundred names a
day from a seed and tries each; the operator registers one. That leaves a very
particular fingerprint in DNS:

    nxdomain rate           the algorithm generates many names and only the
                            registered one resolves — the signal a DGA cannot
                            avoid without abandoning the technique
    character improbability the names were not chosen by a person, and an
                            English character model says so
    structure               digit runs and consonant runs a brand name would
                            not carry

Names are measured as **registered domains** — `k7jf2plqx.biz`, not
`www.k7jf2plqx.biz` — because the registered domain is the unit the algorithm
mints, the unit an operator buys, and the unit a responder blocks.

### Entropy is not used here, and that is a measurement rather than a taste

The obvious component, and the one the roadmap for this cluster specified, is
the Shannon entropy the DNS tunnelling analyzer already computes. It does not
work at this length. A second-level label is 6 to 20 characters and
per-character entropy is bounded by `log2(len)`, so over short strings it
measures length rather than randomness: real registered labels average 0.855
of their maximum, random alphabetic strings 0.893, and hex strings 0.807 —
four points of separation, pointing the *wrong way* on the hex families.

`analyzers/ngrams.py` replaces it with a bigram model over an embedded English
word list, which separates the same populations by a median of 0.145 against
0.667. The account, and why the word list rather than a hand-written
frequency table, is in that module and in `docs/benchmarks.md` §9.

### A family is a host and a suffix, and it is not pre-filtered

The NXDOMAIN rate has to be measured over a *group* of names: one name that
failed to resolve is not a rate, and the one name in a DGA family that
*succeeds* is the interesting one. The group used here is
`(source, public suffix)` — every registered domain one host resolved under
`.biz`, or under `.com`.

Deliberately, that group is **not** narrowed to the names that already look
algorithmic. Selecting a family by the property being measured would let any
host manufacture a family with a perfect NXDOMAIN rate out of its handful of
typos, and the resulting score would describe the selection rather than the
traffic. The cost is real and is paid knowingly: a DGA operating under `.com`
on a host that also browses the web has its NXDOMAIN rate diluted by that
browsing, so the family-level component is weaker than a benchmark on isolated
DGA traffic would suggest.

The consequence is that the *family* supplies one component and the *label*
supplies the other two. Each finding names one domain, scored from that name's
own shape and from the resolution behaviour of the family it belongs to.

### rcode is often missing, and then the strongest component is gone

`dns.log` carries `rcode`. `passivedns` does not — it reconstructs
question/answer pairs from a capture and records no failure code — and it is
the only source of *real* query names this project has. So on the corpus that
measures this analyzer's specificity, its heaviest signal is unavailable.

Handled the way `egress.py` handles a missing `resp_bytes`: the component is
omitted, the remaining weights renormalise, and the evidence payload carries
`nxdomain_rate: null` rather than a substituted zero. A coverage floor decides
it, not the presence of the column, because a sensor that populated `rcode` on
a tenth of a family's queries has described that tenth.

**The predicate survives, and that is not the same call as in `egress.py`.**
There, the missing `resp_bytes` *was* the word "outbound" in `exfiltrates_to`,
so the verb became unsayable. Here the verb is
`resolves_algorithmic_domain` — the Lexicon defines it as a domain "whose
structure is consistent with algorithmic generation", and structure is exactly
what the character model measures. `rcode` is the strongest evidence for the
claim; it is not the claim. What it does change is the *confidence*, which
falls out of the renormalisation automatically, and the false-positive rate,
which is reported separately for the two telemetry shapes in
`docs/benchmarks.md` §9 rather than averaged into one flattering number.

## The TLS half

A JA3 hash summarises the ClientHello: version, cipher list, extension list,
curves. Two hosts running the same browser build produce the same hash, and a
bespoke implant with its own TLS stack produces one nothing else in the estate
produces.

That is the entire claim, and it is a *prevalence* claim. No geometric mean of
loosely-related quantities is assembled to make it resemble the behavioural
analyzers — the mistake `intel.py` was warned against and avoided. Two things
are measured, and they are the measurement and the confidence in it:

    fingerprint_rarity  estate-wide prevalence, via `destination_rarity()`
    estate_support      how many hosts the estate actually contains

The second exists because rarity needs an estate. On a three-host capture
every fingerprint is rare, and a detector that reports so has told the analyst
about the size of the capture rather than about the traffic. Below a floor the
analyzer says nothing at all.

**A rare fingerprint does not corroborate.** `PRESENTS_RARE_TLS_FINGERPRINT`
is in `CorrelationConfig.non_corroborating`, and the reason is the one
cluster 4 sets out for intel hits rather than the partial-evidence reason of
rule 6: the corroboration multiplier counts independent *behaviours of a
host*, and an implant beaconing over TLS produces a beaconing finding and a
rare-fingerprint finding **about the same connection**. That is one behaviour
measured twice, not two behaviours. The evidence still raises the incident's
combined confidence through the noisy-OR, which is where confirmatory evidence
belongs.

### JA3 is not in ssl.log by default

It is written by a Zeek package, not by the core script. A sensor without it
emits an `ssl.log` with every column except the one that matters, which from
the outside is indistinguishable from having no TLS telemetry at all. The
analyzer degrades to silence, and `voidai doctor --telemetry` reports the
difference so an operator can act on it.

## Validation

Split, and reported separately because the halves rest on different evidence.

**DGA specificity is real** — `tests/data/real.passivedns`, and measured
without the `nxdomain_rate` component, which makes it a conservative figure.
**DGA sensitivity is synthetic**: public DGA feeds exist, but nothing is
fetched at runtime or at test time and no redistribution licence was verified,
so no real corpus was vendored. **Both halves of the TLS measurement are
synthetic** — no openly-licensed `ssl.log` corpus carrying JA3 was reachable.
`docs/benchmarks.md` §9 says so in the same sentence as every number.

No language model is involved at any point.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.analyzers.dnstunnel import registered_domain, registered_domain_expr
from voidai.analyzers.ngrams import improbability
from voidai.analyzers.statistics import (
    destination_rarity,
    saturating,
    weighted_geometric_mean,
)
from voidai.lexicon import Artifact, Entity, EntityType, Evidence, Finding, Predicate, Severity

#: Weights for the domain-generation score.
#:
#: `nxdomain_rate` keeps the weight the cluster roadmap gave it: it is the
#: signal a DGA cannot avoid. The other two split what the roadmap assigned to
#: entropy and structure, in the ratio that measured best — see below.
_DGA_WEIGHTS = {
    "nxdomain_rate": 0.34,
    "bigram_improbability": 0.56,
    "structure": 0.10,
}

#: Weights for the fingerprint-rarity score. Two components, both about the
#: same claim: how rare, and how much estate that rarity was measured over.
_TLS_WEIGHTS = {
    "fingerprint_rarity": 0.65,
    "estate_support": 0.35,
}

_VOWELS = frozenset("aeiou")


def _unit(value: float) -> float:
    """Clamp a scalar to [0, 1].

    `np.clip` rather than this was the first version, and it cost 10 of the
    34 seconds of a 1.1M-record run: NumPy's clip dispatches through
    `_wrapfunc` for every call, which is free on an array and ruinous on a
    scalar in a loop that runs once per component per label.
    """
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else float(value)

#: Response codes meaning "no such name". Zeek writes the numeric `rcode` and
#: the textual `rcode_name` in different deployments and both normalise into
#: the one `rcode` column, so both spellings are recognised.
_NXDOMAIN = frozenset({"NXDOMAIN", "3"})


def split_registered(name: str) -> tuple[str, str] | None:
    """Reduce a query name to `(second-level label, public suffix)`.

    `www.k7jf2plqx.biz` becomes `("k7jf2plqx", "biz")`. Returns `None` for a
    name with no label left of its suffix — a bare `com`, or an empty string —
    which is not a registrable name and cannot have been generated by one.

    The suffix reduction is `dnstunnel.registered_domain`, reused rather than
    reimplemented: two public-suffix rules that disagree would split the same
    zone two ways in two analyzers.
    """
    registered = registered_domain(name)
    if "." not in registered:
        return None
    label, suffix = registered.split(".", 1)
    if not label or not suffix:
        return None
    return label, suffix


def longest_consonant_run(label: str) -> int:
    """Length of the longest run of consecutive consonants.

    Real registered labels of eight characters or more in
    `tests/data/real.passivedns` have a median run of 2 and a 90th percentile
    of 4; random alphabetic strings of matched length have a median of 6.
    """
    best = current = 0
    for character in label:
        if character.isalpha() and character not in _VOWELS:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


@dataclass(frozen=True)
class TlsDgaConfig:
    """Tunables. The DGA half is set from measurement; the TLS half is not.

    Every DGA threshold below was chosen against the separation between
    `tests/data/real.passivedns` and randomly generated labels, and the
    figures are in `docs/benchmarks.md` §9. The TLS thresholds have no real
    corpus behind them and are set from the shape of the problem, which is
    recorded there too rather than left to be inferred.
    """

    # --- domain generation ---

    #: Distinct registered domains a host must have resolved under one suffix
    #: before the family's NXDOMAIN rate means anything.
    min_family_labels: int = 12
    #: Queries the family must carry, for the same reason.
    min_family_queries: int = 30

    #: Labels shorter than this are not scored, because below it the bigram
    #: model stops discriminating: a four-bigram abbreviation is genuinely
    #: improbable English, and no threshold separates it from a generated
    #: name. Measured on the real fixture, at the 0.65 threshold and with
    #: `nxdomain_rate` unavailable:
    #:
    #:     gate 5 → `ml314.com` 1.000, `gvt2.com` 0.827, `fbcdn.net` 0.784
    #:     gate 6 → ceiling 0.546 (`crwdcntrl.net`), nothing fires
    #:
    #: The cliff is between five and six, and it is sheer. Six is taken
    #: rather than a rounder eight: the ceiling and the 0.104 margin are
    #: identical from six upward, so every character above it discards
    #: coverage — 68 of the fixture's registered labels are scored at six
    #: against 43 at eight — while buying no measured specificity. The cost
    #: that remains is a generation family minting names of five characters
    #: or fewer, which this analyzer will not see.
    min_label_length: int = 6

    #: Share of a family's queries that must carry a response code before the
    #: NXDOMAIN rate is treated as measured. A sensor that populated `rcode`
    #: on a tenth of the family describes that tenth, not the family.
    min_rcode_coverage: float = 0.5
    #: NXDOMAIN share at which the component scores 0 and 1. Ordinary browsing
    #: produces a few percent — typos, stale bookmarks, search-bar mistakes —
    #: so the floor is above zero rather than at it.
    nxdomain_floor: float = 0.10
    nxdomain_ceiling: float = 0.70

    #: Consonant-run length at which the structure signal scores 0 and 1.
    consonant_run_floor: int = 4
    consonant_run_ceiling: int = 9
    #: Digit share at which the structure signal scores 0 and 1. The floor is
    #: not zero: `office365` and `verblife-2` are real names with digits in
    #: them, and a floor at zero hands both a third of the component.
    digit_ratio_floor: float = 0.15
    digit_ratio_ceiling: float = 0.50

    #: Score at or above which the domain is claimed as algorithmic, and the
    #: score above which the finding is promoted from MEDIUM to HIGH.
    #:
    #: **Set from the real fixture, because the synthetic corpus cannot set
    #: it.** Every threshold between 0.35 and 0.85 finds all three detectable
    #: families in `DgaCorpusGenerator` and none of its decoys — the corpus
    #: says only that the answer lies in a wide band. The binding constraint
    #: is `tests/data/real.passivedns`, whose worst case is `crwdcntrl.net` at
    #: 0.546 and `msftncsi.com` at 0.519: real consonant-heavy service
    #: abbreviations score 0.2 higher than the synthetic ones written to
    #: imitate them, which is itself worth knowing. 0.65 leaves a margin of
    #: 0.10 over real benign traffic at no measured cost in family recall.
    dga_threshold: float = 0.65
    dga_high_threshold: float = 0.85

    #: Findings per family. A DGA mints hundreds of names a day and a finding
    #: for each would be the alert flood this project exists to prevent — so
    #: the family is reported through a handful of exemplars, with the
    #: family-wide measurement on every one of them.
    max_per_family: int = 3
    max_dga_findings: int = 100

    # --- TLS fingerprints ---

    #: Hosts presenting *any* fingerprint, below which the analyzer emits
    #: nothing. On a small capture every fingerprint is rare and a finding
    #: would describe the capture rather than the traffic.
    min_estate_hosts: int = 10
    #: Estate size at which the rarity estimate is well supported.
    strong_estate_hosts: int = 50
    #: Sessions a (host, fingerprint) pair must carry. One session can be a
    #: truncated handshake or a probe; it is not evidence the host runs the
    #: client.
    min_sessions: int = 3
    #: Hosts presenting a fingerprint, above which it is not rare.
    max_presenting_hosts: int = 2

    #: A fingerprint on one host clears this at any estate size past the
    #: floor; a fingerprint on two hosts clears it only over a large estate,
    #: where two is genuinely unusual. That rule is the reason for the number,
    #: and it is the rule rather than the number that should be trusted: no
    #: real `ssl.log` corpus was available to calibrate against, and the value
    #: was set after watching a two-host minority browser build score 0.665 in
    #: a 45-host synthetic estate — a corpus written by the same hand as the
    #: detector. `docs/benchmarks.md` §9 says so.
    tls_threshold: float = 0.70
    #: Deliberately an order of magnitude below the DGA cap. This predicate
    #: fires on prevalence alone and cannot raise a host's rank by itself, so
    #: it is enrichment rather than a queue entry — the same reasoning that
    #: caps `contacts_rare_destination` in `egress.py`.
    max_tls_findings: int = 20

    artifact_samples: int = 5


@dataclass
class DgaScore:
    """The measurement for one registered domain, in its family's context."""

    score: float
    components: dict[str, float]
    label: str
    suffix: str
    #: `None` when the sensor recorded no response codes for this family.
    nxdomain_rate: float | None
    rcode_coverage: float
    family_labels: int
    family_queries: int
    queries: int
    #: `None` when response codes were unavailable, so it is unknown whether
    #: this name ever resolved.
    resolved: bool | None
    consonant_run: int
    digit_ratio: float
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        omitted = [name for name in _DGA_WEIGHTS if name not in self.components]
        missing = f"; omitted (unmeasured): {', '.join(sorted(omitted))}" if omitted else ""
        rate = (
            "no response codes recorded"
            if self.nxdomain_rate is None
            else f"{self.nxdomain_rate:.0%} NXDOMAIN"
        )
        return (
            f"weighted geometric mean of [{parts}] for '{self.label}' within a family of "
            f"{self.family_labels} registered domains under .{self.suffix} from this host "
            f"({self.family_queries} queries, {rate}){missing}"
        )


@dataclass
class TlsScore:
    """The measurement for one (host, client fingerprint) pair."""

    score: float
    components: dict[str, float]
    fingerprint: str
    server_fingerprint: str | None
    sessions: int
    servers: int
    presenting_hosts: int
    estate_hosts: int
    server_names: tuple[str, ...]
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        return (
            f"weighted geometric mean of [{parts}] over {self.sessions} TLS session(s) to "
            f"{self.servers} server(s); this fingerprint was presented by "
            f"{self.presenting_hosts} of the {self.estate_hosts} host(s) observed negotiating TLS"
        )


def score_domain(
    label: str,
    suffix: str,
    nxdomain_rate: float | None,
    config: TlsDgaConfig,
    family_labels: int = 0,
    family_queries: int = 0,
    queries: int = 1,
    resolved: bool | None = None,
    rcode_coverage: float = 0.0,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> DgaScore | None:
    """Measure one registered domain. Returns None if it cannot be measured.

    Separated from the Polars and Lexicon plumbing so the mathematics can be
    tested against hand-built inputs — including the ones where the NXDOMAIN
    rate is absent, which is the case that carries the rule this analyzer
    exists to get right.

    `nxdomain_rate` is `None` when the sensor recorded no response codes. It
    is not defaulted to zero: zero asserts that every name in the family
    resolved, which is a measurement nobody made.
    """
    if len(label) < config.min_label_length:
        return None

    character_score = improbability(label)
    if character_score is None:
        return None

    components: dict[str, float] = {"bigram_improbability": character_score}

    if nxdomain_rate is not None:
        span = max(config.nxdomain_ceiling - config.nxdomain_floor, 1e-9)
        components["nxdomain_rate"] = _unit((nxdomain_rate - config.nxdomain_floor) / span)

    run = longest_consonant_run(label)
    digits = sum(character.isdigit() for character in label) / len(label)
    run_span = max(config.consonant_run_ceiling - config.consonant_run_floor, 1)
    digit_span = max(config.digit_ratio_ceiling - config.digit_ratio_floor, 1e-9)
    run_score = _unit((run - config.consonant_run_floor) / run_span)
    digit_score = _unit((digits - config.digit_ratio_floor) / digit_span)
    # Soft OR, not a mean. These are alternative tells rather than joint
    # requirements: a DGA that emits `xkjfhwuebfq` shows the consonant run and
    # no digits, one that emits `a1b2c3d4e5` shows the digits and no run, and
    # averaging would halve the score of both for failing to be the other.
    components["structure"] = 1.0 - (1.0 - run_score) * (1.0 - digit_score)

    return DgaScore(
        score=weighted_geometric_mean(components, _DGA_WEIGHTS),
        components=components,
        label=label,
        suffix=suffix,
        nxdomain_rate=nxdomain_rate,
        rcode_coverage=rcode_coverage,
        family_labels=int(family_labels),
        family_queries=int(family_queries),
        queries=int(queries),
        resolved=resolved,
        consonant_run=run,
        digit_ratio=digits,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def score_fingerprint(
    fingerprint: str,
    presenting_hosts: int,
    estate_hosts: int,
    config: TlsDgaConfig,
    sessions: int = 1,
    servers: int = 1,
    server_fingerprint: str | None = None,
    server_names: tuple[str, ...] = (),
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> TlsScore | None:
    """Measure one (host, client fingerprint) pair.

    Returns None when the estate is too small for prevalence to mean anything,
    or when the fingerprint is not rare. Neither is a low score — both are
    cases where the question this predicate asks has no answer here, and a
    number would be an answer.
    """
    if estate_hosts < config.min_estate_hosts:
        return None
    if presenting_hosts > config.max_presenting_hosts or presenting_hosts < 1:
        return None
    if sessions < config.min_sessions:
        return None

    components = {
        "fingerprint_rarity": destination_rarity(presenting_hosts),
        "estate_support": saturating(estate_hosts, config.strong_estate_hosts),
    }

    return TlsScore(
        score=weighted_geometric_mean(components, _TLS_WEIGHTS),
        components=components,
        fingerprint=fingerprint,
        server_fingerprint=server_fingerprint,
        sessions=int(sessions),
        servers=int(servers),
        presenting_hosts=int(presenting_hosts),
        estate_hosts=int(estate_hosts),
        server_names=server_names,
        first_seen=first_seen,
        last_seen=last_seen,
    )


class TlsDgaAnalyzer(BaseAnalyzer):
    """Emits `RESOLVES_ALGORITHMIC_DOMAIN` and `PRESENTS_RARE_TLS_FINGERPRINT`."""

    name = "tlsdga"
    version = "0.1.0"

    def __init__(self, config: TlsDgaConfig | None = None) -> None:
        self.config = config or TlsDgaConfig()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Two independent halves over two telemetry sources.

        Either may be absent, and each is silent on its own account. A capture
        with DNS and no TLS produces the DGA findings and nothing else, rather
        than nothing at all.
        """
        return self._analyze_dns(ctx) + self._analyze_tls(ctx)

    # --- domain generation ---

    def _analyze_dns(self, ctx: AnalysisContext) -> list[Finding]:
        scan = ctx.dns_scan()
        available = set(scan.collect_schema().names())
        if not {"query", "src_ip"} <= available:
            return []

        families = self._family_summary(scan, available)
        if families.is_empty():
            return []

        labels = self._family_labels(scan, families, available)
        if labels.is_empty():
            return []

        by_family: dict[tuple[str, str], list[tuple[DgaScore, dict[str, object]]]] = {}
        rates = {
            (str(row["src_ip"]), str(row["suffix"])): row
            for row in families.iter_rows(named=True)
        }
        for row in labels.iter_rows(named=True):
            key = (str(row["src_ip"]), str(row["suffix"]))
            family = rates[key]
            score = score_domain(
                str(row["label"]),
                str(row["suffix"]),
                self._nxdomain_rate(family),
                self.config,
                family_labels=int(family["family_labels"]),
                family_queries=int(family["family_queries"]),
                queries=int(row["queries"]),
                resolved=self._resolved(row, family),
                rcode_coverage=self._rcode_coverage(family),
                first_seen=float(row["first_ts"]),
                last_seen=float(row["last_ts"]),
            )
            if score is not None and score.score >= self.config.dga_threshold:
                by_family.setdefault(key, []).append((score, row))

        selected = self._select_dga(by_family)
        return [self._build_dga_finding(score, row, ctx) for score, row in selected]

    def _family_summary(self, scan: pl.LazyFrame, available: set[str]) -> pl.DataFrame:
        """Pass one: one row per (source, suffix), carrying only scalars.

        The public-suffix reduction runs as a Polars expression rather than a
        Python loop so a multi-million-row `dns.log` stays in the columnar
        path, exactly as `dnstunnel._group` does it.
        """
        prepared = (
            scan.drop_nulls(subset=["query", "src_ip", "ts"])
            .with_columns(registered_domain_expr().alias("registered"))
            .filter(pl.col("registered").str.contains(".", literal=True))
            .with_columns(
                pl.col("registered").str.split(".").list.first().alias("label"),
                pl.col("registered").str.splitn(".", 2).struct.field("field_1").alias("suffix"),
            )
        )

        aggregations = [
            pl.len().alias("family_queries"),
            pl.col("label").n_unique().alias("family_labels"),
            pl.col("ts").min().alias("first_ts"),
            pl.col("ts").max().alias("last_ts"),
        ]
        if "rcode" in available:
            code = pl.col("rcode").cast(pl.Utf8).str.to_uppercase().str.strip_chars()
            aggregations += [
                pl.col("rcode").count().alias("rcode_known"),
                code.is_in(list(_NXDOMAIN)).sum().alias("nxdomain_count"),
            ]

        return (
            prepared.group_by(["src_ip", "suffix"])
            .agg(aggregations)
            .filter(
                (pl.col("family_labels") >= self.config.min_family_labels)
                & (pl.col("family_queries") >= self.config.min_family_queries)
            )
            .collect(engine="streaming")
        )

    def _family_labels(
        self, scan: pl.LazyFrame, families: pl.DataFrame, available: set[str]
    ) -> pl.DataFrame:
        """Pass two: the distinct labels of qualifying families, and only those.

        A semi-join restricts the scan to families that passed the gates
        before any per-label list column is built, so the arrays gathered here
        cover a handful of hosts rather than the capture.
        """
        samples = self.config.artifact_samples
        aggregations = [
            pl.len().alias("queries"),
            pl.col("ts").min().alias("first_ts"),
            pl.col("ts").max().alias("last_ts"),
        ]
        if "rcode" in available:
            code = pl.col("rcode").cast(pl.Utf8).str.to_uppercase().str.strip_chars()
            aggregations.append((~code.is_in(list(_NXDOMAIN))).any().alias("ever_resolved"))
        for column in ("source_file", "source_line"):
            if column in available:
                aggregations.append(pl.col(column).head(samples))

        return (
            scan.drop_nulls(subset=["query", "src_ip", "ts"])
            # Narrowed to the hosts that own a qualifying family *before* the
            # suffix reduction runs, so pass two derives names for a handful
            # of hosts rather than for the capture.
            .join(families.lazy().select("src_ip").unique(), on="src_ip", how="semi")
            .with_columns(registered_domain_expr().alias("registered"))
            .filter(pl.col("registered").str.contains(".", literal=True))
            .with_columns(
                pl.col("registered").str.split(".").list.first().alias("label"),
                pl.col("registered").str.splitn(".", 2).struct.field("field_1").alias("suffix"),
            )
            .filter(pl.col("label").str.len_chars() >= self.config.min_label_length)
            .join(families.lazy().select("src_ip", "suffix"), on=["src_ip", "suffix"], how="semi")
            .group_by(["src_ip", "suffix", "label"])
            .agg(aggregations)
            .collect(engine="streaming")
        )

    def _rcode_coverage(self, family: dict[str, object]) -> float:
        known = family.get("rcode_known")
        queries = int(family["family_queries"])
        if known is None or queries <= 0:
            return 0.0
        return int(known) / queries

    def _nxdomain_rate(self, family: dict[str, object]) -> float | None:
        """Share of the family's queries that returned NXDOMAIN, or None.

        None on two grounds and they are the same rule: the sensor has no
        `rcode` column at all (passivedns), or it populated it on too few of
        the family's queries to describe the family.
        """
        known = family.get("rcode_known")
        if known is None or int(known) == 0:
            return None
        if self._rcode_coverage(family) < self.config.min_rcode_coverage:
            return None
        return int(family["nxdomain_count"]) / int(known)

    def _resolved(self, row: dict[str, object], family: dict[str, object]) -> bool | None:
        """Whether this name ever resolved, or None if response codes are absent."""
        if self._nxdomain_rate(family) is None:
            return None
        answered = row.get("ever_resolved")
        return None if answered is None else bool(answered)

    def _select_dga(
        self, by_family: dict[tuple[str, str], list[tuple[DgaScore, dict[str, object]]]]
    ) -> list[tuple[DgaScore, dict[str, object]]]:
        """Take a few exemplars per family, then apply the global cap.

        Exemplars are chosen by *resolution first*, score second. A DGA family
        is a few hundred names that failed and one that worked, and the one
        that worked is the C2 — reporting the three most improbable names
        while omitting the only one that resolved would hand the analyst the
        least useful members of the set. Where response codes are unavailable
        the sort collapses to score alone, which is all that is known.

        Both sorts end on the label, and that is not decoration. A generated
        family produces hundreds of names scoring an identical 1.0, so the
        order of equal scores decides which three are reported — and without a
        total order that comes from `group_by`, which Polars does not promise
        to keep stable. Two runs over the same capture then emit different
        exemplars and therefore different finding IDs, which would quietly
        break the property every archived report and every benchmark
        comparison in this project depends on.
        """
        selected: list[tuple[DgaScore, dict[str, object]]] = []
        for _, members in sorted(by_family.items()):
            members.sort(key=lambda item: (not item[0].resolved, -item[0].score, item[0].label))
            selected += members[: self.config.max_per_family]

        selected.sort(key=lambda item: (-item[0].score, item[0].suffix, item[0].label))
        return selected[: self.config.max_dga_findings]

    def _dga_artifacts(self, row: dict[str, object], score: DgaScore) -> list[Artifact]:
        files = row.get("source_file") or []
        lines = row.get("source_line") or []
        artifacts: list[Artifact] = []
        for index in range(min(len(lines), self.config.artifact_samples)):
            source = files[index] if index < len(files) and files[index] else "<unknown>"
            artifacts.append(
                Artifact(
                    source=str(source),
                    locator=f"line:{lines[index]}",
                    observed_at=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
                    excerpt=f"{row['src_ip']} -> {score.label}.{score.suffix}",
                )
            )
        return artifacts or [
            Artifact(
                source="<aggregate>",
                locator=f"{row['src_ip']}:{score.label}.{score.suffix}",
            )
        ]

    def _build_dga_finding(
        self, score: DgaScore, row: dict[str, object], ctx: AnalysisContext
    ) -> Finding:
        artifacts = self._dga_artifacts(row, score)
        domain = f"{score.label}.{score.suffix}"
        evidence = [
            Evidence(
                kind="domain_name_structure",
                summary=(
                    f"'{score.label}' scores {score.components['bigram_improbability']:.2f} "
                    f"against an English character model, with a consonant run of "
                    f"{score.consonant_run} and {score.digit_ratio:.0%} digits"
                ),
                payload={
                    "registered_domain": domain,
                    "label": score.label,
                    "label_length": len(score.label),
                    "bigram_improbability": round(
                        score.components["bigram_improbability"], 4
                    ),
                    "longest_consonant_run": score.consonant_run,
                    "digit_ratio": round(score.digit_ratio, 4),
                    "queries": score.queries,
                },
                artifacts=artifacts,
            ),
            Evidence(
                kind="resolution_family",
                summary=(
                    f"{score.family_labels} registered domains under .{score.suffix} from this "
                    f"host over {score.family_queries} queries; "
                    + (
                        "no response codes recorded by the sensor"
                        if score.nxdomain_rate is None
                        else f"{score.nxdomain_rate:.0%} returned NXDOMAIN"
                    )
                ),
                payload={
                    "suffix": score.suffix,
                    "family_labels": score.family_labels,
                    "family_queries": score.family_queries,
                    # Explicitly null rather than zero. A reader can see that
                    # the strongest component was never measured.
                    "nxdomain_rate": (
                        None if score.nxdomain_rate is None else round(score.nxdomain_rate, 4)
                    ),
                    "rcode_coverage": round(score.rcode_coverage, 4),
                    "resolved": score.resolved,
                    "span_seconds": round(score.last_seen - score.first_seen, 1),
                },
                artifacts=artifacts,
            ),
        ]

        return Finding(
            predicate=Predicate.RESOLVES_ALGORITHMIC_DOMAIN,
            subject=ctx.actor(str(row["src_ip"])),
            object=Entity(type=EntityType.DOMAIN, value=domain),
            evidence=[*evidence, *ctx.resolution_evidence(str(row["src_ip"]))],
            confidence=round(score.score, 4),
            basis=score.basis(),
            severity=(
                Severity.HIGH
                if score.score >= self.config.dga_high_threshold
                else Severity.MEDIUM
            ),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )

    # --- TLS fingerprints ---

    def _analyze_tls(self, ctx: AnalysisContext) -> list[Finding]:
        scan = ctx.ssl_scan()
        available = set(scan.collect_schema().names())
        # No `ja3` column means a sensor without the JA3 package. Silence is
        # the honest response; `voidai doctor --telemetry` is where an
        # operator learns that it is fixable.
        if not {"src_ip", "ja3"} <= available:
            return []

        summary = self._fingerprint_summary(scan, available)
        if summary.is_empty():
            return []

        estate_hosts = int(summary["src_ip"].n_unique())

        scored: list[tuple[TlsScore, dict[str, object]]] = []
        for row in summary.iter_rows(named=True):
            score = score_fingerprint(
                str(row["ja3"]),
                int(row["presenting_hosts"]),
                estate_hosts,
                self.config,
                sessions=int(row["sessions"]),
                servers=int(row["servers"]),
                server_fingerprint=self._first(row.get("ja3s")),
                server_names=tuple(
                    str(name) for name in (row.get("server_name") or []) if name
                )[: self.config.artifact_samples],
                first_seen=float(row["first_ts"]),
                last_seen=float(row["last_ts"]),
            )
            if score is not None and score.score >= self.config.tls_threshold:
                scored.append((score, row))

        # Total order, for the reason given in `_select_dga`: equal scores are
        # the common case here too, since rarity is a function of a small
        # integer count.
        scored.sort(key=lambda item: (-item[0].score, str(item[1]["src_ip"]), item[0].fingerprint))
        return [
            self._build_tls_finding(score, row, ctx)
            for score, row in scored[: self.config.max_tls_findings]
        ]

    def _fingerprint_summary(self, scan: pl.LazyFrame, available: set[str]) -> pl.DataFrame:
        """One row per (host, client fingerprint), plus estate-wide prevalence.

        Rows whose `ja3` is null are dropped rather than grouped: a sensor
        that recorded no fingerprint for a session has not recorded a session
        with a blank fingerprint, and grouping them would invent a hugely
        prevalent fingerprint shared by every host with a partial log.
        """
        samples = self.config.artifact_samples
        aggregations = [
            pl.len().alias("sessions"),
            pl.col("ts").min().alias("first_ts"),
            pl.col("ts").max().alias("last_ts"),
        ]
        aggregations.append(
            pl.col("dst_ip").n_unique().alias("servers")
            if "dst_ip" in available
            else pl.lit(1, dtype=pl.UInt32).alias("servers")
        )
        for column in ("ja3s", "server_name", "source_file", "source_line"):
            if column in available:
                aggregations.append(pl.col(column).drop_nulls().head(samples))

        summary = (
            scan.drop_nulls(subset=["src_ip", "ja3", "ts"])
            .filter(pl.col("ja3").str.strip_chars() != "")
            .group_by(["src_ip", "ja3"])
            .agg(aggregations)
            .collect(engine="streaming")
        )
        if summary.is_empty():
            return summary

        prevalence = summary.group_by("ja3").agg(
            pl.col("src_ip").n_unique().alias("presenting_hosts")
        )
        return summary.join(prevalence, on="ja3", how="left")

    @staticmethod
    def _first(values: object) -> str | None:
        if not isinstance(values, list) or not values:
            return None
        return str(values[0])

    def _tls_artifacts(self, row: dict[str, object], score: TlsScore) -> list[Artifact]:
        files = row.get("source_file") or []
        lines = row.get("source_line") or []
        artifacts: list[Artifact] = []
        for index in range(min(len(lines), self.config.artifact_samples)):
            source = files[index] if index < len(files) and files[index] else "<unknown>"
            artifacts.append(
                Artifact(
                    source=str(source),
                    locator=f"line:{lines[index]}",
                    observed_at=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
                    excerpt=f"{row['src_ip']} ja3={score.fingerprint}",
                )
            )
        return artifacts or [
            Artifact(source="<aggregate>", locator=f"{row['src_ip']}:{score.fingerprint}")
        ]

    def _build_tls_finding(
        self, score: TlsScore, row: dict[str, object], ctx: AnalysisContext
    ) -> Finding:
        artifacts = self._tls_artifacts(row, score)
        evidence = [
            Evidence(
                kind="tls_client_fingerprint",
                summary=(
                    f"JA3 {score.fingerprint} presented by {score.presenting_hosts} of "
                    f"{score.estate_hosts} host(s) negotiating TLS, over "
                    f"{score.sessions} session(s) to {score.servers} server(s)"
                ),
                payload={
                    "ja3": score.fingerprint,
                    "ja3s": score.server_fingerprint,
                    "sessions": score.sessions,
                    "servers": score.servers,
                    "presenting_hosts": score.presenting_hosts,
                    "estate_hosts": score.estate_hosts,
                    "server_names": list(score.server_names),
                    "span_seconds": round(score.last_seen - score.first_seen, 1),
                },
                artifacts=artifacts,
            )
        ]

        return Finding(
            predicate=Predicate.PRESENTS_RARE_TLS_FINGERPRINT,
            subject=ctx.actor(str(row["src_ip"])),
            object=Entity(type=EntityType.TLS_FINGERPRINT, value=score.fingerprint),
            evidence=[*evidence, *ctx.resolution_evidence(str(row["src_ip"]))],
            confidence=round(score.score, 4),
            basis=score.basis(),
            # Held at the Lexicon default. A rare fingerprint is a lead, and
            # promoting it would put a prevalence observation alongside a
            # measured command-and-control channel.
            severity=Predicate.PRESENTS_RARE_TLS_FINGERPRINT.spec.default_severity,
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )
