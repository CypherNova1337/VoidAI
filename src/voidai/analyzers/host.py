"""Host and endpoint detection: rare executions and anomalous process lineage.

Two predicates, one analyzer, because they share a parser and a baseline and
because only something that sees both can tell when they are describing the
same event — see `_subsume` below.

    executes_rare_process      this machine ran a binary the estate does not
    exhibits_anomalous_lineage this parent spawned a child it does not spawn

## Both verbs are estate-relative, and that decides everything

The Lexicon says what they mean: `executes_rare_process` is *"runs a process
rare across the observed estate"*, and `exhibits_anomalous_lineage` is *"a
parent/child relationship inconsistent with normal system behaviour"* — where
the only thing this analyzer knows about normal is what the estate did.

Estate prevalence is therefore not a *component* of these scores. It is the
signal that defines the verbs. On a single host, "rare" means "seen once",
which is every process ever run; a lineage scored against a baseline of one
machine is scored against nothing.

That is roadmap rule 6 at its second level, and the answer is the same one
cluster 1 reached for `exfiltrates_to` on direction-blind NetFlow: **if the
defining signal is unavailable, the verb is unsayable.** Unlike cluster 1
there is no weaker predicate to fall back to — the Lexicon has no
`executes_process_from_unusual_path`, and minting one is a grammar change,
which is cross-cutting work and not this analyzer's to do. So the analyzer
gates and emits nothing, and `estate_baseline` records why in terms an
operator can read (`voidai doctor --telemetry`).

Three gates, in `EstateBaseline.gate`. Two are ordinary floors. The third is
not, and it is the one that matters: **the share of images seen on exactly one
host.** Host count alone passes an estate that is wide but shallow — thirty
machines observed for twenty seconds each — where every image is still a
singleton and every rarity score is still 1.0. The threshold was set from real
telemetry rather than judgement; `docs/benchmarks.md` section 11 has the
numbers.

## What is measured, and how the two predicates divide the work

They divide on **where the anomaly is**, and that division is what keeps them
from describing one event twice.

If the estate has never run this binary, the story is the binary, and the
verb is `executes_rare_process`. Its parentage is evidence inside that
finding, not a second finding — a novel image trivially has a novel parent
edge, so reporting both would be one observation counted twice.

If the binary is ordinary and only the *relationship* is not — `winword.exe`
spawning `cmd.exe`, where both run on every machine in the estate — the story
is the relationship, and the verb is `exhibits_anomalous_lineage`.

That division is structural rather than a filter bolted on afterwards: the
lineage components are conditional on the parent and the child each being
widespread, so a novel child scores near zero on them by construction.
`_subsume` then guarantees the disjointness that the arithmetic already
almost provides.

`executes_rare_process`, three components:

    image_prevalence      hosts running this image, through the same rarity
                          curve used for destinations and signatures
    path_anomaly          a graded prior over where the binary lives
    execution_prevalence  how few times it ran estate-wide, which separates
                          "ran once anywhere" from "runs constantly on one box"

`exhibits_anomalous_lineage`, three, the last frequently omitted:

    parent_breadth   1 - hosts(edge)/hosts(parent). "This parent is everywhere
                     and only here does it do this."
    child_breadth    1 - hosts(edge)/hosts(child). "This child is everywhere
                     and only here does it arrive this way."
    child_surprisal  -log2 P(child | parent) from the estate's lineage graph.
                     Omitted unless the parent has enough child executions for
                     a frequency to mean anything.

Both breadths are *conditional* prevalences, and that is the whole of why they
work. A raw count of hosts showing an edge cannot tell `winword.exe -> cmd.exe`
on one machine from `cmd.exe -> msbuild.exe` on one machine; dividing by how
widespread each end is separates them completely. `msbuild.exe` runs on one
host and is spawned by `cmd.exe` on that host every time, so its parentage is
entirely typical and its child breadth is zero. `cmd.exe` runs on forty and is
spawned by an Office application on one.

## The two components that are not here

**Command-line entropy.** The roadmap asked for command-line length and
entropy. Entropy was measured against the real corpus and removed, for a
reason that is not section 9's. Section 9 found entropy fails on
6-to-20-character domain labels because at that length it measures length.
Command lines are hundreds of characters, so that objection does not apply —
and it fails anyway, harder: the encodings attackers actually use are *less*
entropic than ordinary command lines. The 7,106-character base64 Empire
payload in `tests/data` scores 4.44 bits, the exact median of the corpus,
while a routine `cvtres.exe` invocation with a temporary path scores 5.52.
Ranking by entropy puts the attack at the fiftieth percentile.

Length alone does separate it — 7,106 characters against a 99th percentile of
308 — but only against the image's *own* baseline, and a length component
scored against a global constant is a constant drag on every score rather
than a signal. So the command line is carried in the evidence payload, where
an analyst reads it, and not in the arithmetic. A per-image length deviation
is the candidate replacement, and it is noted in the benchmarks rather than
guessed at here.

**Chain surprisal.** The ancestry is walked, reported, and pivoted on —
`explorer -> winword -> cmd -> powershell` is a different sentence from
`explorer -> cmd`, and an analyst needs the first one. It is deliberately not
*scored*. Three formulations were tried: the mean edge anomaly along the chain
dilutes the one edge that matters with the ordinary ones above it
(`explorer -> winword` is on every host), the maximum restates
`parent_breadth`, and a count of unusual edges scores a genuine single-step
anomaly at zero. A component that restates another is exactly the double-count
this analyzer is built to avoid, so the chain stays in the evidence until
there is a measurement of it that is not a restatement.

No language model is involved at any point.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, TypeVar

import networkx as nx
import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.analyzers.statistics import (
    destination_rarity,
    saturating,
    weighted_geometric_mean,
)
from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    Predicate,
)

_PROCESS_WEIGHTS = {
    "image_prevalence": 0.50,
    "path_anomaly": 0.34,
    "execution_prevalence": 0.16,
}

_LINEAGE_WEIGHTS = {
    "parent_breadth": 0.38,
    "child_breadth": 0.38,
    "child_surprisal": 0.24,
}

class _Scored(Protocol):
    """What `_cap` needs of a score: a number to rank by.

    Both score types satisfy it, and stating the requirement rather than
    taking `object` keeps the two capped lists distinguishable — a cap that
    returned `object` let a lineage score reach `_process_finding` without
    complaint.
    """

    score: float


_Score = TypeVar("_Score", bound=_Scored)


#: Directory prefixes any unprivileged user can write to. A graded *prior* over
#: filesystem structure, in the same sense `destination_rarity` is a prior over
#: prevalence — not a signature list, and it names no malware, no tool and no
#: technique. Roadmap section 6 warns against a design drifting into a rule
#: list; the test is whether the table grows when new attacks appear, and this
#: one grows only when Windows does.
_WRITABLE_PREFIXES = (
    "\\users\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\$recycle.bin\\",
    "\\public\\",
    "\\perflogs\\",
    "\\downloads\\",
)

#: Where the operating system's own binaries live.
_SYSTEM_PREFIXES = ("\\windows\\system32\\", "\\windows\\syswow64\\")


@dataclass(frozen=True)
class HostConfig:
    """Tunables, with defaults set for precision over recall.

    Every default that could have been a judgement call was set from the real
    corpus instead; `docs/benchmarks.md` section 11 says which and how.
    """

    #: Distinct hosts reporting process telemetry, below which no prevalence
    #: claim is made. Five is the point at which a single-host image
    #: (`destination_rarity` 1.0) is meaningfully rarer than a universal one
    #: (0.45) rather than merely different from it.
    min_baseline_hosts: int = 5
    #: Total process creations, below which the conditional probabilities have
    #: no denominator. A parent observed three times cannot say what is normal
    #: for it, however many hosts it was observed on.
    min_executions: int = 200
    #: Share of distinct images seen on exactly one host, above which the
    #: baseline has not converged and prevalence measures the estate's size
    #: rather than an image's rarity. See the module docstring.
    max_singleton_share: float = 0.50

    score_threshold: float = 0.60
    lineage_threshold: float = 0.62

    #: Executions beyond which an image stops looking unusual for running at
    #: all. Low on purpose: this component separates "ran once anywhere" from
    #: "runs constantly on one machine", which host prevalence cannot see.
    execution_prevalence_target: float = 8.0

    #: Surprisal, in bits, mapped to a component score of 1.0. Six bits is one
    #: execution in sixty-four; beyond it the estimate rests on counts too
    #: small to distinguish.
    surprisal_cap_bits: float = 6.0
    #: Child executions a parent needs before `P(child | parent)` means
    #: anything. An application observed spawning one process has spawned
    #: 100% of its children exactly once, and scoring that as unremarkable —
    #: or as remarkable — is a claim from a sample of one. Below the floor the
    #: component is omitted and the two breadths carry the finding (rule 6).
    min_frequency_samples: int = 20

    #: How far up a process tree the ancestry walk climbs. Each level costs
    #: one bounded scan (see `_ancestry`), so this is a memory-for-passes
    #: trade and not an accuracy one — the chain is reported, not scored.
    max_chain_depth: int = 4

    #: Ceiling on emitted findings. Both ceilings are **per predicate**, so
    #: this analyzer's own maximum is twice `max_findings`. A single budget
    #: shared between the two would let a flood of rare executions silence
    #: every lineage finding in the estate, which is a worse failure than
    #: emitting a few more rows.
    max_findings: int = 60
    #: Ceiling per host, applied first. A connection log's findings spread
    #: across an estate; a compromised machine can run thousands of distinct
    #: images by itself and would otherwise consume the whole budget alone.
    #: This is roadmap rule 4 in the form this telemetry needs.
    max_findings_per_host: int = 5
    #: Executions sampled as artifacts per finding.
    artifact_samples: int = 3


@dataclass(frozen=True)
class EstateBaseline:
    """What the estate can and cannot support, and why.

    Constructed before anything is scored. Carried rather than recomputed so
    that `voidai doctor --telemetry` reports the same numbers the analyzer
    acted on, instead of a second opinion that might disagree.
    """

    hosts: int
    executions: int
    distinct_images: int
    singleton_images: int
    span_seconds: float

    @property
    def singleton_share(self) -> float:
        if self.distinct_images == 0:
            return 1.0
        return self.singleton_images / self.distinct_images

    def gate(self, config: HostConfig) -> str | None:
        """The reason this estate cannot support a prevalence claim, or None.

        A sentence rather than a boolean, because the analyzer emitting
        nothing and the analyzer having nothing to say look identical from the
        outside, and an operator needs to tell them apart.
        """
        if self.hosts < config.min_baseline_hosts:
            return (
                f"{self.hosts} host(s) reporting process telemetry, "
                f"below the {config.min_baseline_hosts} a prevalence claim needs"
            )
        if self.executions < config.min_executions:
            return (
                f"{self.executions} process creations, below the "
                f"{config.min_executions} the conditional frequencies need"
            )
        if self.singleton_share > config.max_singleton_share:
            return (
                f"{self.singleton_share:.0%} of {self.distinct_images} images are seen on "
                f"exactly one host (limit {config.max_singleton_share:.0%}); the baseline "
                "has not converged, so rarity would measure the estate rather than the image"
            )
        return None

    def summary(self) -> str:
        """One line an operator can act on.

        The observation window is in it because a shallow estate is the
        failure the singleton share exists to catch, and a reader who sees
        "74% seen on one host only" over half an hour can diagnose it without
        being told.
        """
        return (
            f"{self.hosts} hosts, {self.executions} process creations over "
            f"{self.span_seconds / 3600:.1f}h, {self.distinct_images} distinct images, "
            f"{self.singleton_share:.0%} seen on one host only"
        )


@dataclass
class ProcessScore:
    """The full measurement behind one `executes_rare_process` finding."""

    score: float
    components: dict[str, float]
    image_name: str
    image_path: str
    hosts_running: int
    executions: int
    estate_hosts: int
    observed: int
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        return (
            f"weighted geometric mean of [{parts}]; {self.image_name} ran "
            f"{self.executions} time(s) on {self.hosts_running} of {self.estate_hosts} "
            f"hosts, {self.observed} of them here"
        )


@dataclass
class LineageScore:
    """The full measurement behind one `exhibits_anomalous_lineage` finding."""

    score: float
    components: dict[str, float]
    parent_name: str
    child_name: str
    child_path: str
    pair_hosts: int
    pair_executions: int
    parent_hosts: int
    child_hosts: int
    estate_hosts: int
    child_given_parent: float | None
    chain: tuple[str, ...]
    chain_truncated: bool
    observed: int
    first_seen: float
    last_seen: float

    def chain_text(self) -> str:
        """The ancestry as a sentence, which is what makes the finding legible.

        Not scored — see the module docstring — but reported everywhere,
        because `explorer.exe -> winword.exe -> cmd.exe` and
        `explorer.exe -> cmd.exe` are different things for a responder to read
        even where the arithmetic cannot yet tell them apart.
        """
        walked = " -> ".join(self.chain) if self.chain else self.parent_name
        suffix = " (ancestry truncated at the capture boundary)" if self.chain_truncated else ""
        return f"{walked} -> {self.child_name}{suffix}"

    def basis(self) -> str:
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        frequency = (
            f", and is {self.child_given_parent:.1%} of what {self.parent_name} spawns"
            if self.child_given_parent is not None
            else f", and {self.parent_name} has spawned too little for a frequency to be read"
        )
        return (
            f"weighted geometric mean of [{parts}]; {self.chain_text()} — this edge is on "
            f"{self.pair_hosts} host(s) against {self.parent_hosts} running {self.parent_name} "
            f"and {self.child_hosts} running {self.child_name}, of {self.estate_hosts}"
            f"{frequency}"
        )


def image_name(path: str | None) -> str | None:
    """The lowercased basename of an executable path.

    Both separators are handled: Sysmon writes Windows paths, but the same
    field carries a device path (`\\device\\harddiskvolume2\\…`) for a handful
    of early-boot processes, and a collector normalising to forward slashes is
    not unheard of.
    """
    if not path:
        return None
    normalised = path.replace("/", "\\").rstrip("\\")
    name = normalised.rsplit("\\", 1)[-1].strip().lower()
    return name or None


def path_anomaly(path: str | None) -> float | None:
    """A graded prior on how unusual it is for a binary to live where it does.

    Four bands rather than a flag. A flag would annihilate the geometric mean
    for anything under `System32`, and the binaries most often abused live
    exactly there — so a system path scores low, not zero, and a genuinely
    unusual one can still surface on the strength of the other components.

    Returns None when the sensor recorded no image path, so the weight
    renormalises rather than the component being invented (rule 6).
    """
    if not path:
        return None
    lowered = path.replace("/", "\\").lower()
    if any(prefix in lowered for prefix in _WRITABLE_PREFIXES):
        return 1.0
    if any(lowered.startswith(prefix) or prefix in lowered for prefix in _SYSTEM_PREFIXES):
        return 0.15
    if "\\windows\\" in lowered:
        return 0.30
    return 0.55


def _surprisal(probability: float, config: HostConfig) -> float:
    """Map a conditional probability to [0, 1] through its surprisal in bits."""
    if probability <= 0.0:
        return 1.0
    bits = -math.log2(min(probability, 1.0))
    return min(1.0, bits / config.surprisal_cap_bits)


def score_process(
    image_path: str,
    hosts_running: int,
    executions: int,
    observed: int,
    baseline: EstateBaseline,
    config: HostConfig,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> ProcessScore | None:
    """Measure one (host, image) pair. None if it cannot qualify.

    Separated from the Polars and Lexicon plumbing so the arithmetic can be
    tested against hand-computed values, the way `score_pair` is.
    """
    name = image_name(image_path)
    if name is None:
        return None

    components: dict[str, float] = {
        "image_prevalence": destination_rarity(hosts_running),
        "execution_prevalence": 1.0 - saturating(executions, config.execution_prevalence_target),
    }
    location = path_anomaly(image_path)
    if location is not None:
        components["path_anomaly"] = location

    return ProcessScore(
        score=weighted_geometric_mean(components, _PROCESS_WEIGHTS),
        components=components,
        image_name=name,
        image_path=image_path,
        hosts_running=hosts_running,
        executions=executions,
        estate_hosts=baseline.hosts,
        observed=observed,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def score_lineage(
    child_path: str,
    parent_name: str,
    pair_hosts: int,
    pair_executions: int,
    parent_hosts: int,
    child_hosts: int,
    child_given_parent: float | None,
    chain: tuple[str, ...],
    chain_truncated: bool,
    observed: int,
    baseline: EstateBaseline,
    config: HostConfig,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> LineageScore | None:
    """Measure one (host, parent, child) triple. None if it cannot qualify.

    Both breadths are conditional prevalences: the share of the machines
    running one end of the edge on which the edge itself is *not* seen. Each
    needs at least two hosts at that end before it says anything — an image
    that runs on one machine is spawned the way it is spawned on one machine,
    and calling that typical or atypical is a claim from a sample of one. The
    unmeasurable one is omitted and the weights renormalise (rule 6).

    With neither breadth measurable there is nothing left that distinguishes a
    relationship from its ends, so no score is returned at all. That is the
    predicate level of the same rule: the verb names a property of an edge,
    and with no edge measurement it is unsayable.
    """
    name = image_name(child_path)
    if name is None or not parent_name:
        return None

    components: dict[str, float] = {}
    if parent_hosts >= 2:
        components["parent_breadth"] = max(0.0, 1.0 - pair_hosts / parent_hosts)
    if child_hosts >= 2:
        components["child_breadth"] = max(0.0, 1.0 - pair_hosts / child_hosts)
    if not components:
        return None
    if child_given_parent is not None:
        components["child_surprisal"] = _surprisal(child_given_parent, config)

    return LineageScore(
        score=weighted_geometric_mean(components, _LINEAGE_WEIGHTS),
        components=components,
        parent_name=parent_name,
        child_name=name,
        child_path=child_path,
        pair_hosts=pair_hosts,
        pair_executions=pair_executions,
        parent_hosts=parent_hosts,
        child_hosts=child_hosts,
        estate_hosts=baseline.hosts,
        child_given_parent=child_given_parent,
        chain=chain,
        chain_truncated=chain_truncated,
        observed=observed,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def host_summary(frame: pl.DataFrame | pl.LazyFrame) -> pl.DataFrame:
    """Pass one, as a function: one row per (host, parent image, image).

    Public because `voidai doctor --telemetry` needs the same arithmetic the
    analyzer gated on, and a second implementation of it would eventually
    disagree — the defect `dnstunnel.registered_domain_expr` exists to
    prevent, one level up.
    """
    scan = frame.lazy() if isinstance(frame, pl.DataFrame) else frame
    return (
        scan.drop_nulls(subset=["ts", "host", "image"])
        .with_columns(
            _name_expr("image").alias("image_name"),
            _name_expr("parent_image").alias("parent_name"),
        )
        .group_by(["host", "parent_name", "image_name"])
        .agg(
            pl.len().alias("n"),
            pl.col("ts").min().alias("first_ts"),
            pl.col("ts").max().alias("last_ts"),
        )
        .collect(engine="streaming")
    )


def _presence(summary: pl.DataFrame) -> pl.DataFrame:
    """Hosts on which each image ran, counting both roles.

    An image that appears only as a *parent* still ran: its own creation
    record may predate the capture, or the sensor may have started after it.
    Counting one role would put `explorer.exe` on zero hosts in a window that
    opens after logon and make everything it spawns look unprecedented.
    """
    as_child = summary.select(pl.col("image_name").alias("name"), "host")
    as_parent = summary.drop_nulls("parent_name").select(
        pl.col("parent_name").alias("name"), "host"
    )
    return (
        pl.concat([as_child, as_parent], how="vertical")
        .group_by("name")
        .agg(pl.col("host").n_unique().alias("hosts"))
    )


def estate_baseline(summary: pl.DataFrame) -> EstateBaseline:
    """Describe the estate from the pass-1 summary.

    Takes the summary rather than the capture so that the figure an operator
    is shown and the figure the gate acted on are the same arithmetic over the
    same rows.
    """
    if summary.is_empty():
        return EstateBaseline(0, 0, 0, 0, 0.0)

    presence = _presence(summary)
    return EstateBaseline(
        hosts=int(summary["host"].n_unique()),
        executions=int(summary["n"].sum()),
        distinct_images=presence.height,
        singleton_images=int(presence.filter(pl.col("hosts") == 1).height),
        span_seconds=float(summary["last_ts"].max()) - float(summary["first_ts"].min()),
    )


def _prevalence_ceiling(threshold: float, weight: float) -> int:
    """Most hosts an image can run on and still reach `threshold`.

    Every other component is at most 1.0, so a score is bounded above by
    `rarity ** weight` — and because absent components only *raise* the
    prevalence weight when they renormalise, the nominal weight gives the
    loosest bound. Inverting `destination_rarity` at that bound gives the
    largest prevalence worth gathering arrays for, which is the same gate the
    scorer applies anyway, hoisted forward so pass 2 never collects a row
    destined to be rejected. The shape is `beaconing._candidates`.
    """
    if weight <= 0.0 or not 0.0 < threshold < 1.0:
        return 1 << 30
    rarity_floor = threshold ** (1.0 / weight)
    if rarity_floor <= 0.0:
        return 1 << 30
    return max(1, math.floor(1.0 / (rarity_floor * rarity_floor)))


class HostAnalyzer(BaseAnalyzer):
    """Emits `EXECUTES_RARE_PROCESS` and `EXHIBITS_ANOMALOUS_LINEAGE`."""

    name = "host"
    version = "0.1.0"

    def __init__(self, config: HostConfig | None = None) -> None:
        self.config = config or HostConfig()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Two streaming passes, then a bounded ancestry walk.

        Pass 1 groups the capture to one row per (host, parent, image) holding
        only scalars — a count and a first/last timestamp. That is enough to
        describe the whole estate and to decide which triples could possibly
        qualify, and it streams.

        Pass 2 re-scans and gathers arrays for the survivors alone, through a
        semi-join. Almost every triple is ordinary, so pass 2 collects a small
        fraction of the capture and peak memory tracks the number of
        *candidates* rather than the number of executions.

        The ancestry walk is a third stage rather than a third pass shape: it
        climbs at most `max_chain_depth` levels, and each level fetches only
        the process records whose GUIDs the level below asked for. Bounded by
        candidates times depth, not by the capture.
        """
        scan = ctx.process_scan().drop_nulls(subset=["ts", "host", "image"])
        scan = scan.with_columns(
            _name_expr("image").alias("image_name"),
            _name_expr("parent_image").alias("parent_name"),
        )

        summary = self._triple_summary(scan)
        if summary.is_empty():
            return []

        baseline = estate_baseline(summary)
        if baseline.gate(self.config) is not None:
            # The estate cannot support the claim. Rule 6's second level: the
            # verbs are unsayable, so nothing is said. `voidai doctor
            # --telemetry` prints the reason.
            return []

        images, pairs, presence, graph = self._distributions(summary)
        candidates = self._candidates(summary, images, pairs, presence)
        if candidates.is_empty():
            return []

        rows = self._collect_series(scan, candidates)
        if rows.is_empty():
            return []

        # Rare-process first, and lineage second: a binary the estate has
        # never run is claimed by the predicate that says so, and the edge it
        # arrived on is evidence inside that finding rather than a second one.
        # See `_subsume`.
        #
        # Both are scored in full before either is capped. Subsuming against
        # the *capped* list is a hole: a rare-process finding dropped by the
        # per-host ceiling stops suppressing its lineage twin, and the
        # duplicate the ceiling was meant to bound reappears under the other
        # predicate — as a second behaviour of the same host, which is the
        # promotion `_subsume` exists to prevent.
        process_scores = self._score_processes(rows, images, baseline)
        lineage_scores = self._score_lineage(
            rows, pairs, presence, graph, baseline, scan, _subsume(process_scores)
        )

        processes = self._cap(
            process_scores,
            key=lambda item: (str(item[1]["host"]), item[0].image_name, ""),
        )
        lineage = self._cap(
            lineage_scores,
            key=lambda item: (str(item[1]["host"]), item[0].child_name, item[0].parent_name),
        )
        return [self._process_finding(score, row) for score, row in processes] + [
            self._lineage_finding(score, row) for score, row in lineage
        ]

    # Pass 1: scalar summary per (host, parent, image)

    def _triple_summary(self, scan: pl.LazyFrame) -> pl.DataFrame:
        """One row per (host, parent image, image), carrying only scalars.

        Grouped at triple granularity rather than separately by image and by
        pair, so a single streaming aggregation answers both. The estate is
        described by re-aggregating this frame in memory, which is cheap
        because its height is the number of *distinct* lineage relationships
        rather than the number of executions.
        """
        return host_summary(scan)

    def _distributions(
        self, summary: pl.DataFrame
    ) -> tuple[pl.DataFrame, pl.DataFrame, dict[str, int], nx.DiGraph]:
        """Estate-wide prevalence per image and per edge, plus the lineage graph.

        The graph is the estate's observed lineage: one node per image name,
        one directed edge per parent→child relationship, weighted by how often
        it was seen. `P(child | parent)` comes off its out-strength, which is
        the measurement the roadmap asks for — parent-to-child pairs scored
        against observed frequency — expressed as the graph it is.

        `networkx` has been a core dependency since the beginning and this is
        the first place a directed one earns its keep. The second is
        `_ancestry`.
        """
        images = summary.group_by("image_name").agg(
            pl.col("host").n_unique().alias("image_hosts"),
            pl.col("n").sum().alias("image_executions"),
        )
        pairs = (
            summary.drop_nulls("parent_name")
            .group_by(["parent_name", "image_name"])
            .agg(
                pl.col("host").n_unique().alias("pair_hosts"),
                pl.col("n").sum().alias("pair_executions"),
            )
        )
        presence_frame = _presence(summary)
        presence = dict(
            zip(
                presence_frame["name"].to_list(),
                presence_frame["hosts"].to_list(),
                strict=True,
            )
        )

        graph = nx.DiGraph()
        for row in pairs.iter_rows(named=True):
            graph.add_edge(
                row["parent_name"],
                row["image_name"],
                weight=int(row["pair_executions"]),
                hosts=int(row["pair_hosts"]),
            )
        return images, pairs, presence, graph

    def _candidates(
        self,
        summary: pl.DataFrame,
        images: pl.DataFrame,
        pairs: pl.DataFrame,
        presence: dict[str, int],
    ) -> pl.DataFrame:
        """Triples that could still reach either threshold, on prevalence alone.

        Two hoisted gates, neither of them a guess.

        The rarity ceiling is derived from the threshold and the weight — see
        `_prevalence_ceiling`. The lineage gate is the weaker of the two
        breadths: a score is bounded above by `max(parent_breadth,
        child_breadth)` raised to its weight, so an edge seen on every host
        that runs either end cannot reach the threshold no matter what the
        frequency says. Both are gates the scorer applies anyway, hoisted
        forward so pass 2 never gathers arrays for a row destined to be
        rejected — the shape is `beaconing._candidates`.
        """
        image_ceiling = _prevalence_ceiling(
            self.config.score_threshold, _PROCESS_WEIGHTS["image_prevalence"]
        )
        breadth_floor = self.config.lineage_threshold ** (
            1.0 / _LINEAGE_WEIGHTS["parent_breadth"]
        )

        annotated = summary.join(images, on="image_name", how="left").join(
            pairs, on=["parent_name", "image_name"], how="left", nulls_equal=True
        )
        ends = pl.max_horizontal(
            pl.col("parent_name").replace_strict(presence, default=1, return_dtype=pl.Int64),
            pl.col("image_name").replace_strict(presence, default=1, return_dtype=pl.Int64),
        )
        return annotated.filter(
            (pl.col("image_hosts") <= image_ceiling)
            | (
                pl.col("pair_hosts").is_not_null()
                & ((1.0 - pl.col("pair_hosts") / ends) >= breadth_floor)
            )
        )

    # Pass 2: full arrays, candidates only

    def _collect_series(self, scan: pl.LazyFrame, candidates: pl.DataFrame) -> pl.DataFrame:
        """Gather executions, command lines and locators for candidates alone.

        `nulls_equal` is not optional. `parent_name` is null at the root of a
        process tree — a process whose parent started before the capture
        window — and a default join would silently drop exactly the rows a
        first execution on a freshly compromised host produces.

        Columns are sorted by `ts` inside the aggregation rather than the
        frame being globally sorted first, so the artifact locators stay
        aligned with the timestamps they describe without a full sort of the
        capture. The shape is `beaconing._collect_series`.
        """
        keys = candidates.select("host", "parent_name", "image_name")
        return (
            scan.join(keys.lazy(), on=["host", "parent_name", "image_name"], how="semi",
                      nulls_equal=True)
            .group_by(["host", "parent_name", "image_name"])
            .agg(
                pl.col("ts").sort_by("ts"),
                pl.col("image").sort_by("ts"),
                pl.col("command_line").sort_by("ts"),
                pl.col("parent_command_line").sort_by("ts"),
                pl.col("user").sort_by("ts"),
                pl.col("integrity_level").sort_by("ts"),
                pl.col("process_guid").sort_by("ts"),
                pl.col("parent_guid").sort_by("ts"),
                pl.col("sha256").sort_by("ts"),
                pl.col("source_file").sort_by("ts"),
                pl.col("source_line").sort_by("ts"),
                pl.len().alias("n"),
            )
            .collect(engine="streaming")
        )

    # Stage 3: bounded ancestry

    def _ancestry(self, scan: pl.LazyFrame, seeds: set[str]) -> nx.DiGraph:
        """Climb the process tree from a set of parent GUIDs, depth-bounded.

        Each level fetches only the records whose GUIDs the level below asked
        for, so the rows held are bounded by the number of candidates times
        the depth, not by the capture. The cost is one scan per level, which
        is the trade this makes deliberately: a process-creation log is dense
        in distinct subjects rather than in records, and holding a GUID map
        for the whole capture is what rule 3 exists to prevent.

        Returned as a `nx.DiGraph` of GUIDs so the walk in `_chain` is
        protected from a cycle. Duplicated GUIDs happen — a collector that
        replays a spool writes the same record twice — and a plain parent
        pointer chased in a loop does not terminate.
        """
        tree = nx.DiGraph()
        wanted = {guid for guid in seeds if guid}
        for _ in range(self.config.max_chain_depth):
            if not wanted:
                break
            level = (
                scan.filter(pl.col("process_guid").is_in(list(wanted)))
                .select("process_guid", "image_name", "parent_guid")
                .unique(subset=["process_guid"])
                .collect(engine="streaming")
            )
            if level.is_empty():
                break
            nxt: set[str] = set()
            for row in level.iter_rows(named=True):
                guid = str(row["process_guid"])
                tree.add_node(guid, image_name=row["image_name"])
                parent = row["parent_guid"]
                if parent:
                    tree.add_edge(str(parent), guid)
                    if str(parent) not in tree.nodes or "image_name" not in tree.nodes[str(parent)]:
                        nxt.add(str(parent))
            wanted = nxt - {n for n in tree.nodes if "image_name" in tree.nodes[n]}
        return tree

    def _chain(self, tree: nx.DiGraph, parent_guid: str | None) -> tuple[tuple[str, ...], bool]:
        """The ordered ancestry above a process, oldest first.

        Truncated when the walk runs out of depth or reaches a GUID the
        capture does not hold — a process whose parent started before the
        window. Both are reported, because a chain that stops because the
        capture stopped is not the same claim as one that stops at a root.
        """
        if not parent_guid or parent_guid not in tree.nodes:
            return (), True

        names: list[str] = []
        seen: set[str] = set()
        guid: str | None = parent_guid
        truncated = False
        while guid and guid not in seen and len(names) < self.config.max_chain_depth:
            seen.add(guid)
            attributes = tree.nodes.get(guid, {})
            name = attributes.get("image_name")
            if not name:
                truncated = True
                break
            names.append(str(name))
            predecessors = list(tree.predecessors(guid))
            guid = predecessors[0] if predecessors else None
            if guid is not None and guid not in tree.nodes:
                truncated = True
                break
        else:
            truncated = truncated or guid is not None
        return tuple(reversed(names)), truncated

    # Scoring

    def _score_lineage(
        self,
        rows: pl.DataFrame,
        pairs: pl.DataFrame,
        presence: dict[str, int],
        graph: nx.DiGraph,
        baseline: EstateBaseline,
        scan: pl.LazyFrame,
        claimed: set[tuple[str, str]],
    ) -> list[tuple[LineageScore, dict[str, object]]]:
        lookup = {
            (row["parent_name"], row["image_name"]): row for row in pairs.iter_rows(named=True)
        }
        parented = [
            row
            for row in rows.iter_rows(named=True)
            if row["parent_name"]
            and (str(row["host"]), str(row["image_name"])) not in claimed
        ]
        seeds = {str(guid) for row in parented for guid in row["parent_guid"] if guid}
        tree = self._ancestry(scan, seeds) if seeds else nx.DiGraph()

        scored: list[tuple[LineageScore, dict[str, object]]] = []
        for row in parented:
            parent, child = str(row["parent_name"]), str(row["image_name"])
            stats = lookup.get((parent, child))
            if stats is None:
                continue
            chain, truncated = self._chain(tree, _first(row["parent_guid"]))
            score = score_lineage(
                child_path=str(_first(row["image"]) or child),
                parent_name=parent,
                pair_hosts=int(stats["pair_hosts"]),
                pair_executions=int(stats["pair_executions"]),
                parent_hosts=presence.get(parent, 1),
                child_hosts=presence.get(child, 1),
                child_given_parent=_conditional(graph, parent, child, self.config),
                chain=chain,
                chain_truncated=truncated,
                observed=int(row["n"]),
                baseline=baseline,
                config=self.config,
                first_seen=float(min(row["ts"])),
                last_seen=float(max(row["ts"])),
            )
            if score is not None and score.score >= self.config.lineage_threshold:
                scored.append((score, row))

        return scored

    def _score_processes(
        self,
        rows: pl.DataFrame,
        images: pl.DataFrame,
        baseline: EstateBaseline,
    ) -> list[tuple[ProcessScore, dict[str, object]]]:
        """Score (host, image).

        Rows arrive keyed by (host, parent, image) because that is what pass 2
        groups by, and an image with two parents is two rows describing one
        image on one host. They are merged here so the finding says "this host
        ran this binary" once, rather than once per parent.
        """
        lookup = {row["image_name"]: row for row in images.iter_rows(named=True)}
        merged: dict[tuple[str, str], dict[str, object]] = {}
        for row in rows.iter_rows(named=True):
            key = (str(row["host"]), str(row["image_name"]))
            existing = merged.get(key)
            merged[key] = row if existing is None else _merge(existing, row)

        scored: list[tuple[ProcessScore, dict[str, object]]] = []
        for (_host, name), row in merged.items():
            stats = lookup.get(name)
            if stats is None:
                continue
            score = score_process(
                image_path=str(_first(row["image"]) or name),
                hosts_running=int(stats["image_hosts"]),
                executions=int(stats["image_executions"]),
                observed=int(row["n"]),
                baseline=baseline,
                config=self.config,
                first_seen=float(min(row["ts"])),
                last_seen=float(max(row["ts"])),
            )
            if score is not None and score.score >= self.config.score_threshold:
                scored.append((score, row))

        return scored

    def _cap(
        self,
        scored: list[tuple[_Score, dict[str, object]]],
        key: Callable[[tuple[_Score, dict[str, object]]], tuple[str, ...]],
    ) -> list[tuple[_Score, dict[str, object]]]:
        """Sort by score under a total order, then cap per host and overall.

        Roadmap rule 12, and this telemetry is where it bites hardest: an
        estate of `svchost.exe` sits at an identical prevalence, and hundreds
        of command lines are byte-identical. With score alone as the key the
        `group_by` result order decides which findings survive the cap, and it
        is not stable across input orderings. The tiebreak is the host and the
        two image names, which together identify the row.

        The per-host cap runs first, so one compromised machine running a
        thousand distinct binaries cannot crowd every other host out of the
        budget (rule 4).
        """
        ordered = sorted(scored, key=lambda item: (-item[0].score, *key(item)))

        per_host: dict[str, int] = {}
        kept: list[tuple[_Score, dict[str, object]]] = []
        for item in ordered:
            host = str(item[1]["host"])
            if per_host.get(host, 0) >= self.config.max_findings_per_host:
                continue
            per_host[host] = per_host.get(host, 0) + 1
            kept.append(item)
            if len(kept) >= self.config.max_findings:
                break
        return kept

    # Lexicon

    def _artifacts(self, row: dict[str, object], count: int) -> list[Artifact]:
        """Spread-out representatives: the first execution, the last, and between."""
        timestamps = row["ts"]
        files, lines = row["source_file"], row["source_line"]
        commands, images = row["command_line"], row["image"]

        wanted = min(self.config.artifact_samples, count)
        if wanted <= 1:
            indices = [0]
        else:
            step = (count - 1) / (wanted - 1)
            indices = sorted({round(i * step) for i in range(wanted)})

        artifacts: list[Artifact] = []
        for index in indices:
            source = files[index] if index < len(files) and files[index] else "<unknown>"
            line = lines[index] if index < len(lines) and lines[index] is not None else index
            command = commands[index] if index < len(commands) and commands[index] else ""
            artifacts.append(
                Artifact(
                    source=str(source),
                    locator=f"line:{line}",
                    observed_at=datetime.fromtimestamp(float(timestamps[index]), tz=timezone.utc),
                    excerpt=f"{row['parent_name'] or '<no parent>'} -> "
                    f"{images[index]} {command}".strip(),
                )
            )
        return artifacts

    def _process_finding(self, score: ProcessScore, row: dict[str, object]) -> Finding:
        artifacts = self._artifacts(row, int(row["n"]))
        evidence = [
            Evidence(
                kind="image_prevalence",
                summary=(
                    f"{score.image_name} ran {score.executions} time(s) on "
                    f"{score.hosts_running} of {score.estate_hosts} hosts, "
                    f"{score.observed} of them on this one"
                ),
                payload={
                    "image": score.image_path,
                    "image_name": score.image_name,
                    "hosts_running": score.hosts_running,
                    "estate_hosts": score.estate_hosts,
                    "estate_executions": score.executions,
                    "executions_here": score.observed,
                    "components": {k: round(v, 4) for k, v in sorted(score.components.items())},
                    "command_lines": _sample_commands(row),
                    "sha256": _first(row["sha256"]),
                    "user": _first(row["user"]),
                    "integrity_level": _first(row["integrity_level"]),
                },
                artifacts=artifacts,
            )
        ]
        return Finding(
            predicate=Predicate.EXECUTES_RARE_PROCESS,
            subject=Entity(type=EntityType.HOST, value=str(row["host"])),
            object=Entity(type=EntityType.PROCESS, value=score.image_name),
            evidence=evidence,
            confidence=round(score.score, 4),
            basis=score.basis(),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )

    def _lineage_finding(self, score: LineageScore, row: dict[str, object]) -> Finding:
        artifacts = self._artifacts(row, int(row["n"]))
        evidence = [
            Evidence(
                kind="process_lineage",
                summary=(
                    f"{score.chain_text()} seen on {score.pair_hosts} of "
                    f"{score.estate_hosts} hosts, against {score.parent_hosts} running "
                    f"{score.parent_name} and {score.child_hosts} running "
                    f"{score.child_name}"
                ),
                payload={
                    "parent_image": score.parent_name,
                    "child_image": score.child_name,
                    "child_path": score.child_path,
                    "chain": [*score.chain, score.child_name],
                    "chain_truncated": score.chain_truncated,
                    "pair_hosts": score.pair_hosts,
                    "parent_hosts": score.parent_hosts,
                    "child_hosts": score.child_hosts,
                    "estate_hosts": score.estate_hosts,
                    "pair_executions": score.pair_executions,
                    "executions_here": score.observed,
                    "p_child_given_parent": (
                        round(score.child_given_parent, 5)
                        if score.child_given_parent is not None
                        else None
                    ),
                    "components": {k: round(v, 4) for k, v in sorted(score.components.items())},
                    "command_lines": _sample_commands(row),
                    "parent_command_line": _first(row["parent_command_line"]),
                    "sha256": _first(row["sha256"]),
                    "user": _first(row["user"]),
                },
                artifacts=artifacts,
            )
        ]
        return Finding(
            predicate=Predicate.EXHIBITS_ANOMALOUS_LINEAGE,
            subject=Entity(type=EntityType.HOST, value=str(row["host"])),
            object=Entity(type=EntityType.PROCESS, value=score.child_name),
            evidence=evidence,
            confidence=round(score.score, 4),
            basis=score.basis(),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )


def _name_expr(column: str) -> pl.Expr:
    """`image_name`, as a pushed-down Polars expression.

    Kept in step with the Python `image_name` by
    `tests/test_host.py::test_the_two_normalisers_agree` — two spellings of
    one rule that disagreed would split an image two ways in one analyzer,
    which is the defect `dnstunnel.registered_domain_expr` guards against.
    """
    return (
        pl.col(column)
        .str.replace_all("/", "\\", literal=True)
        .str.strip_chars_end("\\")
        .str.to_lowercase()
        .str.extract(r"([^\\]+)$", 1)
        .replace("", None)
    )


def _conditional(graph: nx.DiGraph, parent: str, child: str, config: HostConfig) -> float | None:
    """P(child | parent) from the lineage graph's out-strength, or None.

    Returns None — not 1.0 — when the parent has spawned too little for a
    frequency to mean anything. An application observed launching one process
    has launched 100% of its children exactly once, and 1.0 there is not the
    observation "this is what it always does"; it is an artefact of the sample
    size. Rule 6's first level, and the same shape as `robust_deviation`
    refusing a baseline of two points.
    """
    if not graph.has_edge(parent, child):
        return None
    total = sum(data["weight"] for _, _, data in graph.out_edges(parent, data=True))
    if total < config.min_frequency_samples:
        return None
    return graph[parent][child]["weight"] / total


def _subsume(
    processes: list[tuple[ProcessScore, dict[str, object]]],
) -> set[tuple[str, str]]:
    """(host, image) pairs the rare-process claim has already taken.

    One process creation can look like both predicates at once, and reported
    as two findings it becomes two independent behaviours of the host — the
    corroboration multiplier promoting an incident for one event observed
    twice. That is the argument that keeps `presents_rare_tls_fingerprint` out
    of the count, applied inside this analyzer instead.

    It has to be here rather than in the correlator. `correlate.incidents`
    sees two findings about one host and cannot know they describe a single
    execution; the analyzer that produced both knows exactly.

    Rare-process wins, which is not the "higher severity wins" rule it might
    look like — `exhibits_anomalous_lineage` is the HIGH one. It wins because
    it is the claim that identifies what is actually unusual. A binary the
    estate has never run trivially arrives on an edge the estate has never
    seen, so the lineage sentence is true and says nothing the rarity sentence
    did not; the reverse is not true, since `winword.exe -> cmd.exe` is
    anomalous with both ends entirely ordinary.

    Mostly a guarantee rather than a mechanism: `score_lineage`'s breadths are
    conditional on each end being widespread, so a novel child already scores
    near zero on them. This closes the gap where a child on two hosts could
    score enough breadth to slip through.
    """
    return {(str(row["host"]), score.image_name) for score, row in processes}


def _merge(left: dict[str, object], right: dict[str, object]) -> dict[str, object]:
    """Combine two pass-2 rows for one (host, image) under different parents."""
    merged = dict(left)
    for column in (
        "ts",
        "image",
        "command_line",
        "parent_command_line",
        "user",
        "integrity_level",
        "process_guid",
        "parent_guid",
        "sha256",
        "source_file",
        "source_line",
    ):
        merged[column] = list(left[column]) + list(right[column])  # type: ignore[call-overload]
    merged["n"] = int(left["n"]) + int(right["n"])  # type: ignore[call-overload]
    order = sorted(range(len(merged["ts"])), key=lambda i: merged["ts"][i])  # type: ignore[index, arg-type]
    for column in (
        "ts",
        "image",
        "command_line",
        "parent_command_line",
        "user",
        "integrity_level",
        "process_guid",
        "parent_guid",
        "sha256",
        "source_file",
        "source_line",
    ):
        merged[column] = [merged[column][i] for i in order]  # type: ignore[index]
    return merged


def _first(values: object) -> str | None:
    """The first non-empty entry of a pass-2 list column.

    Every column this is applied to holds strings — an image path, a hash, a
    user, a GUID — so the return type is narrowed here rather than left as
    `object` for each caller to widen something else by accident.
    """
    if not isinstance(values, (list, tuple)):
        return None
    for value in values:
        if value:
            return str(value)
    return None


def _sample_commands(row: dict[str, object], limit: int = 3) -> list[str]:
    """Distinct command lines, for the payload rather than for the score.

    See the module docstring: entropy was measured and removed, and length
    against a global constant is a drag rather than a signal. The command line
    is still the first thing an analyst reads, so it is carried here.
    """
    seen: list[str] = []
    for command in row["command_line"]:  # type: ignore[attr-defined]
        if command and command not in seen:
            seen.append(str(command))
        if len(seen) >= limit:
            break
    return seen
