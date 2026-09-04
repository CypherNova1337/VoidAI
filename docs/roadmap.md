# Roadmap — filling in the Lexicon

Eighteen predicates are declared. Four have an analyzer that emits them. The
vocabulary is ahead of the code on purpose: the grammar was written for the
system VoidAI is meant to become, and the remaining fourteen predicates are the
work list.

```
18 predicates declared · 4 analyzers built · 14 predicates unclaimed
```

This document is the plan for the other fourteen. Each section is a self-contained
unit of work sized to one branch, and they are ordered by ratio of value
to lift. **Take one. Do not take two.**

---

## The rules every one of these follows

Learned the hard way, in this repository, mostly from being wrong first. They are
not negotiable and none of them is stylistic.

**1 · Add analyzers, never a second tool.** A new analyzer is one file in
`src/voidai/analyzers/` plus one line in `DEFAULT_ANALYZERS`. It then inherits the
Lexicon, chain of custody, correlation, ranking, run receipt, hunt-query generation,
CLI and language layer unchanged. A separate tool inherits none of it and has to be
merged later.

**2 · Peak memory is `max(analyzers)`, not `sum(analyzers)`.** Measured: the four
existing analyzers run together peak at 521 MB, against 1,035 MB if it were
additive, because they run sequentially and release. Adding analyzers is therefore
close to free on the constraint that decides whether this runs on a Pi. That holds
only while each analyzer individually behaves — see rule 3.

**3 · Two passes, always.** Pass one computes scalars per group and stays streaming.
Pass two collects full arrays for candidates only, via a semi-join. Copy
`_pair_summary` and `_collect_series` from `beaconing.py`. An analyzer that
materialises a capture will be the one that breaks the 4 GB board.

**4 · Cap what you emit.** `max_findings` exists on every analyzer for a reason.
Findings from all analyzers accumulate into one list, and a low-severity predicate
over a large estate can emit thousands. The project exists to *prevent* alert
floods; do not add one.

**5 · Weighted geometric mean, never an average.** An average lets one strong
signal carry a detection alone — that is how a software updater gets reported as
C2. Absent components renormalise the remaining weights.

**6 · Absent is not zero.** Two separate bugs here came from conflating "the sensor
did not record this" with "the sensor recorded 0". If a field is unavailable, omit
the component and let the weights renormalise. Never substitute a value.

**7 · Say which half of your validation is synthetic.** Synthetic data validates
your assumptions, not your detector — you built both from the same beliefs. If only
specificity is measured on real traffic, the docs say exactly that, in the same
sentence as the result.

**8 · Test the intent, not the implementation.** After writing a regression test,
break the fix and confirm the test fails. There was a test here named
`test_all_zero_values_are_not_treated_as_regular` that asserted the exact opposite
of its own name and guarded nothing for weeks.

**9 · No new core dependency.** Six, no compiler, every one has an `aarch64` wheel.
Anything needing a dissector or a build step goes behind an extra, like `[llm]` and
`[tui]` already do.

**10 · No execution path.** VoidAI proposes; a human disposes. Never add code that
blocks an address, kills a process or edits a rule. Enforced by absence.

**11 · No network at runtime.** Not for intel feeds, not for enrichment, not for
model downloads. The test suite severs sockets and asserts the pipeline still
completes.

---

## 1 · Volume and egress — `analyzer-egress`

**Start here.** Three predicates, no new parser, and CTU-13 validates it the day
it is written.

**Claims** `exfiltrates_to` (critical) · `transfers_anomalous_volume` (medium) ·
`contacts_rare_destination` (low)

**Input** `conn.log` and NetFlow. Both already parsed. Fields already present:
`ts`, `src_ip`, `dst_ip`, `dst_port`, `orig_bytes`, `resp_bytes`.

### Signals

| Component | Measure | Weight |
|---|---|---|
| `egress_ratio` | `orig_bytes / (orig_bytes + resp_bytes)` — pushing out, not pulling in | 0.30 |
| `volume_deviation` | Robust deviation (MAD) of bytes to this destination against the host's own distribution across all destinations | 0.28 |
| `destination_rarity` | Estate-wide prevalence — reuse `destination_rarity()` | 0.24 |
| `novelty` | Destination unseen from this host before the transfer window | 0.18 |

### The trap that will bite you

**NetFlow has no directional byte counts.** `ingest/netflow.py` records total flow
bytes as `orig_bytes` because that is the only figure available, and says so in a
comment. On NetFlow, `egress_ratio` is therefore *unavailable*, not zero and not
0.5. Omit the component and let the remaining weights renormalise. Getting this
wrong reproduces bug 6 above for the third time.

**`contacts_rare_destination` is an alert flood waiting to happen.** It is LOW
severity and fires on a single cheap signal, so over a real estate it can emit
thousands. Gate it hard: minimum byte volume, minimum flow count, and a tight
`max_findings`. Consider emitting it *only* when it corroborates something else.

**Backups and cloud sync look exactly like exfiltration.** High egress ratio, large
volume, regular schedule. `destination_rarity` is what separates them, so do not
let it be the lightest weight.

### Validation

CTU-13 has per-flow ground truth and is already wired into `voidai bench --real`.
Real sensitivity *and* specificity are both measurable here, which is rare — say so.

### Done when

`egress.py`, tests including a NetFlow-shaped context that asserts the ratio
component is omitted rather than defaulted, one line in `DEFAULT_ANALYZERS`, a
`benchmarks.md` section with CTU-13 numbers, README table row.

---

## 2 · Threat intel — `analyzer-intel`

Cheapest cluster in the list. A short piece of work.

**Claims** `matches_threat_intel` (medium, unary) · `shares_infrastructure_with` (info)

**Input** Local IOC files supplied by the operator. Plain newline lists first;
MISP JSON and STIX later if wanted.

### Design

This one is not statistics, it is a join, and that changes the shape. A match is
binary — do not manufacture a geometric mean to make it look like the others.
Confidence should come from properties of the *feed*: its declared confidence, and
the age of the indicator. An indicator with no provenance gets low confidence, not
a default.

`shares_infrastructure_with` is a graph problem and `networkx` is already a core
dependency: link two domains that resolve to the same address, or two addresses in
the same netblock, using resolution data VoidAI already ingests.

### The trap that will bite you

**No network at runtime.** This is the cluster most likely to tempt someone into
fetching a feed. Do not. IOC sets are files the operator places on disk; VoidAI
reads them and never retrieves them. Rule 11 is asserted by the test suite.

**Stale intel is worse than none.** An indicator from 2019 firing on a residential
IP that was reassigned years ago is a false positive with a confident citation
attached. Record the indicator's age in the evidence payload and let it attenuate
confidence.

### Validation

Synthetic, and honestly labelled as such — the correctness question here is
integration, not detection. A fixture with a handful of indicators is sufficient.

### Done when

`intel.py`, a documented IOC file format, an offline test asserting no fetch is
attempted, registry line, docs.

---

## 3 · TLS and DGA — `analyzer-tlsdga`

Reuses most of the entropy machinery already written for DNS tunnelling.

**Claims** `resolves_algorithmic_domain` (medium) · `presents_rare_tls_fingerprint` (medium)

**Input** `dns.log` — already parsed — for DGA. A small new `ssl.log` parser for
JA3/JA3S fingerprints.

### Signals — DGA

| Component | Measure | Weight |
|---|---|---|
| `nxdomain_rate` | Share of the host's queries under this pattern that fail to resolve | 0.34 |
| `label_entropy` | Shannon entropy of the second-level label — `shannon_entropy()` exists | 0.26 |
| `bigram_improbability` | Character-pair likelihood against a small embedded table of real domain bigrams | 0.24 |
| `structure` | Digit ratio, consonant runs, length uniformity across the family | 0.16 |

`nxdomain_rate` carries the most weight because it is the signal a DGA cannot
avoid: the algorithm generates many names and only the registered one resolves.

### The trap that will bite you

**`rcode` is in `dns.log` but not in passivedns.** The strongest signal is
unavailable on the passivedns corpus used for the existing real-data specificity
test. Omit and renormalise — and note in the docs that DGA specificity on that
fixture is measured *without* its best component, which makes the result
conservative rather than optimistic.

**JA3 is not in `ssl.log` by default.** It requires the JA3 Zeek script to be
loaded. Detect its absence and degrade cleanly rather than emitting an empty
analyzer; `voidai doctor` should report it.

**CDN and cloud hostnames look algorithmic.** This is the same trap DNS tunnelling
already navigated. Run against `tests/data/real.passivedns` early and often — it
contains exactly the Akamai chains and reputation lookups that produce false
positives.

### Validation

Public DGA name lists give real sensitivity for the domain-generation half.
Specificity comes from the existing real passivedns corpus. TLS fingerprint
rarity is synthetic only unless a real `ssl.log` corpus turns up — say which is
which.

---

## 4 · Temporal ordering — `analyzer-precedes`

No parser, no telemetry, no new dependency. It operates on findings that already
exist and makes the narrative substantially better.

**Claims** `precedes` (info)

### Design

Within one incident, order findings by first-observed time and emit `precedes`
between adjacent behaviours, so the language layer can narrate a sequence — scan,
then beacon, then transfer — instead of an unordered set. This is correlator-side
work in `correlate/incidents.py`, not a conventional analyzer.

### The trap that will bite you

**`precedes` must never count toward corroboration.** `CorrelationConfig` already
carries a set of predicates that contribute evidence without counting as
independent behaviours, and `precedes` belongs in it. Miss this and every incident
inflates its own ranking by describing itself, which defeats the mechanism that
took the CTU-13 true positive from rank 358 to rank 1.

**Timestamps come from sensors that disagree.** Two log sources on one host can be
seconds or hours apart. Require a minimum separation before asserting order, and
record the separation in the evidence payload so a reader can judge it.

---

## 5 · Host and endpoint — `analyzer-host`

The highest-value cluster and the largest lift. Four predicates, a new telemetry
family, and the biggest payoff for corroboration ranking — a host that beacons
*and* spawns an anomalous child process is precisely what the noisy-OR was built
to surface.

**Claims** `executes_rare_process` (medium) · `exhibits_anomalous_lineage` (high) ·
`establishes_persistence` (high) · `authentication_anomaly` (medium)

**Input** New parser. Start with Sysmon exported as JSON lines to defer EVTX
parsing entirely; add EVTX behind an extra afterwards. `python-evtx` is pure
Python and so Pi-safe, but it is still a new dependency and belongs in an extra.

### Signals

- **`executes_rare_process`** — estate-wide image prevalence (the same rarity curve
  used for destinations and signatures), path anomaly (execution from a temp or
  user-writable directory), and command-line length and entropy.
- **`exhibits_anomalous_lineage`** — parent-to-child pairs scored against observed
  frequency across the estate. A graph problem; `networkx` is already core.
- **`establishes_persistence`** — event-driven rather than statistical: Run keys,
  scheduled tasks, service creation. Closer to alert triage in shape.
- **`authentication_anomaly`** — failure-to-success ratio, first-seen source for an
  account, and one account touching many hosts in a short window.

### The trap that will bite you

**Rarity needs an estate.** Every "rare process" signal degenerates on a single
host, where everything is rare exactly once. Gate on a minimum host count and say
so, rather than emitting nonsense on a one-machine capture.

**This is four predicates, which is four analyzers wearing a trenchcoat.** Split
the work: `executes_rare_process` and `exhibits_anomalous_lineage` share a parser
and a baseline and belong together. `authentication_anomaly` is separate work.

### Validation

Public labelled EVTX corpora exist — the OTRF Security-Datasets and
EVTX-ATTACK-SAMPLES collections carry real attack telemetry. Verify licensing
before vendoring anything, and attribute it the way `tests/data/real.passivedns`
already is.

---

## 6 · Web — `analyzer-web`

Listed last deliberately. It is the least novel cluster — the space is crowded
with mature tools — and the one where VoidAI's architecture adds least.

**Claims** `attacks_web_endpoint` (high) · `enumerates_web_paths` (low)

**Input** New parser for nginx and Apache combined log format; Zeek `http.log`
optionally.

### Design

`enumerates_web_paths` transfers almost directly from the fan-out analyzer: path
breadth against revisit rate, plus 404 ratio and request regularity. The insight
that made fan-out work — browsing revisits, enumeration does not — applies
unchanged to paths instead of destinations.

`attacks_web_endpoint` is pattern-driven, which puts it in the same category as
alert triage. Cap its severity the way `alerts.py` does, for the same reason: a
signature firing is corroborating evidence, not a conclusion.

### The trap that will bite you

**Do not build a worse WAF.** If the design drifts toward a rule list, stop. The
part worth having is the statistical half — parameter count and length against an
endpoint's own baseline, encoding depth, path enumeration behaviour — because that
is what existing tools do badly.

**The negation trap.** Any category or rule-name matching repeats the
`"Not Suspicious Traffic"` bug unless negations are matched first. Read the
`_NEGATIVE` table in `alerts.py` before writing a matcher.

### Validation

The CSIC 2010 HTTP dataset is public and labelled. Verify its licence before
vendoring.

---

## Suggested order

| | Cluster | Lift | Why this position |
|---|---|---|---|
| 1 | Volume and egress | Low | No new parser; CTU-13 gives real sensitivity and specificity immediately |
| 2 | Threat intel | Low | Cheapest; mostly integration |
| 3 | TLS and DGA | Medium | Small parser; reuses existing entropy work |
| 4 | Temporal ordering | Low | No parser at all; markedly improves the narrative |
| 5 | Host and endpoint | High | Biggest corroboration payoff, biggest lift — split it up |
| 6 | Web | Medium | Least novel; do last, or not at all |

---

## Working on one

Each cluster gets its own branch, named `CN/analyzer-<cluster>`. Do not push to
`main` without asking — `main` and the working branch are reconciled and should
stay that way.

Before writing any code, establish two things and write both down:

**What the repository already does.** Most of these clusters reuse machinery that
exists — the rarity curve, the entropy functions, the two-pass streaming pattern,
the geometric mean. Read `src/voidai/analyzers/` before adding to it.

**Whether a real, openly-licensed corpus exists for this cluster.** That answer
decides whether the finished analyzer can claim sensitivity or only specificity,
and it belongs in the documentation either way. Deciding it afterwards is how a
synthetic result quietly gets written up as a real one.

Then work the section's plan: claim only its predicates, use its signals, and take
its listed traps seriously. Each one is a bug that already happened in this
repository or a close relative of one.

Anything cross-cutting — a change to the Lexicon, to correlation behaviour, or to
a shared rule above — affects every other cluster and should be settled before it
is built, not after.
