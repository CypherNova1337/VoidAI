# Roadmap — filling in the Lexicon

Eighteen predicates are declared. Fourteen have something that emits them. The
vocabulary is ahead of the code on purpose: the grammar was written for the
system VoidAI is meant to become, and the remaining four predicates are the
work list.

```
18 predicates declared · 8 analyzers built · 4 predicates unclaimed
```

Fourteen rather than thirteen, and eight analyzers rather than nine:
`precedes` is emitted by the correlator, which is why cluster 4 below is the
one entry here that adds no file to `analyzers/`.

This document is the plan for the rest. Each section is a self-contained
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

**6 · A claim is bounded by what was measured, not by what the survivors
score.** Three separate bugs here came from partial evidence producing a
whole-strength assertion. It applies at three levels, and getting one right
does not get the others right.

*The component.* If a field is unavailable, omit it and let the weights
renormalise. Never substitute a value — not zero, not a midpoint, not the
value that happens to reproduce the right answer.

*The predicate.* If the signal that defines a verb is unavailable, that verb
is unsayable. `exfiltrates_to` means "anomalous outbound volume"; with no
directional bytes, emit `transfers_anomalous_volume`, which claims only what
was seen.

*The corroboration.* A finding resting on partial evidence may be reported,
but must not count as an independent behaviour. Put it in
`CorrelationConfig.non_corroborating`. Measured on CTU-13: letting a
direction-blind volume finding corroborate moved the infected host from rank 2
to rank 5 and took corroborated incidents from 3 to 33, while contributing no
evidence on the true positive at all.

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

**12 · A top-N over equal scores needs a total order.** Ranking, capping and
sampling all pick a few items out of many, and ties are not rare — a generated
domain family produces hundreds of names scoring an identical 1.0. With no
tiebreaker, `group_by` ordering decides which ones are reported, so two runs
over one capture return different findings and therefore different
content-addressed IDs. Reproducibility is a promise this project makes on its
front page: citations in last month's report still resolve. Sort by score *and*
by a stable key — the subject and object values will do — everywhere a limit is
applied.

Printing the findings twice and diffing finds it, but weakly: the same input in
the same order can hide an ordering that depends on the input. Shuffle the row
order of the input frame and assert the output is identical — that is what
catches a `group_by` whose result order leaks into a top-N.

**13 · Say why a row is in the queue.** Every incident the operator sees must
name what put it there. Five predicates no longer corroborate, and a display
built only from corroborating ones printed a severity, a priority and a blank
reason for any incident made entirely of the rest. An analyst cannot triage a
row that will not say why it exists.

---

## 1 · Volume and egress — `analyzer-egress`

> **Done.** `src/voidai/analyzers/egress.py`, registered, tested, and scored
> against a seeded synthetic corpus — 4 of 4 planted transfers, one false
> positive on a backup target only one machine uses. On CTU-13 the infected
> host holds rank 2 of 247 on scenario 3 and rank 1 on scenario 6, with
> corroborated incidents unchanged at 3 and 1. **Accuracy is synthetic and
> ranking is real**; the corpus labels spam and scanning rather than
> transfers, so it offers no precision figure for a volume detector.
>
> The trap below turned out to have three levels rather than one, and rule 6
> was rewritten because of it — read the rule before the section.
> `docs/benchmarks.md` §7 has the account. Everything below stands as the
> record of what was designed and why.

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
0.5. Omit the component and let the remaining weights renormalise.

That is rule 6's first level, and it is the level everyone gets right. The
second and third are what this cluster cost: with the ratio omitted,
`exfiltrates_to` is unsayable — the verb means *outbound* — and the
`transfers_anomalous_volume` you emit instead must not corroborate, because it
rests on partial evidence. Both were measured on CTU-13 rather than reasoned
about, and both were wrong on the first attempt.

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

> **Done.** `src/voidai/analyzers/intel.py` and `src/voidai/ingest/ioc.py`,
> registered, documented in `docs/ioc.md`, and covered by 63 tests. Validation
> is **synthetic and there is no detection rate to measure** — by
> construction, not for want of a corpus: the detection was performed by
> whoever wrote the feed, and what is scorable is whether the join is correct
> and whether the claim is bounded by what the file said.
>
> It was the cheapest cluster as predicted, and the two things that took the
> time were not the join. The first was rule 6 with no weights to
> renormalise — see below. The second was that both flood mechanisms only
> became visible by printing the findings and reading them, which is worth
> doing before writing the tests rather than after.
>
> One cross-cutting question came out of it and is deliberately **not**
> settled here: `matches_threat_intel` is unary and its subject is the
> indicator, so an intel hit forms its own incident instead of corroborating
> the host that contacted it. That is correlator-side and belongs with
> cluster 4. `docs/benchmarks.md` §8 has the account.

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

### What it cost, for whoever takes the next one

**Rule 6 had to be re-derived, because there are no weights here.** The rule
is written for a geometric mean: drop the component, renormalise. This
analyzer's confidence is a product of a declared value and a decay, and the
same principle lands in two different places. A feed declaring no confidence
scores at an explicit unprovenanced floor. An indicator with no *date* is the
one that bites: the obvious handling is a decay of 1.0, and it fails in the
flattering direction — an undated indicator would outscore a dated one a month
old, rewarding the feed that recorded less. The confidence is **capped**
instead. A cap says the claim cannot be made strongly; a substituted age says
the indicator is fresh, which nobody measured.

**Age must be measured against the capture, not the clock.** Not only because
it is the right question — how stale was the intelligence when the traffic
happened — but because every ID in the Lexicon is content-addressed. A
wall-clock `age_days` in an evidence payload gives the same run a different
evidence ID every day, and last week's citations resolve to nothing. Note that
a test asserting "two runs produce the same IDs" does **not** catch this: the
two runs are seconds apart and agree about today. The assertion that catches
it needs two captures ninety days apart to disagree by ninety days.

**Both flood mechanisms were found by reading the output, not by reasoning.**
A parent-domain indicator emitted one finding per subdomain, so one wildcarded
feed entry became forty findings about one fact. And
`shares_infrastructure_with` linked five addresses inside one `/24` entry to
each other — reporting the operator's own file back to them as a discovery.
Both are obvious once printed and neither was predicted. Print the findings
before writing the tests.

**`max_age_days` and `min_confidence` overlap, and a test can name the wrong
one.** At default settings the decay pushes anything past two years under the
floor before the hard cut is reached, so a test asserting "an ancient
indicator produces nothing" passes with `max_age_days` deleted. It names one
mechanism and guards another — rule 8 exactly. Disable the floor in that test
to isolate the cut, and assert the floor separately.

---

## 3 · TLS and DGA — `analyzer-tlsdga`

> **Done.** `src/voidai/analyzers/tlsdga.py` and
> `src/voidai/analyzers/ngrams.py`, plus an `ssl.log` parser, registered,
> wired into `voidai demo`, `voidai bench` and `voidai doctor --telemetry`,
> and covered by 58 tests. DGA specificity is **real** — zero findings across
> `tests/data/real.passivedns`, measured without its heaviest component
> because that corpus carries no `rcode`. DGA sensitivity is **synthetic**:
> 3 of 4 planted families, the fourth a dictionary generator counted as a
> miss rather than excluded. TLS fingerprint rarity is **synthetic on both
> sides** — no openly-licensed `ssl.log` carrying JA3 was reachable.
> `docs/benchmarks.md` §9 has the account.
>
> **The first line below is wrong, and that is the cluster's main finding.**
> It does not reuse the entropy machinery, because entropy does not work at
> second-level-label length — read §9 before the signal table. Everything
> below stands as the record of what was planned.

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

### What it cost, for whoever takes the next one

**The prescribed signal was measured and removed.** `label_entropy` at 0.26
was the second-heaviest component in the table above. Per-character Shannon
entropy is bounded by `log2(len)`, and a second-level label is 6 to 20
characters, so it measures length rather than randomness: real labels average
0.855 of their maximum against 0.893 for random strings — and 0.807 for hex,
which means the component scores an encoded family as *more natural* than
`googleapis`. It was replaced by a bigram model, not down-weighted. Rules 5
and 6 are about what a component may claim; this is the prior question of
whether it measures anything, and the table above did not settle it.

**An embedded table of hand-written frequencies would have been fabricated
precision.** The plan said "a small embedded table of real domain bigrams".
1,369 letter-pair probabilities written from memory are three significant
figures of invention. `ngrams.py` embeds 1,233 ordinary English words and
derives the table from them at import — a datum that can be checked by eye,
and arithmetic on top of it. Brand names are excluded because the corpus that
measures specificity is full of them, and a model fitted to its own validation
set measures nothing.

**A synthetic corpus that cannot choose between two settings has validated
neither.** Every threshold from 0.35 to 0.85 gives identical results on
`DgaCorpusGenerator`. The real fixture is what set it, and the real decoys
turned out to be 0.2 harder than the synthetic ones written to imitate them —
`crwdcntrl.net` reaches 0.546 where the generator's abbreviations top out at
0.337. Expect the generator you write to be gentler than the traffic.

**Rule 6's second level went the other way here, and that is not a
contradiction.** Cluster 1 lost the verb when `resp_bytes` went missing,
because `exfiltrates_to` *means* outbound. Cluster 3 keeps the verb when
`rcode` goes missing, because `resolves_algorithmic_domain` means structurally
generated and structure is still measured. The rule is not "a missing
component downgrades the claim". It is: read what the verb asserts, and check
whether the telemetry still supports that particular assertion. One predicate
at a time.

**Determinism is not free once findings are capped.** A generation family
mints hundreds of names scoring an identical 1.0 and only three are reported,
so the tie-break decides which — and with no total order it fell through to
`group_by` ordering, which Polars does not promise to keep stable. Two runs on
one capture produced different content-addressed finding IDs. Anything that
takes a top-N of equal scores needs a total order; and this was caught by
printing the findings twice, which cluster 2 also recommends and which is
still the highest-yield thing to do before writing tests.

**Profile before optimising, and then again.** The obvious cost was the
per-row `map_elements` public-suffix reduction. Vectorising it moved a
1.1M-record run from 32k to 34k records/second — noise. The real costs were
scalar `np.clip` inside the scoring loop and an uncached character model, and
fixing those gave 60k. The same `np.clip` pattern is in
`statistics.weighted_geometric_mean`, where it is shared by every analyzer
here and is worth more than any one cluster.

**Two small things that are not this cluster's, and were done anyway because
nothing worked without them.** `read_dns_log` now prefers Zeek's textual
`rcode_name`/`qtype_name` over the numeric columns, so an evidence payload
says `NXDOMAIN` rather than `"3"`. And `registered_domain_expr` sits beside
`registered_domain` in `dnstunnel.py`, with a test asserting the two agree
over the real capture — two public-suffix rules that disagreed would split one
zone two ways in two analyzers.

---

## 4 · Temporal ordering — `analyzer-precedes`

> **Done.** `src/voidai/correlate/incidents.py`, covered by 26 tests. Both
> halves of the section are built: `precedes` between adjacent behaviours,
> and the unary attachment settled below. **Nothing here has an accuracy
> figure and nothing could** — neither half claims an observation, so what is
> scorable is that they never reach a score. Measured against the previous
> correlator over 250 incidents: zero priorities changed and zero ranks moved.
> `docs/benchmarks.md` §10 has the account.
>
> **The trap below is half of the trap.** `precedes` was already kept out of
> the corroboration count; the same circularity runs through the noisy-OR,
> which had no guard and needed a second, narrower set. Read §10 before the
> trap. Two other things worth having in advance: the ordering had to be
> stored *in* order, because edges inherit the confidence of what they order
> and sorting them with the rest scrambles the chain; and a `@property` that
> derived an incident's subject from its findings broke the moment
> attachment let a finding have a different one.

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

### Attaching unary findings — settled, build it here

Cluster 2 surfaced this and correctly declined to settle it alone.
`matches_threat_intel` is unary and its subject is the *indicator*, so
incidents formed by subject put an intel hit in its own incident rather than in
the one for the host that contacted it. A host that beacons **and** reaches a
known-bad address reads as two incidents — exactly the conjunction the
corroboration multiplier exists to surface, and the single most actionable fact
the system can produce, currently invisible.

The decision, to be implemented in this cluster:

**Attach; do not re-subject.** Incident formation follows an edge from a
finding's *object* to a unary finding's *subject*. The predicate is left
alone — `matches_threat_intel(ip:45.83.220.17)` is a true and well-formed
proposition about the address, and rewriting it to take the host as subject
would make it false, since a host does not appear in a feed.

**Attach to every incident naming the indicator.** Several hosts may have
reached it, and each one's analyst needs to see it.

**A finding that attached anywhere does not also stand alone.** One that
attached nowhere stays its own incident — an indicator seen in traffic with no
other finding against it is still worth reporting, just not worth promoting.

**It does not corroborate.** `MATCHES_THREAT_INTEL` goes in `non_corroborating`,
and the reason is not rule 6 — an intel match is complete evidence of exactly
what it claims, not partial. The reason is what corroboration *means* here. The
multiplier counts independent **behaviours of a host**, on the argument that a
machine doing several unrelated suspicious things is more likely compromised
than one doing a single thing. An intel hit is not a second thing the host did;
it is better information about the first thing. Confirmatory evidence belongs in
the noisy-OR, which already lifts combined confidence, and not in a count of
behaviours.

The failure mode that settles it: a feed that is stale, over-broad, or simply
wrong would otherwise become a queue-flooding weapon, multiplying the priority
of every host that touched anything in it. Cluster 2 built age decay because
that worry is real; letting the same finding corroborate would reintroduce it on
a different axis.

**If intel hits later prove too weak in the queue, the lever is the finding's
own confidence, not the behaviour count.** Written down so it is not "fixed"
later by the move this section exists to rule out.

### What it cost, for whoever takes the next one

**The trap above names one of the two routes into a score, and the other one
was open.** `CorrelationConfig.non_corroborating` stops the multiplier and
deliberately does *not* stop the noisy-OR — every other member of that set is
a real observation about the world, so raising combined confidence with one is
sound. `precedes` is not an observation: the correlator derives it from
findings already inside the incident, so the noisy-OR is the same closed loop
on the other side of the arithmetic, and it tightens as behaviours are added.
It needed a second and narrower set, `non_evidential`, whose members
contribute neither. Two sets that both mean "does not count" is one more
concept than anyone wants, and collapsing them would either let bookkeeping
raise a score or stop a real observation from doing so.

**A sensor-skew floor does not have to be one number.** The trap says
timestamps come from sensors that disagree and asks for a minimum separation.
A single floor has to cover the worst case, which is hours, and then nothing
within one log gets ordered either. Whether two findings share a clock is
already in the data — every Artifact names its `source` — so the floor is one
second within a source and five minutes across two. Most of the design here
turned out to be reading what the repository already records rather than
adding anything.

**Neither half of this cluster produces a number, and that is the honest
report.** Every previous cluster could say something about precision, even if
only that it was synthetic. This one detects nothing: it reorders what an
incident contains and changes which incident a finding lands in. The
measurement that matters is therefore *negative* — priorities and ranks
unchanged against the previous correlator — and the temptation is to reach for
a positive-sounding one instead. Cluster 5 should expect the same shape from
anything correlator-side.

**Print the queue, not just the findings.** Clusters 2 and 3 both recommend
printing findings before writing tests, and it is still right, but this
cluster's two worst defects were only visible one level up.
`RankedIncident.subject` derived the incident's subject from `findings[0]`,
which held while every finding in an incident shared a subject and stopped
holding the moment a unary finding could attach — a strong intel hit renamed a
host's incident after a foreign address, and the queue row, `rank_of`, the
hunt pivots and the model brief all read that one attribute. Nothing in the
findings shows it. The types stayed correct throughout.

**Rule 8 earns its place on the eleventh guard, not the first.** Breaking each
fix in turn found two tests that passed for a reason other than the one they
named: a self-edge test whose three behaviours happened to contain no
*adjacent* pair sharing a pivot, and a chain-order test whose three equal
confidences let it fall through to a finding-id tiebreak and pass under four
of six hash seeds. Both look like careful tests. Neither guarded anything.

**A salted `hash()` in a fixture makes a reproducibility test meaningless.**
`tests/test_correlate.py` built artifact locators from `abs(hash(kind)) % 1000`,
and Python salts string hashing per process, so every fixture finding had a
different content-addressed id in every run. The same shape as cluster 2's
wall-clock `age_days`, and with the same tell: the assertion compares a run
with itself and cannot fail.

---

## 5 · Host and endpoint — `analyzer-host`

> **Half done.** `src/voidai/analyzers/host.py` and
> `src/voidai/ingest/sysmon.py`, registered, and covered by 75 tests.
> `executes_rare_process` and `exhibits_anomalous_lineage` are built, as the
> trap below instructs: they share a parser and a baseline and were taken as
> one unit.
>
> **`establishes_persistence` and `authentication_anomaly` are deliberately
> not built.** The trap says this cluster is four analyzers wearing a
> trenchcoat and that taking all four is how it goes wrong, and that is
> correct for a reason worth stating precisely: the two built here share
> *both* a parser and a baseline, and neither of the other two shares either.
> `establishes_persistence` reads Sysmon events 11, 12 and 13 and registry
> and scheduled-task creation — a different event set — and is event-driven
> rather than statistical, so it has no estate baseline at all and is closer
> in shape to `alerts.py`. `authentication_anomaly` reads Windows Security
> 4624/4625, takes a `user` as subject rather than a `host`, and its baseline
> is per-account rather than per-image. Three predicates in one branch would
> have shared one gate between three incompatible notions of "normal".
> Both remain declared in the Lexicon and unclaimed. **Take one. Do not take
> two.**
>
> **Validation is synthetic sensitivity and a real refusal**, which is a
> shape no previous cluster produced. A real, openly-licensed, correctly
> formatted corpus of Windows attack telemetry is committed at
> `tests/data/real.sysmon.jsonl.gz` — OTRF Security-Datasets, MIT, licence
> verified by fetching it — and it contains a genuine true positive. The
> analyzer **declines to score it**, because four hosts is not an estate and
> a rarity measure over that capture ranks `lsass.exe` identically with the
> APT29 day-1 payload. Synthetic: 6 of 6 plants, one planted false positive
> that stays. CTU-13 is a no-op by construction and asserted as one.
>
> Two things went differently from the plan and both are in
> `docs/benchmarks.md` §11. **Command-line entropy was measured and removed**
> — for a different reason than §9's, and a worse one: the encodings
> attackers use are *less* entropic than ordinary command lines, and the
> corpus's largest base64 payload sits at the 38th percentile. **The lineage
> measurement had to be rewritten**, because raw edge rarity made
> `executes_rare_process` structurally unreachable: a novel binary always
> arrives on a novel edge. Conditional breadth on both ends fixes it. Read
> §11 before the section below.

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

### What it cost, for whoever takes the next one

**A host count is not an estate check.** The trap asks for a minimum host
count and that is necessary and not sufficient: thirty machines observed for
twenty seconds each pass it, and every image on them is still a singleton.
The gate that does the work is the **share of images seen on exactly one
host**, which asks whether the baseline has converged rather than how many
machines are in it — and it was set from the real corpus (74%) rather than
chosen. It is the first gate in this project set by measurement, and the
pattern generalises: cluster 6's endpoint baselines will need the same
question asked.

**"Rare" and "anomalously parented" are the same observation unless you make
them different.** `hosts(edge) ≤ hosts(child)` always, so a novel binary
guarantees a novel edge and the lineage half will swallow the rarity half
whole. Two things fix it and both are needed: measure the edge *conditionally*
on how widespread each end is, and give the analyzer a subsumption rule so
one process creation cannot become two behaviours of one host. The second has
to live in the analyzer — the correlator sees two findings about a host and
cannot know they describe one event.

**A conditional frequency computed over the sample you are scoring is a trap
in both directions.** `P(child | parent)` is 1.0 for a parent observed
spawning one process, which annihilated the clearest true positive in the
corpus; the fix is a minimum sample count and an omitted component below it,
not a floor value. This is rule 6's first level, and it is the third cluster
in a row to meet it in a new disguise.

**Two of fifteen guards passed for the wrong reason, and rule 8 found both.**
A cycle test that asserted only termination — which a depth bound already
guarantees — and a null-join test containing no nulls. Both looked careful.
Neither guarded anything. Budget for the exercise; it is the second time in
this repository it has paid.

**Run rule 8's mutants with `-B`.** A size-preserving mutation leaves a `.pyc`
whose cache key does not change, so the reverted source is shadowed by the
mutant's bytecode on the *next* run and a passing test fails for no visible
reason.

**Host telemetry and network telemetry do not join, and nothing in this
cluster could fix it.** Sysmon records a computer name and no address, so one
compromised machine becomes two incidents and the corroboration payoff this
cluster was sold on is only half collected. `AnalysisContext.ip_to_host` is
shaped for the inventory that would close it and nothing populates it — the
same gap the queue already has for demoting a gateway. It is one small parser
and it is now the highest-value item in `benchmarks.md` §12.

**A predicate you wish existed is a Lexicon change, not a workaround.** With
prevalence unavailable there is no weaker verb to fall back on — cluster 1
had `transfers_anomalous_volume` waiting and this one has nothing. The
temptation is to emit `executes_rare_process` scored on path and command line
alone, which is exactly cluster 1's mistake: keeping the claim after losing
the measurement. `executes_process_from_unusual_path` is noted as a candidate
and deliberately not minted.

## 6 · Asset inventory — `analyzer-inventory`

Not an analyzer at all, and the highest ratio of value to lift left on this
list. **One parser. No correlator change, no Lexicon change, no new
predicate.**

Cluster 5 delivered host telemetry and only half its promised payoff, because
Sysmon records a computer name and a connection log records an address, so one
compromised machine appears as two incidents that do not corroborate each
other. `AnalysisContext.ip_to_host` is already shaped for the answer,
`AnalysisContext.actor()` already prefers it, and all six network analyzers
already route their subject through `actor()`. The map is simply never
populated by anything.

### Measured, before the work is specified

Loading a single mapping by hand — `{"10.0.1.14": "FINANCE-WS04"}` — against
the demo capture:

| | No inventory | One line of inventory |
|---|---|---|
| Patient zero | **two rows**: `ip:10.0.1.14` with 5 behaviours, `host:FINANCE-WS04` with 2 | **one row**: `host:FINANCE-WS04` with **7** |
| Priority | 2.50 and 1.50 | 2.50 |
| Incidents in the queue | 10 | 9 |

Seven behaviours on one subject — `beacons_to`, `scans`, `tunnels_dns_over`,
`resolves_algorithmic_domain`, `triggered_signature`, `executes_rare_process`,
`exhibits_anomalous_lineage` — is network and host evidence corroborating on
one machine, which is the thing cluster 5 was ranked highest for and did not
get. Nothing else in the pipeline changes.

**Input** An operator-supplied inventory file. Follow `docs/ioc.md` and
`ingest/ioc.py` exactly: a `#`-prefixed metadata header, then one mapping per
line. It is read from disk and never fetched — rule 11, and this is the second
cluster in a row where the tempting shortcut is a lookup service.

### Done when

`ingest/inventory.py`, an `--inventory` option on `run` and `hunt` wired
through `_detect` the way `--intel` is, a documented file format, `voidai
doctor` reporting how many mappings loaded and how many observed addresses they
cover, the demo capture shipping one, and the README demo block re-run.

### The trap that will bite you

**Resolve the finding, not the incident.** `actor()` does this already and it is
the right layer: a finding that names `host:FINANCE-WS04` is a *more* accurate
assertion than one naming the address, and its evidence still cites the
`conn.log` lines it was measured from. Do not add a second resolution step in
`correlate/incidents.py` — cluster 2 settled that incidents attach and findings
assert, and this is the same rule from the other side.

**A wrong mapping is worse than none.** DHCP moves addresses. An inventory
naming the wrong machine attaches a beacon to an innocent host with full
confidence and a clean chain of custody — the one failure this project cannot
tolerate. Record where each mapping came from and when it was stated, the way
`ingest/ioc.py` records an indicator's provenance and age, and put both in the
evidence payload. If the file carries a timestamp older than the capture,
say so rather than resolving silently.

**Coverage is a number the operator needs.** An inventory covering 3% of an
estate is a rounding error dressed as an improvement. Report coverage in
`doctor` and in the receipt, not just the mapping count.

### Validation

Synthetic, and there is nothing to detect — the correctness question is whether
the join is right and whether a stale or partial inventory degrades honestly.
Rule 7 still applies to how that is written up.

---

## 7 · Web — `analyzer-web`

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
| 1 | Volume and egress | Low | **Done** — and it rewrote rule 6; see the section |
| 2 | Threat intel | Low | **Done** — and rule 6 had to be re-derived without weights; see the section |
| 3 | TLS and DGA | Medium | **Done** — and entropy turned out not to work at this length; see the section |
| 4 | Temporal ordering | Low | **Done** — and the trap was half the trap; see the section |
| 5 | Host and endpoint | High | **Half done** — the two that share a baseline; the other two are still open, see the section |
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
