# Benchmarks

Synthetic corpora and real captures, reported separately and never averaged
together. A synthetic corpus proves the mathematics; a real capture proves —
or disproves — the product. Where they disagree, the real capture wins.

Which analyzers have a real half is not uniform, and every section says which
it has. Beaconing has both. DNS tunnelling has real specificity and synthetic
sensitivity, and section 5 splits them. Alert triage and volume-and-egress
are synthetic on both halves, and sections 6 and 7 say so before they say
anything else.

Everything here is reproducible:

```bash
voidai bench                              # synthetic, seeded: beaconing, then egress
voidai bench --real data/ctu13/<file>     # CTU-13, after fetching a capture
```

---

## 1. Synthetic corpus — beaconing (seed 1337, 24h)

Six planted implants hidden among browsing traffic, a monitoring agent, a
software update checker, and NTP.

`voidai bench` scores this corpus and then generates a second one for the
volume-and-egress analyzer — different traffic, different decoys, different
ground truth. The two are printed as separate tables and never combined; one
number covering two analyzers measuring different behaviours would describe
neither. Section 7 has the second.

```
precision 1.000 · recall 0.833 · f1 0.909      (5 TP · 0 FP · 1 FN)
55,983 records → 5 findings in 0.24s           (230,000+ rec/s, x86_64, 4 cores)
```

| Implant | Period | Jitter | Model | Score | Found |
|---|---|---|---|---|---|
| textbook-60s | 60s | 0% | symmetric | 0.982 | yes |
| jittered-5m | 300s | 10% | symmetric | 0.874 | yes |
| jittered-15m | 900s | 25% | symmetric | 0.718 | **no** |
| low-and-slow-30m | 1800s | 50% | symmetric | 0.753 | yes |
| scheduled-33s-menti-like | 33s | 18% | scheduled | 0.852 | yes |
| scheduled-10m | 600s | 30% | scheduled | 0.800 | yes |

The single miss scores 0.718 against a 0.72 threshold. It is left as a miss
deliberately — see "Alert burden" below, where the real captures show the
false-positive rate, not sensitivity, is the binding constraint.

**A synthetic benchmark measures the generator as much as the detector.**
Section 3 is a worked example of that going wrong.

---

## 2. Real captures: CTU-13

[CTU-13](https://www.stratosphereips.org/datasets-ctu13) is thirteen captures
of real botnet traffic on a university network, every flow labelled `Botnet`,
`Normal`, or `Background`. Licence: CC-BY.

Measured with all three network analyzers running — beaconing, fan-out, and
volume-and-egress.

| | Scenario 3 | Scenario 6 |
|---|---|---|
| Malware | Rbot | Menti |
| Duration | 66.8h | 2.15h |
| Flows analysed | 12,689,947 | 1,916,655 |
| **Infected host detected** | **yes** | **yes** |
| C2 beaconing confidence | **0.958** | 0.749 |
| C2 rank among beaconing findings | 204 / 1277 | 358 / 395 |
| **Infected host queue rank** | **2 / 247** | **1 / 160** |
| Findings → incidents | 1589 → 247 | 512 → 160 |
| Corroborated incidents | 3 | 1 |
| Beaconing pair precision | 0.0008 | 0.0025 |
| Throughput | 206,657 rec/s | 180,280 rec/s |
| Peak RSS | 2,662 MB | 632 MB |

**What the third analyzer changed, and what it did not.** Findings rise by
about 20% on scenario 3 (1328 → 1589) and 29% on scenario 6 (397 → 512), and
throughput falls by roughly 8% and 18% as a third pass runs. Memory is flat:
peak RSS is inside 10 MB of the two-analyzer figure on both captures, which is
rule 2 holding — peak is `max(analyzers)`, not `sum(analyzers)`, because they
run sequentially and release.

The two rows that matter are the two that did not move. **The infected host
holds rank 2 and rank 1**, against larger queues than before — 247 and 160
incidents rather than 214 and 133. And **corroborated incidents stay at 3 and
1**, exactly where two analyzers had them, while a third analyzer emits
findings across the estate. That is what `non_corroborating` is for, and it is
emphatically not what the first two versions of the egress analyzer did: they
took corroboration to 33 and 16 and pushed the scenario 3 true positive to
rank 5. Section 7 has that story.

Two rows are scoped rather than re-measured, and are named for it. "C2
beaconing confidence" and "C2 rank among beaconing findings" are computed from
`beacons_to` findings alone, so they are unchanged by construction — the
beaconing analyzer itself is untouched. Selected across every predicate, as
they briefly were, scenario 3's C2 row reported a `contacts_rare_destination`
finding at 0.983 instead of the beacon at 0.958: a row keeping its name while
measuring something else, and losing comparability with every figure it had
published before. `voidai bench --real` now reports the strongest finding of
any kind on a labelled pair under its own separate row.

Scenario 3's C2 channel (`147.32.84.165 → 38.229.70.20`) is found at 0.958
confidence — genuinely strong. Scenario 6's Menti channel
(`147.32.84.165 → 91.212.135.158:5678`) is found at 0.749, near the threshold.

### Why beaconing "precision" is near zero, and why that number is not what it looks like

Two things make the raw figure misleading in *both* directions, so it is
reported as-is and explained rather than massaged.

**`Background` means unlabelled, not benign.** The CTU-13 authors labelled
only traffic they could attribute. A flagged pair labelled `Background` is
unverified, not confirmed wrong. Pair precision is therefore a hard lower
bound on real precision, not an estimate of it.

**Most botnet traffic is not beaconing.** The `Botnet` label covers spam runs,
ICMP floods, scanning, and click fraud. Scenario 6 is overwhelmingly spam —
port 25 to 1,106 distinct mail servers. A beaconing detector *should* ignore
all of it, so recall against all botnet-labelled flows would punish the
analyzer for being correct. Defining C2 as "the botnet traffic that looks
periodic" and then measuring whether periodic traffic is found would score
1.000 by construction and mean nothing.

So the honest measures are: was the compromised host surfaced (yes, in both),
and how much noise came with it.

### Alert burden, and how it was fixed

The first version of this page reported the real problem: 184 findings/hour on
scenario 6, with the true positive at **rank 358 of 395**. Detected and
invisible are the same thing to an analyst working a queue.

The instinct is to tighten the detector. That is wrong, and the data says so.
The high-scoring findings that outranked the C2 are *genuinely* beacon-like —
perfectly regular, uniform payload, single-host destinations. They are
monitoring agents, backup jobs and keep-alives. No refinement of a periodicity
measure separates them, because on the axis of periodicity they are not
different.

**What separates a compromised host is that it does more than one suspicious
thing.** The scenario 6 host beacons every 33 seconds *and* mails 1,573
distinct destinations on port 25 — rank 1 of 143,546 (host, port) pairs for
fan-out. Scenario 3's beacons *and* sweeps 26,702 hosts on port 22, where
seven of the top ten fan-out pairs in the whole capture are infected hosts.

So a second analyzer was added (`fanout`, the `SCANS` predicate) and ranking
moved out of the analyzers into `voidai.correlate`. A `Finding` answers "how
beacon-like is this traffic?"; an `Incident` answers "how much should an
analyst care about this host?" Conflating those two questions is what buried
the true positive.

| | scenario 3 | scenario 6 |
|---|---|---|
| Before — C2 finding rank | 204 / 1277 | 358 / 395 |
| **After — infected host queue rank** | **2 / 214** | **1 / 133** |
| Findings → incidents | 1328 → 214 | 397 → 133 |
| Corroborated incidents | 3 | 1 |

This table is the one-analyzer to two-analyzer transition and its numbers are
that measurement, not the current one — a third analyzer has since been added
and the table at the top of this section carries the figures with all three.
The rank and the corroboration count are the same in both.

Adding the second analyzer costs about 25% in wall time (223k rec/s against
310k for beaconing alone) and nothing in memory.

On scenario 3 the three corroborated incidents are, in order: a resolver or
gateway reaching 162,612 destinations, **the actual bot**, and a BitTorrent
client on port 6881. An analyst triaging three incidents finds it immediately.

Ranking is by noisy-OR over the strongest finding *per predicate*, multiplied
by a corroboration bonus. Per-predicate deliberately: twenty beaconing
findings on one host are twenty views of one behaviour, not twenty independent
reasons to believe it, and treating them as independent would let a chatty
analyzer manufacture certainty.

The remaining noise is still genuinely periodic benign traffic — SNMP polling
on port 161, internal monitoring, backups, P2P. It is no longer *ranked above
the intrusion*, which was the operational problem. Suppressing it outright
needs environment context: an asset inventory, a business-hours model, a
baseline.

---

## 3. What the real captures changed

Every item here was invisible against synthetic data and was caught only by
running on real traffic. This is the argument for doing it early.

### One check-in is not one record — burst coalescing

NetFlow emits a record per direction and splits long connections at the
active timeout. The Menti C2 beacons every 33 seconds but appears as 384
records whose **median interval is 0.15 seconds**. Every interval statistic
downstream measured record framing rather than the beacon, and the channel was
rejected outright by the minimum-period gate.

Interval distributions like this are strongly bimodal in log space. VoidAI now
detects that with Otsu's method and coalesces bursts before measuring
anything, recovering 183 check-ins at 33.3s. Unimodal series — well-formed
connection logs — are left untouched.

Otsu rather than "largest gap between sorted intervals": a handful of
intermediate values bridge the valley in real captures, and the simpler rule
fails silently on exactly the traffic it exists to fix. That was the first
implementation, and it did fail.

### Real beacons are right-skewed — the symmetry measure was backwards

The original ensemble scored interval *symmetry* via Bowley skewness, on the
reasoning that jitter is applied evenly and human traffic skews right.

The Menti channel has Bowley **+0.948**: q1=33.0s, q2=33.3s, q3=42.4s, with a
tail running to 2x, 3x and 5x the base period as check-ins are missed. Strong
right skew is a *hallmark* of a real beacon. The measure was penalising its
own best evidence.

It scored ~1.0 on every synthetic implant because the generator applied
`uniform(±jitter)` — symmetric by construction. **The component was measuring
an artifact of the generator.**

It is replaced by `schedule_floor_dispersion`, `(q2-q1)/q2`, which asks
whether the distribution has a hard *floor*. A process on a timer cannot fire
early but can easily fire late; a person has neither constraint. Measured
across traffic types, browsing lands at 0.59 and every beacon shape at 0.00
to 0.33.

The generator now also emits hard-floor, right-tailed implants alongside the
symmetric ones, so neither shape can be over-fitted again.

### The obvious flow-orientation rule deletes real C2

Bidirectional NetFlow lists both halves of every conversation. The reply half
becomes a pair whose "destination port" is the client's ephemeral port, and
since a client holds that port for the life of the conversation, those replies
form textbook-looking beacons. On scenario 6 they manufactured tens of false
detections on ports like 49375.

The textbook fix — "the server is the endpoint with the lower port" — is
wrong. The scenario 6 bot sources from ports **1027–4985**, the Windows XP
ephemeral range, to a controller on **5678**. Under that rule the genuine C2
channel is classified as a reply and silently deleted, taking the capture's
only true positive with it. Measured, not theorised: findings dropped 618 →
309 and detection went from yes to no.

VoidAI drops a record only when its destination port is ≥32768 *and* the
source port is lower. Findings fell to 395 and the C2 survived. A real service
listening above 32768 and contacted from a lower port still produces spurious
pairs; that is the accepted cost of never discarding a real channel.

### Memory did not survive contact with 12.7M flows

Scenario 3 originally peaked at **7,165 MB** — more than the Pi 5 target has
in total. The cause was materialising the whole capture before grouping: the
per-pair arrays of timestamps and byte counts hold every record in the file.

Now split into two streaming passes:

  **Pass 1** groups to one row per (src, dst, port) carrying only scalars — a
  count and a first/last timestamp. Enough to decide which pairs could
  possibly qualify, cheap enough to stream.

  **Pass 2** re-scans, semi-joins to the survivors, and gathers full arrays
  for those alone.

On scenario 3, pass 1 yields 1,123,519 pairs, of which **15,737 (1.4%)**
survive the count-and-span gate. Pass 2 therefore collects a fortieth of what
the single-pass version held.

| | before | after |
|---|---|---|
| Peak RSS | 7,165 MB | **2,653 MB** |
| Wall time | 46.5s | **40.8s** |
| Throughput | 272,649 rec/s | 310,801 rec/s |
| Findings | 1277 | 1277 (identical) |

Faster despite reading twice, because nothing large is ever materialised.
Findings are byte-identical, asserted by a test rather than assumed.

**What remains.** 2,653 MB is Polars' hash state for the pass-1 `group_by`
over 1.12M distinct keys — the summary frame it produces is only 53 MB. Thread
count barely moves it (2,042 MB at one thread against 2,093 MB at four, for a
4x speed difference), so it is inherent to the aggregation rather than to
parallelism.

**Does that fit a 4GB board?** This document previously said no, reasoning
from the peak-RSS figure. Measured against a hard cgroup ceiling with swap
pinned to match — see `tools/envelope.py` and `deployment.md` — the answer is
yes: OOM-killed at 2,400 MB, flaky at exactly 2,500 MB, reliable from 2,600 MB,
and comfortable in the 3,696 MB a 4GB Pi has left after the OS. The estimate
was pessimistic by about one board class.

Splitting pass 1 into time windows and merging partial summaries would still
lower the peak — counts sum and min/max combine, so the merge is exact — but
CSV has no random access, so windowing means either re-parsing per window or
moving to a batched reader. A Pi deployment would realistically process hourly
or daily windows anyway, which is the same benefit arriving from the
operational direction rather than as a requirement.

### Parsing was 21x slower than it needed to be

The first NetFlow parser looped in Python: 37k flows/s, which turns scenario 3
into a ten-minute wait on a desktop and something far worse on a Pi. Rewritten
as vectorised Polars expressions it runs at 790k flows/s with identical
output.

---

## 4. The language layer

Qwen2.5-1.5B-Instruct Q4_K_M, 4 CPU threads, x86_64, on the CTU-13 scenario 6
top-ranked incident:

| | |
|---|---|
| Evidence brief | 256 tokens (2 findings, 3 measurements) |
| Prompt / completion | 605 / 188 tokens |
| Wall time | 28.9 s (~7-11 tok/s) |
| Claims struck | 0 |
| Detection throughput, same run | 332,759 rec/s |

Detection and reasoning are metered separately. Folding them together
divides detection throughput by the time a model spent writing prose — the
first version of the receipt reported 781 rec/s for a stage that actually runs
at over 300,000.

Four things the model got wrong, all fixed by changing what it is *shown*
rather than by prompting harder — full detail in
[`models.md`](models.md):

- Called a 0.98-confidence beacon "likely a legitimate communication". It did
  not know what the predicate meant; the Lexicon's own description now goes in
  the brief.
- Glossed T1071/T1573/T1008 as "reconnaissance, credential harvesting, and
  monitoring". Those are Application Layer Protocol, Encrypted Channel and
  Fallback Channels. Technique codes were removed from the prompt.
- Wrote "the host is a noisy-OR beacon", having parroted the ranking
  rationale. The brief now carries the priority number, not the arithmetic.
- Produced a 900-character narrative, exhausted its token budget, and was cut
  off mid-claim leaving unparseable JSON. The grammar now bounds every string
  and list, and caps whitespace.

The pattern: **show the model only what it can reason about.** Raw logs,
technique codes and scoring notation are all things a small model repeats
without understanding.

The verifier catches uncited claims, citations that do not resolve against the
brief, and claims naming addresses or ports absent from the cited evidence. It
cannot catch a well-cited claim that is simply wrong — which is why all four
fixes above are about grounding rather than filtering.

---

## 5. DNS tunnelling — real specificity, synthetic sensitivity

Validation here is split, and the halves are reported separately because they
rest on different evidence.

**False positives: measured on real traffic.** The Stratosphere malware
captures ship `passivedns` logs alongside their NetFlow, and those carry real
query names. Across **3,655 records from 18 hosts** — Akamai CNAME chains,
Mozilla update services, Google notification endpoints, OneNote CDN, telemetry
and certificate status lookups — the analyzer emits **nothing**. Only one zone
even passed the volume gates (`google.com`, scoring 0.065 against a 0.62
threshold).

This is the half that decides whether the analyzer is deployable, and it is
the half no generator can honestly test: real DNS is stranger than anything
worth writing by hand. A 400-record excerpt is committed as
`tests/data/real.passivedns` (CC-BY, Stratosphere IPS) so the result is
regression-tested rather than reported once.

**True positives: synthetic only.** No labelled DNS-tunnelling corpus was
reachable, so sensitivity is measured against traffic modelled on published
tool behaviour. That distinction is not blurred: the analyzer is *known* not
to fire on real benign DNS, and *believed* to fire on real tunnels.

The generator is adversarial: benign traffic includes a content delivery
network minting 300 subdomains per host, hex-encoded reputation lookups, and
DNSBL queries — the categories that break entropy detectors.

| Zone | Queries | Entropy (bits/char) | Score |
|---|---|---|---|
| `tunnel-example.com` (iodine-like, TXT) | 600 | 4.55 | **0.911** |
| `exfil-example.org` (chunked labels) | 380 | 4.57 | **0.891** |
| `c2-example.net` (dnscat2-like, A only) | 450 | 4.35 | **0.783** |
| `reputation-example.net` (hex hashes) | 250 | 3.87 | 0.569 |
| `akamaiedge.net` (CDN) | 300 | 3.39 | 0.268 |
| `blocklist-example.org` (DNSBL) | 200 | 3.03 | 0.080 |

3 of 3 tunnels found, no false positives, at a 0.62 threshold — and zero
findings across the real traffic above.

**The margin on reputation lookups is thin — 0.05.** Hex encoding tops out at
4.0 bits/char against base32's 5.0, and that gap is the only thing separating
a hash-lookup service from a tunnel. The threshold is deliberately *not*
widened to make the number look better: with no real corpus, tuning it would
mean calibrating against a generator written by the same hand as the
detector, which is precisely the error section 3 documents. The margin is
pinned by a test instead, so a regression is visible.

Two consequences follow honestly: a tunnel that encodes in hex would likely be
missed, and a reputation service using longer or denser encodings could false
positive. Both wait on real data.

---

## 6. Alert triage

A mid-sized sensor emits tens of thousands of alerts a day and an analyst
reads a few dozen, so every deployed IDS is already an alert-suppression
problem. This analyzer does not try to decide which alerts are true. It
reduces the flood to the few worth *correlating* and hands them on as one more
opinion about a host — which is why `TRIGGERED_SIGNATURE` is capped at MEDIUM
severity and never reaches HIGH on its own. A ruleset's opinion should not
outrank VoidAI's own measurements.

On a synthetic stream shaped like a real one — 60 hosts tripping policy and
scan rules thousands of times, one host tripping two rare severe rules, and
3,000 non-alert flow events mixed in:

```
14,534 EVE events → 11,534 alerts parsed → 2 findings
both on the compromised host; the 60-host estate-wide noise entirely suppressed
```

A 5,767:1 reduction with the intrusion intact. Volume alone does not raise a
score: ten thousand copies of one alert is one fact, and a test pins that.

**Synthetic only.** The Stratosphere captures carry NetFlow and passivedns but
no EVE output, so no real alert stream was reachable.

Three bugs the tests caught before this shipped, all in the category table:

- `"Not Suspicious Traffic"` scored **0.55**. The substring `"suspicious"`
  matched before `"not suspicious"`, so Suricata's *noisiest* category was
  being read as moderately suspicious — the exact inverse of intent, and
  enough to flood the queue on its own. Negations are now matched first, in a
  separate table, so the invariant survives someone appending to the list.
- `"Attempted Administrator Privilege Gain"` scored **0.40**, the unmatched
  default. The table was written with Snort classtype names
  (`attempted-admin`) but EVE emits human-readable descriptions, so roughly
  half the entries matched nothing. Both forms are now listed.
- One malformed line discarded an entire file. Log rotation truncates the
  final record mid-write routinely, so `read_eve` now falls back to a
  line-by-line salvage when the bulk reader rejects a file.

---

## 7. Volume and egress — synthetic accuracy, real-capture ranking

Two halves, resting on different evidence, and they are not the halves section
5 splits.

**Accuracy is synthetic.** Every precision, recall and score below is measured
against a generator, and describes traffic built to the same beliefs as the
detector. There is no real precision figure for this analyzer.

**Ranking behaviour is real.** CTU-13 has been run against it, and what it
returned was not an accuracy number — it was two design errors and the
measurements that fixed them, under "What CTU-13 changed" onward. Both
captures are now restored with the analyzer running: scenario 3's infected
host at rank 2 of 247, scenario 6's at rank 1 of 160.

The analyzer claims three predicates that are one measurement seen at three
strengths: `exfiltrates_to` (critical/high), `transfers_anomalous_volume`
(medium), and `contacts_rare_destination` (low). Which one a pair can support
is decided first by *which signals the sensor actually supplied* and only then
by how high the combined score reached — see "What CTU-13 changed" for why
that order is not an implementation detail. Four signals, combined the same
way beaconing combines its six:

| Component | Measure | Weight |
|---|---|---|
| `egress_ratio` | share of the conversation's bytes that went out | 0.30 |
| `volume_deviation` | modified z-score against the host's own per-destination distribution | 0.28 |
| `destination_rarity` | estate-wide prevalence, the same curve beaconing uses | 0.24 |
| `novelty` | share of the host's window elapsed before it first reached this destination | 0.18 |

### The corpus

`EgressCorpusGenerator`, seeded, separate from the beaconing corpus in section
1 — adding traffic to that one would have invalidated results this document
calls reproducible. Twelve hosts, 12,251 flows over 24 hours, 125 distinct
source→destination pairs.

The benign traffic is not filler. Three of its four categories are
indistinguishable from exfiltration on volume and direction alone:

| Benign category | Per host | Direction | Why it is hard |
|---|---|---|---|
| Nightly backup | ~2.1 GB in 24 flows | 99.8% outbound | Large, outbound, scheduled — three of the four things exfiltration is |
| Cloud sync | ~310 MB in 140 flows | 99% outbound | Same, reached by the whole estate |
| Software mirror | ~2.4 GB in 20 flows | 99.8% **inbound** | Same volume, travelling the other way |
| Browsing | 6 destinations, ~150 KB each | inbound-heavy | Every host reaches addresses nobody else does |

Plus one deliberate trap, described below.

### Result

```
precision 0.800 · recall 1.000 · f1 0.889      (4 TP · 1 FP · 0 FN)
12,251 records → 5 findings in 0.06s           (189,000 rec/s, x86_64, 4 cores)
```

| Planted transfer | Volume | Flows | Appears at | Predicate | Score |
|---|---|---|---|---|---|
| `bulk-single-archive` | 800 MB | 3 | 70% in | `exfiltrates_to` | **0.946** |
| `slow-and-small` | 12 MB | 40 | 55% in | `exfiltrates_to` | **0.899** |
| `staged-chunked` | 600 MB | 120 | 40% in | `exfiltrates_to` | **0.851** |
| `trickle-upload` | 600 KB | 25 | 62% in | `contacts_rare_destination` | **0.704** |

The last one is 600 KB, below the megabyte floor for a volume claim, so the
strongest thing sayable about it is that something went somewhere rare — and
that is what it says, at LOW. It counts as found because it was found; scoring
it a miss would penalise the analyzer for not overstating what it measured.

And the decoys, scored with the thresholds removed so the separation is
visible rather than inferred from silence:

| Benign category | Instances | Median score | Threshold it had to clear |
|---|---|---|---|
| Software mirror | 12 | 0.098 | 0.45 |
| Cloud sync | 12 | 0.340 | 0.45 |
| Nightly backup | 12 | 0.360 | 0.45 |
| Lone-host backup | 1 | **0.485** | 0.45 — **fires** |

Thirty-six of the thirty-seven hard decoys are silent, and the 72 browsing
destinations with them. The nightly backups clear the highest bar in the
corpus on volume and direction and still land at 0.36, because a backup target
is reached by the whole estate and was already in use when the sensor started
recording. That is rule 5 doing its job: under an arithmetic mean the backups
would score 0.65 and flood the queue.

### The one false positive is the one that cannot be fixed here

`10.0.2.13 → 10.0.2.61`, at 0.485 against a 0.45 threshold. It is a backup
target used by exactly one machine, and it is in the corpus on purpose.

Estate-wide rarity scores it 1.0 because the score is right: one host, one
destination, nobody else. Novelty is what holds it to MEDIUM rather than
CRITICAL — the destination has been in use since the capture opened — but
nothing available to this analyzer can take it to zero, because nothing in the
telemetry says "backup server". This is the gap section 8 already records as
open: **the estate has no identity.** An asset inventory demotes it in one
step, and `AnalysisContext.ip_to_host` exists for exactly that.

The margin is 0.035, which is thin. It is not widened by moving the threshold:
with no real corpus, tuning it would mean calibrating against a generator
written by the same hand as the detector — the error section 3 documents. A
test pins the false-positive *count* at one instead, so a regression that
starts reporting backups is a failing test rather than a quiet flood.

### NetFlow has no direction, and the obvious default deletes every detection

This is the trap the roadmap names, and it is worth the space because the
failing version emits no error and reads as a quiet network.

`ingest/netflow.py` records total flow bytes as `orig_bytes` — a NetFlow
record carries no directional split — so there is no `resp_bytes` column at
all. The egress ratio is *unavailable*, which is not zero and not 0.5. Run
against the same corpus with the responder column removed:

| Telemetry | Ratio handling | Planted transfers found | Top score | Strongest claim |
|---|---|---|---|---|
| Zeek `conn.log` | measured | **4 of 4** | 0.946 | `exfiltrates_to`, CRITICAL |
| NetFlow-shaped | **omitted**, weights renormalise | **4 of 4** | 0.923 | `transfers_anomalous_volume`, MEDIUM |
| NetFlow-shaped | defaulted to 0.5 ("neutral") | **0 of 4** | — | — |
| NetFlow-shaped | defaulted to 1.0 ("it's all we have") | 4 of 4 | 0.946 | `exfiltrates_to`, CRITICAL |

Omitting the component costs 0.02 to 0.06 of score as the remaining weights
redistribute, and finds everything. Substituting a neutral 0.5 scores the
component at zero, and under a geometric mean that is enough to sink every
finding in the capture — **detection goes to nothing, silently.**

The fourth row is the more instructive one. Defaulting to 1.0 produces results
identical to the sensor that actually measured direction, so it would pass
every test in this table and look like the right answer. It is not: it asserts
that every byte went outbound on telemetry that never observed a direction,
and the first capture where that is false is the one where it invents an
exfiltration. A default that happens to look right is more dangerous than one
that looks wrong. The component is omitted, the evidence payload carries
`egress_ratio: null`, and the basis line on every affected finding names the
omission.

The last column is the part that took a real capture to get right. Less
telemetry produces a *weaker claim*, not the same claim with a worse number:
the same transfers that are called exfiltration on Zeek are called an
anomalous volume on NetFlow, and the lone-host backup falls further still,
out of the volume band into `contacts_rare_destination` at LOW.

### What is not measured

**Thresholds.** `min_bytes` (1 MB), `rare_min_bytes` (100 KB),
`exfil_threshold` (0.70), `volume_threshold` (0.45) and
`rare_score_threshold` (0.30) are set from the shape of the problem, not from
a measurement.

`min_bytes` is the one CTU-13 has something to say about, and what it says is
*leave it alone* — the real command-and-control transfer it catches is smaller
than the noise it would have to exclude, and scores lower too. "Why the byte
floor is not the lever" below has the numbers. It also means what `min_bytes`
counts differs by sensor: originator bytes on Zeek, whole-flow bytes on
NetFlow. That is a property of the telemetry, recorded so a reader knows what
the floor means on theirs.

**Alert burden on a real estate.** `contacts_rare_destination` is the
predicate the roadmap flags as a flood waiting to happen, and the corpus
proves the flood is real: without its score threshold, prevalence alone marks
72 browsing destinations as rare and the analyzer emits one finding each at
confidences around 0.03. Gated, it emits one. Whether that holds on a
university network with a hundred thousand destinations is not something
twelve synthetic hosts can answer. It is also in
`CorrelationConfig.non_corroborating`, so however many it emits, it can
enrich an incident other evidence created but never create or promote one.

**Precision and recall on a real capture.** CTU-13 gives queue ranks and
corroboration counts for this analyzer, reported below, but not a precision
figure: `Background` in CTU-13 means unlabelled rather than benign, and the
label set covers spam, scanning and click fraud rather than transfers, so
there is nothing to score a volume detector's false-alarm rate against. The
one real true positive it has — scenario 6's Menti channel, at 2.16 MB — is a
single data point, not a recall measurement.

### What CTU-13 changed: omitting a component is not enough if you keep the claim

The analyzer's first version scored four signals, omitted any it could not
measure, and then picked its predicate from the resulting number:
`exfiltrates_to` above 0.70, `transfers_anomalous_volume` above 0.45. That
passed every synthetic test on this page, including all of the omission tests
in the table above.

Run against CTU-13 scenario 3, it regressed the thing the whole project is
ranked on:

| | before this analyzer | with it, predicate by score | change |
|---|---|---|---|
| **Infected host queue rank** | **2 / 214** | **5 / 247** | **worse** |
| Corroborated incidents | 3 | 33 | 11x |

Scenario 6 held rank 1. The cause was **176 `exfiltrates_to` findings across
35 hosts, median confidence 0.892, every one of them CRITICAL** — and every
one of them a claim about *outbound* volume made on NetFlow, which does not
record a direction.

The omission logic was right and did exactly what it was written to do: the
egress ratio was dropped, the weights renormalised across volume deviation,
destination rarity and novelty, and those three still reached 0.892 on real
traffic. What was wrong was that the analyzer then kept the verb the omitted
component existed to justify. `exfiltrates_to` is defined in the Lexicon as
"transfers an anomalous outbound volume"; `transfers_anomalous_volume` as
"byte volume between subject and target deviates from its own baseline". With
no direction observed, only the second sentence is grounded — and the first
was being asserted at CRITICAL, 176 times, each one adding a distinct
predicate to a host and multiplying its priority.

**This is rule 6 one level up.** "Absent is not zero" was written as a rule
about arithmetic: do not substitute a value for a measurement you do not have.
It is really a rule about claims. A component dropped from a score, and a
claim left standing that the component was the only evidence for, are the same
error — and the second is harder to see, because the arithmetic looks
scrupulous right up to the point where the verb is chosen. The roadmap's rule
6 now says so in three levels rather than one, because there turned out to be
a third.

The fix is that the predicate is now a function of **which signals were
measured**, and only then of the score. `exfiltrates_to` requires the egress
ratio; `transfers_anomalous_volume` requires the volume deviation. On NetFlow
the critical claim is unreachable at any score, and a test asserts that using
a transfer that *does* clear the exfiltration threshold with the ratio
omitted — so the gate cannot quietly become the threshold doing the work.

**The synthetic corpus could not have caught this.** Its traffic is Zeek-
shaped and carries `resp_bytes` on every flow, so the ratio is always
measured, the exfiltration claim is always grounded, and the bug is invisible
by construction. The corpus can be run with the column dropped — the table
above does exactly that — but that only tests whether the *score* survives
omission, which it did. Nothing in a corpus that always has direction can ask
whether a claim about direction should still be made without it. That question
only exists once a real sensor that cannot supply it is in the picture, which
is the argument for running on real captures early, restated for the fourth
time on this page.

### And the predicate fix alone did not restore the rank

It was not expected to. Demoting the verb changes what is claimed and at what
severity; it does not change how many pairs are reported, what confidence they
carry, or how many *distinct predicates* a host ends up with — and queue
priority is a noisy-OR over the strongest finding per predicate, multiplied by
the count of distinct behaviours. A host that was corroborating with
`exfiltrates_to` corroborates identically with `transfers_anomalous_volume`.
Re-run, scenario 3 stayed at rank 5.

The third level of rule 6 is what moved it. `transfers_anomalous_volume` is,
by construction, the claim the analyzer makes when it *cannot* make the
stronger one — the direction was not recorded, or the four signals did not
reach the exfiltration threshold. Partial evidence, every time. Partial
evidence may be reported; it may not be counted as an independent behaviour.
So the predicate joins `CorrelationConfig.non_corroborating`, where it still
contributes to the incident's combined confidence through the noisy-OR and
still appears in front of the analyst, but no longer multiplies a priority.

| | before this analyzer | predicate by score | + predicate grounded | + volume non-corroborating |
|---|---|---|---|---|
| **Scenario 3 — infected host rank** | **2 / 214** | 5 / 247 | 5 / 247 | **2 / 247** |
| Scenario 3 — corroborated incidents | 3 | 33 | 33 | **3** |
| **Scenario 6 — infected host rank** | **1 / 133** | 1 | 1 | **1 / 160** |
| Scenario 6 — corroborated incidents | 1 | 16 | 16 | **1** |

Scenario 6's rank is given without a denominator in the two middle columns;
the incident count was not recorded for those runs and is not filled in from
the column beside it.

Both captures are restored, with a third analyzer running and its findings
kept. The scenario 6 bot's incident still carries its
`transfers_anomalous_volume` finding: evidence retained, false promotion
removed. That is the outcome to want from this rule — not silence, but a
finding that informs without inflating.

### Why the byte floor is not the lever, and will not be moved

The obvious response to 176 findings is to raise `min_bytes`. Three
measurements say not to.

**The scenario 6 volume finding sits on the real Menti command-and-control
channel, at 2.16 MB.** It is the only real-world true positive this analyzer
has. A 10 MB floor — the size that would have suppressed most of scenario 3's
noise — discards it.

**Scenario 3's infected host has no volume finding at all.** So on that
capture the floor is being tuned entirely against traffic that contains no
true positive to protect.

**And confidence does not separate them either.** Scenario 3's noise scores a
median of **0.851**. The scenario 6 true positive scores **0.487**. The noise
outranks the real detection by a wide margin on the very number a threshold
would sort by. There is no value of `min_bytes`, and no value of
`volume_threshold`, that keeps the true positive and drops the noise, because
on both axes the noise is on the wrong side of it.

This is the same lesson the alert-burden section reached from the other
direction: when a detector's own axis cannot separate signal from noise, the
answer is not a tighter threshold on that axis. It is to stop letting the
finding carry more weight than its evidence supports.

**`orig_bytes` does mean different things on different sensors, and that is
recorded rather than tuned around.** On Zeek it is the originator's bytes; on
NetFlow it is the whole flow's total in both directions, because that is the
only figure the format carries and `ingest/netflow.py` says so in a comment.
The same `min_bytes` constant is therefore a lower bar on NetFlow than on
Zeek. That is a real property of the telemetry, documented here so a reader
knows what the floor means on their sensor — not a defect to be corrected by
picking a number that suits one capture.

---

## 8. What is still open

**Corroboration is broad but shallow on real data.** Five analyzers now
exist, and multi-way corroboration ranks correctly on synthetic traffic. But
CTU-13 carries neither DNS query names nor alerts, so on the real captures the
signal is still only two-valued. Closing that needs a capture with network,
DNS and alert telemetry together — which is a data problem, not a code one.

**Volume and egress has no real accuracy figure, and may not get one here.**
CTU-13 gives it queue ranks and corroboration counts — section 7 — but not a
precision number: the corpus labels spam, scanning and click fraud rather than
transfers, so there is nothing to score a volume detector against. Its one
real true positive is scenario 6's Menti channel at 2.16 MB. Closing that
needs a capture with labelled exfiltration in it, which is a data problem
rather than a code one.

**The estate has no identity.** VoidAI does not know which of its hosts is a
mail relay, a resolver, or a domain controller. `147.32.84.229` ranks first on
scenario 3 because it reaches 162,612 destinations, which is exactly what a
gateway does. The volume analyzer meets the same wall from the other side: its
single false positive is a backup target that exactly one machine uses, which
no signal available to it can distinguish from a private drop box. An asset
inventory would demote both in one step, and the `AnalysisContext` already
carries `ip_to_host` for exactly this.

**Memory headroom on the largest capture.** 2,662 MB does fit a 4GB board —
measured against a hard cgroup ceiling, section 3 — but with roughly 1.1 GB
spare rather than a wide margin. A third analyzer did not change that, and a
fourth need not either, but nothing enforces it. Windowing pass 1 would lower
it further.

---

## 9. Energy

Every figure on this page was produced on x86_64 with **estimated** energy —
this container exposes no RAPL counters, and the fallback profile deliberately
overstates draw (15 W idle + 12 W/active-core). Those numbers are indicative
only and are labelled as such in every receipt.

Measured energy requires either RAPL access or an ARM board with INA rails.
Pending real hardware, no energy claim in this project should be treated as
verified.

---

## 10. Reproducing

```bash
# Synthetic — no download required. Prints two tables: beaconing (section 1)
# and volume-and-egress (section 7), scored against separate corpora.
voidai bench

# CTU-13 scenario 6 (245MB) and scenario 3 (1.4GB)
mkdir -p data/ctu13 && cd data/ctu13
curl -O https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/capture20110816.pcap.netflow.labeled
curl -O https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/capture20110812.pcap.netflow.labeled
```

Captures are not committed — they total 1.7GB and are freely redistributable
from the source above under CC-BY.
