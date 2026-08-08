# Benchmarks

Two corpora, reported separately and never averaged together. The synthetic
corpus proves the mathematics; the real captures prove — or disprove — the
product. Where they disagree, the real captures win.

Everything here is reproducible:

```bash
voidai bench                              # synthetic, seeded
voidai bench --real data/ctu13/<file>     # CTU-13, after fetching a capture
```

---

## 1. Synthetic corpus (seed 1337, 24h)

Six planted implants hidden among browsing traffic, a monitoring agent, a
software update checker, and NTP.

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

| | Scenario 3 | Scenario 6 |
|---|---|---|
| Malware | Rbot | Menti |
| Duration | 66.8h | 2.15h |
| Flows analysed | 12,689,947 | 1,916,655 |
| **Infected host detected** | **yes** | **yes** |
| C2 confidence | **0.958** | 0.749 |
| C2 rank among findings | 204 / 1277 | 358 / 395 |
| **Infected host queue rank** | **2 / 214** | **1 / 133** |
| Findings → incidents | 1328 → 214 | 397 → 133 |
| Corroborated incidents | 3 | 1 |
| Beaconing pair precision | 0.0008 | 0.0025 |
| Throughput | 223,651 rec/s | 219,088 rec/s |
| Peak RSS | 2,672 MB | 634 MB |

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

That fits an 8GB Pi 5 but not a 4GB board. Splitting pass 1 into time windows
and merging partial summaries would fix it — counts sum and min/max combine,
so the merge is exact — but CSV has no random access, so windowing means
either re-parsing per window or moving to a batched reader. A Pi deployment
would realistically process hourly or daily windows rather than 66 hours in
one shot, which is the same fix arriving from the operational direction.

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

## 5. What is still open

**Corroboration needs more than two opinions.** Two analyzers give a binary
signal: corroborated or not. Scenario 3's three corroborated incidents are the
bot, a resolver, and a BitTorrent client — enough to find the intrusion in
three lines, but a DNS-tunnelling or alert-triage analyzer would let the
ranking discriminate *within* that set rather than leaving it to the analyst.

**The estate has no identity.** VoidAI does not know which of its hosts is a
mail relay, a resolver, or a domain controller. `147.32.84.229` ranks first on
scenario 3 because it reaches 162,612 destinations, which is exactly what a
gateway does. An asset inventory would demote it in one step, and the
`AnalysisContext` already carries `ip_to_host` for exactly this.

**Memory on a 4GB board.** 2,672 MB fits an 8GB Pi 5 but not a 4GB one. See
section 3.

---

## 6. Energy

Every figure on this page was produced on x86_64 with **estimated** energy —
this container exposes no RAPL counters, and the fallback profile deliberately
overstates draw (15 W idle + 12 W/active-core). Those numbers are indicative
only and are labelled as such in every receipt.

Measured energy requires either RAPL access or an ARM board with INA rails.
Pending real hardware, no energy claim in this project should be treated as
verified.

---

## 7. Reproducing

```bash
# Synthetic — no download required
voidai bench

# CTU-13 scenario 6 (245MB) and scenario 3 (1.4GB)
mkdir -p data/ctu13 && cd data/ctu13
curl -O https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/capture20110816.pcap.netflow.labeled
curl -O https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/capture20110812.pcap.netflow.labeled
```

Captures are not committed — they total 1.7GB and are freely redistributable
from the source above under CC-BY.
