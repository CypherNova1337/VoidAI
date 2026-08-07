<div align="center">

# VoidAI

**A local-first, evidence-bound agent runtime for cyber defence.**

*Runs on a $80 board. Cites every claim. Tells you what it cost.*

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Arch](https://img.shields.io/badge/arch-aarch64%20%7C%20x86__64-lightgrey.svg)](docs/deployment.md)

</div>

---

> *"The limits of my language mean the limits of my world."*
> — Ludwig Wittgenstein

VoidAI takes that sentence literally.

Most security AI is a language model holding a log file, asked politely not to
make things up. It makes things up anyway, because nothing in its architecture
prevents it. The model's world is unbounded, so its claims are too.

VoidAI inverts this. At its centre is the **Lexicon** — a closed, typed
vocabulary of propositions the system is permitted to assert, and a grammar
governing which nouns each verb accepts. An assertion outside the Lexicon is
not "low confidence." It is **unsayable**: it has no representation, so it
cannot reach an analyst. Every proposition that *is* sayable must carry a chain
of custody down to a specific byte range in a specific source file.

The result is a defensive AI that cannot hallucinate a finding, because
findings are not something it is able to author freely.

---

## The architectural bet

```
   telemetry ──▶  Ingest  ──▶  Analyzers  ──▶  Correlate  ──▶  Reason  ──▶  Propose
                 (parsers)    (statistics,     (entity        (small      (analyst
                              no model)         graph)         model)      approves)
                                        │
                    Lexicon ────────────┴──────── binds every stage
                                        │
                    Receipt ── joules · tokens · seconds · watts
```

**The language model never sees a raw log.**

Detection is done by deterministic parsers and vectorised statistics. The model
receives only a compressed, token-budgeted *evidence brief* — a few hundred
tokens of already-grounded findings — and does the three things it is genuinely
good at: ranking competing hypotheses, narrating a correlation, and
recommending an analyst's next step. Its output is constrained to a Lexicon
schema and then passed through a **claim verifier** that strikes any sentence
whose cited evidence IDs do not resolve.

This is what lets VoidAI run at four tokens per second on a Raspberry Pi and
still process gigabytes of telemetry. It is also why the detection quality is
identical with the model switched off:

```console
$ voidai run ./capture --no-llm
```

You lose the narrative. You do not lose a single finding. **Detection was never
the model's job.**

---

## What it does today

| Agent | Method | Status |
|---|---|---|
| **C2 Beaconing Analyzer** | Six-signal ensemble: interval regularity, Bowley symmetry, payload uniformity, adaptive-bin autocorrelation, coverage, estate-wide destination rarity | **working** |
| **DNS Tunnelling Detector** | Label entropy, subdomain cardinality, NXDOMAIN ratio, qtype skew | planned |
| **Suricata Alert Triage** | Alert deduplication, entity clustering, priority reranking | planned |
| **Web Attack Detector** | Signature + statistical hybrid over access logs | planned |
| **Hunt Query Generator** | Confirmed incident → Sigma / KQL / SPL / Zeek | planned |

On the seeded 24-hour benchmark corpus — four implants from textbook-60s to a
50%-jittered low-and-slow, hidden among browsing traffic, a monitoring agent,
an update checker, and NTP:

```
precision 1.000 · recall 1.000 · f1 1.000        (4 TP · 0 FP · 0 FN)
55,983 records → 4 findings in 0.24s             (230,628 rec/s, x86_64, 4 cores)
```

Reproduce with `voidai bench`. Same seed, same corpus, same numbers.

---

## Design commitments

These are constraints on the codebase, enforced in review and in tests — not
aspirations.

**Nothing leaves the machine.** No telemetry, no API calls, no model
downloads at runtime, no update checks. VoidAI runs correctly with the network
interface down, and the test suite asserts it.

**Every dependency installs on a Pi.** No CUDA, no compiler toolchain, no
wheel that lacks an `aarch64` build. The language layer is an *optional extra*;
the core is six libraries.

**Small by construction.** The target model tier is 1.7B–4B parameters at
4-bit quantisation. If a finding requires a larger model, the correct fix is a
better analyzer, not a bigger model.

**Semi-autonomous, always.** VoidAI proposes; a human disposes. It has no
capability to block an IP, kill a process, or modify a rule. Actions are
emitted as reviewed recommendations, and there is no execution path — by
absence, not by policy toggle.

**Self-accounting.** Every run prints an itemised receipt: joules, tokens,
wall time, peak RSS. Energy is labelled `measured` when it comes from a real
counter (RAPL, INA3221) and `estimated` when it comes from a platform model.
An estimate is never dressed up as a measurement.

---

## Installation

```bash
git clone https://github.com/CypherNova1337/VoidAI
cd VoidAI
python3 -m venv .venv && source .venv/bin/activate

pip install -e .            # core: detection, correlation, receipts
pip install -e ".[llm]"     # optional: the narrative layer
pip install -e ".[tui]"     # optional: the operator console
```

Core install pulls six runtime dependencies and needs no compiler.

## Usage

```bash
voidai run ./zeek-logs/                 # detection pipeline over a log directory
voidai run ./zeek-logs/ --evidence      # print the full evidence chain per finding
voidai bench                            # reproducible accuracy + energy benchmark
voidai lexicon                          # print the complete grammar
voidai version                          # version and detected power profile
```

Every command prints a run receipt unless given `--no-receipt`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
