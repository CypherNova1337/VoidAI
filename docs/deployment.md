# Deployment

VoidAI is architecture-agnostic: pure Python, no compiled extensions in the
core, and no dependency that lacks an `aarch64` wheel. It runs the same way on
x86_64 and on ARM.

Start with:

```bash
voidai doctor
```

which reports the platform, whether energy will be **measured** or
**estimated**, and whether the optional narrative layer is present — before
you run a benchmark rather than after.

---

## Raspberry Pi 5

The reference target. **4GB is enough**, including for the largest capture in
this repository — measured, not assumed; see the memory section below.

```bash
sudo apt install -y python3-venv python3-dev
git clone https://github.com/CypherNova1337/VoidAI && cd VoidAI
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
voidai doctor
```

The core install needs no compiler. `pip install -e ".[llm]"` does —
`llama-cpp-python` builds from source on ARM and takes several minutes.

### Memory — measured against a board's ceiling, not estimated

An earlier version of this document claimed the 66-hour capture did not fit a
4GB Pi. That was a guess from a peak-RSS figure, and it was wrong. `tools/envelope.py`
puts the workload inside a cgroup with a hard memory limit and swap pinned to
the same value — the same mechanism a board with no swap enforces — so the
question can be answered by running it:

```bash
sudo python3 tools/envelope.py --board pi5-4gb --reserve-mb 400 -- \
    voidai bench --real data/ctu13/botnet-44-scenario03.netflow.labeled
```

**What each workload actually needs** (peak charge, and the smallest ceiling
it survives):

| Workload | Records | Peak | Smallest ceiling that completes |
|---|---|---|---|
| `voidai demo` | 74,157 | 231 MB | **512 MB** |
| `pytest` (361 tests) | — | 286 MB | ≤1 GB |
| CTU-13 scenario 6 | 1.9M | 550 MB | **768 MB** |
| CTU-13 scenario 3 | 12.7M | 2,545 MB | **2.6 GB** |
| Detection + Qwen2.5-1.5B q4\_k\_m | 74,157 | 2,072 MB | ~2.5 GB |

**Where the 66-hour capture actually breaks**, bisected against a hard ceiling:

| Ceiling | Outcome |
|---|---|
| 2,000–2,400 MB | OOM-killed, every run |
| 2,500 MB | **flaky** — killed on one run, completed on the next |
| 2,600 MB | completes |
| 3,000 MB | completes, peak settles at 2,545 MB |
| 3,696 MB (4GB board less 400 MB for the OS) | completes |

The flakiness at exactly 2,500 MB is the useful part: it is what "running at
the wall" looks like, and it is why the recommendation is 2.6 GB of *free*
memory rather than the bare peak. A 4GB Pi 5 clears that with about 1.1 GB to
spare, and the full pipeline including the language model peaks at 2,072 MB —
1.6 GB of headroom on the same board.

Windowing is still what a real deployment does — hourly or daily batches, not
three days of telemetry at once — but it is now a convenience, not a
requirement:

```bash
for log in /var/log/zeek/*/conn.*.log.gz; do voidai run "$(dirname "$log")"; done
```

### CPU — a curve, because a quota is not a Cortex-A76

The same harness caps CPU with a CFS quota. A quota can make a core slower but
cannot give it a different microarchitecture, so no single setting *is* a Pi.
What it produces instead is a scaling curve that real hardware can be located
on with one run. Measured on CTU-13 scenario 6, 1.9M flows, memory
unconstrained:

| CPU quota | Wall | Throughput |
|---|---|---|
| 400% (4 cores) | 8.5 s | 284k rec/s |
| 300% | 10.2 s | 235k rec/s |
| 200% | 14.2 s | 169k rec/s |
| 100% (1 core) | 25.3 s | 95k rec/s |
| 50% | 52.5 s | 45k rec/s |

Four cores return 3.0× the throughput of one, so the pipeline parallelises at
about 75% efficiency.

The load-bearing result is the combined envelope. The 12.7M-flow capture, held
to 3 GB and a *single* 2.1GHz core, completes in **166 seconds** — and returns
the infected host at **queue rank 2 of 214, identical to the unconstrained
run**. Constraining the board changes how long the answer takes, not what the
answer is:

| Envelope | Wall | Throughput | Infected host |
|---|---|---|---|
| 3,000 MB @ 200% | 84.8 s | 179k rec/s | rank 2 of 214 |
| 3,000 MB @ 100% | 165.8 s | 91k rec/s | rank 2 of 214 |
| 3,696 MB @ 200% | 87.2 s | 173k rec/s | rank 2 of 214 |

### What this harness does not prove

It runs on x86-64. **It is not an ARM test.** aarch64 has different wheels,
128-bit NEON rather than 256-bit AVX2, and a different allocator profile.
Memory ceilings and core counts are reproduced by the kernel's own accounting
and are therefore evidence; the instruction set is not reproduced at all, and
anything that would only fail on ARM passes here. The architecture question
stays open until it runs on the board.

### Getting *measured* energy

The Pi 5 has no on-board power telemetry, so out of the box VoidAI reports
`estimated` from a published power profile. To get a real number, put a
current-sense breakout on the 5V rail. An INA219 or INA260 is the usual
choice and costs a few pounds.

```bash
sudo raspi-config nonint do_i2c 0          # enable I2C
sudo modprobe ina2xx
echo ina219 0x40 | sudo tee /sys/bus/i2c/devices/i2c-1/new_device
```

That creates an hwmon device exposing `power1_input` in microwatts.
`voidai doctor` should then report `measured`, and every receipt switches from
`estimated` to `measured` automatically — VoidAI discovers hwmon power rails
without configuration.

Verify by hand first:

```bash
cat /sys/class/hwmon/hwmon*/power1_input     # microwatts
```

Without a shunt the figures remain honest but indicative, and are labelled as
such everywhere they appear.

---

## NVIDIA Jetson (Orin Nano / NX / AGX)

Jetson modules expose INA3221 rails through hwmon already, so energy is
**measured** with no extra hardware. `voidai doctor` will confirm it.

Detection is CPU-only and does not use CUDA. Building
`llama-cpp-python` with CUDA support is possible and will speed up the
narrative layer considerably, but is not required and is not the tier this
project argues for.

---

## x86_64

Intel and AMD expose RAPL energy counters through `powercap`. Since
CVE-2020-8694 these are root-readable only on most distributions:

```bash
sudo chmod -R a+r /sys/class/powercap/intel-rapl
```

Do that and VoidAI reports `measured` on ordinary hardware. Note that RAPL
covers the CPU package, not the whole board — it understates system draw,
which is the safe direction for a project claiming efficiency.

Many virtual machines and containers expose no counters at all. This is the
case in CI, where every figure is correctly labelled `estimated`.

---

## Running against real telemetry

```bash
voidai run /var/log/zeek/current/          # Zeek conn.log and dns.log
voidai run ./capture/ --evidence           # with the full chain of custody
voidai run ./capture/ --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf
```

Supported inputs:

| Source | Format | Analyzers fed |
|---|---|---|
| Zeek `conn.log` | TSV or JSON, `.gz` accepted | beaconing, fan-out |
| Zeek `dns.log` | TSV or JSON, `.gz` accepted | DNS tunnelling |
| nfdump labelled NetFlow | CTU-13 dialect | beaconing, fan-out |

VoidAI reads logs. It does not capture traffic, and needs no privileged
network access — point it at a sensor's output directory.

## Operating notes

**No network access is required or used.** VoidAI runs with the interface
down; the test suite severs sockets and asserts the pipeline still completes.
There are no update checks, no telemetry, and no runtime model downloads.

**It cannot act.** There is no code path that blocks an address, kills a
process or edits a rule. Recommendations are text. This is enforced by
absence, not by a configuration flag.

**Nothing needs root** except reading energy counters. Detection runs
unprivileged.

## Sizing

Measured on x86_64, 4 cores. ARM will be slower per core; the shape holds.

| Capture | Flows | Wall | Peak RSS |
|---|---|---|---|
| 2 hours | 1.9M | 8.7 s | 0.6 GB |
| 66 hours | 12.7M | 57 s | 2.7 GB |

Detection runs at roughly 220,000 records/second. The narrative layer adds
about 30 seconds per incident narrated on a 1.5B model at 4-bit — it is
metered separately on the receipt for that reason, and `--explain N` bounds
how many incidents are narrated.
