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

The reference target. 8GB is recommended; see the memory note below for 4GB.

```bash
sudo apt install -y python3-venv python3-dev
git clone https://github.com/CypherNova1337/VoidAI && cd VoidAI
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
voidai doctor
```

The core install needs no compiler. `pip install -e ".[llm]"` does —
`llama-cpp-python` builds from source on ARM and takes several minutes.

### Memory

The 66-hour CTU-13 scenario (12.7M flows) peaks at **2.7GB**. That fits an
8GB Pi 5 comfortably and does not fit a 4GB one.

On a 4GB board, process in windows rather than in one shot:

```bash
for log in /var/log/zeek/*/conn.*.log.gz; do voidai run "$(dirname "$log")"; done
```

This is what a real deployment does anyway — hourly or daily batches, not
three days of telemetry at once.

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
