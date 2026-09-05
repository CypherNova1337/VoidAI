"""Robust statistics shared by the analyzers.

Everything here is a pure function over NumPy arrays: no I/O, no Lexicon
types, no configuration. That separation exists so the detection mathematics
can be unit-tested against hand-computed values, independently of the
plumbing that feeds it.

Robust estimators (median, MAD, Bowley skewness) are used throughout in
preference to mean and standard deviation. Security telemetry is heavy-tailed
and full of outliers; a single 40-minute connection stall should not erase the
evidence of two hundred regular check-ins on either side of it.
"""

from __future__ import annotations

import math

import numpy as np

_EPS = 1e-12


def median_absolute_deviation(values: np.ndarray) -> float:
    """MAD: the median of absolute deviations from the median.

    A breakdown point of 50% — half the samples can be arbitrarily corrupted
    before the estimate is. Standard deviation breaks at a single outlier.
    """
    if values.size == 0:
        return 0.0
    median = float(np.median(values))
    return float(np.median(np.abs(values - median)))


def coefficient_of_dispersion(values: np.ndarray) -> float:
    """MAD normalised by the median: a scale-free measure of raggedness.

    Returns 0.0 for a perfectly uniform series. A beacon at 60s ± 6s scores
    0.1; unstructured human browsing typically lands well above 0.5.
    """
    if values.size == 0:
        return 1.0
    median = float(np.median(values))
    if abs(median) < _EPS:
        # Degenerate: the median carries no scale to normalise by. An all-zero
        # byte column is *literally* uniform, but reporting that as perfect
        # regularity hands a free maximum to a sensor that recorded nothing.
        # Maximally dispersed is the honest answer in both directions.
        return 1.0
    return median_absolute_deviation(values) / abs(median)


def schedule_floor_dispersion(values: np.ndarray) -> float:
    """Spread of the *lower* half of an interval distribution, scale-free.

    A scheduled process has a hard floor and a soft ceiling. An implant told to
    sleep thirty seconds cannot call home in twenty — but it can easily take
    sixty, because a check-in was missed, the host slept, or the network
    stalled. So the informative part of the distribution is its bottom edge:
    tight for anything driven by a timer, ragged for anything driven by a
    person.

    Measured as `(q2 - q1) / q2`, which is near zero for a scheduler and large
    for interactive traffic.

    This replaces an earlier symmetry test built on Bowley skewness, which was
    wrong in a way only real captures revealed. Synthetic beacons generated
    with `uniform(±jitter)` are symmetric by construction, so the measure
    scored perfectly against them and looked strong. Real command-and-control
    is heavily *right*-skewed — the CTU-13 Menti channel scores +0.95, its long
    tail being missed check-ins at two, three, and five times the base period.
    The old measure therefore penalised precisely the evidence it should have
    rewarded. Judging the floor instead is both more discriminating and easier
    to justify to an analyst.
    """
    if values.size < 4:
        return 0.0
    q1, q2 = (float(x) for x in np.percentile(values, [25, 50]))
    if q2 < _EPS:
        return 1.0
    return max(0.0, (q2 - q1) / q2)


def autocorrelation_at_period(
    timestamps: np.ndarray,
    period: float,
    jitter_scale: float = 0.0,
    max_bins: int = 200_000,
) -> float | None:
    """How strongly the event series repeats at `period`, in [0, 1].

    The interval statistics above are blind to a beacon that misses check-ins:
    a dropped interval becomes one double-length gap and inflates the
    dispersion. Binning the arrival times and autocorrelating recovers the
    underlying rhythm through those gaps.

    Bin width adapts to the observed jitter. A fixed fraction of the period
    fails exactly where this measurement is most needed: under heavy jitter,
    arrivals smear across several narrow bins and the correlation peak
    dissolves. Widening the bins to roughly the jitter envelope reassembles
    it. `jitter_scale` should be the MAD of the inter-arrival intervals.

    Returns `None` — not zero — when the jitter is too large for the period to
    be resolvable at all. That distinction matters downstream: an unmeasurable
    signal must be dropped from the score, whereas a zero would be read as
    positive evidence of *aperiodicity* and would wrongly sink the pair.
    """
    if timestamps.size < 8 or period <= 0:
        return None

    span = float(timestamps[-1] - timestamps[0])
    if span <= 0:
        return None

    # Bins are never narrower than a quarter period — beyond that, resolution
    # buys nothing and only thins the correlation — and never coarser than
    # half, which is the Nyquist limit for expressing the period at all.
    resolution = min(max(2.5 * jitter_scale, period / 4.0), period / 2.0)
    if 2.5 * jitter_scale > period / 2.0:
        return None

    bin_count = int(span / resolution) + 1
    if bin_count > max_bins:
        # Widen bins rather than allocate without bound: memory stays flat on
        # a Pi regardless of capture length. If the widening pushes past
        # Nyquist the period is no longer expressible, and that is reported as
        # unmeasurable rather than papered over with a degraded number.
        resolution = span / max_bins
        bin_count = max_bins
        if resolution > period / 2.0:
            return None

    indices = ((timestamps - timestamps[0]) / resolution).astype(np.int64)
    np.clip(indices, 0, bin_count - 1, out=indices)
    counts = np.bincount(indices, minlength=bin_count).astype(np.float64)

    signal = counts - counts.mean()
    energy = float(np.dot(signal, signal))
    if energy < _EPS:
        return None

    # One period spans this many lags at the chosen resolution.
    period_lag = period / resolution
    lag_from = max(1, round(period_lag * 0.8))
    lag_to = min(round(period_lag * 1.2), signal.size - 1)
    if lag_to < lag_from:
        return None

    best = 0.0
    for lag in range(lag_from, lag_to + 1):
        correlation = float(np.dot(signal[:-lag], signal[lag:])) / energy
        best = max(best, correlation)
    return float(np.clip(best, 0.0, 1.0))


def bimodal_gap_threshold(
    intervals: np.ndarray,
    min_separation_decades: float = 1.0,
    min_mass: float = 0.10,
    bins: int = 64,
) -> float | None:
    """Find the valley separating intra-burst from inter-burst intervals.

    One logical check-in rarely arrives as one telemetry record. NetFlow
    exporters emit a record per direction and split long connections at the
    active timeout; Zeek logs a separate connection for each TCP session in a
    keep-alive sequence. The result is that a 33-second beacon appears as
    hundreds of records whose *median* interval is 0.15 seconds, and every
    statistic computed downstream then describes record framing rather than
    the beacon.

    Such a series is strongly bimodal in log space: a tight cluster of
    near-zero intra-burst gaps, a wide valley, then the true period. The split
    is found with Otsu's method — the threshold maximising between-class
    variance.

    Otsu rather than the largest gap between consecutive sorted intervals: a
    handful of intermediate values bridge the valley in real captures (a
    retransmit here, a truncated flow there), and any single-gap rule silently
    fails on exactly the traffic this is meant to fix. Otsu weighs the whole
    distribution, so a few bridging samples cannot hide the split.

    Because Otsu always returns *some* threshold, two guards decide whether
    there is really anything to split:

      `min_separation_decades` — the class means must differ by this much,
        so a merely broad unimodal distribution is not carved in half.
      `min_mass` — each class must hold this share of the samples, so one
        outlying gap cannot be promoted to a mode of its own.

    Returns `None` when neither holds, which is the common case for
    well-formed connection logs: no valley, no coalescing, no change in
    behaviour. Only telemetry that needs the correction receives it.
    """
    positive = intervals[intervals > 0]
    if positive.size < 8:
        return None

    log_intervals = np.log10(positive)
    spread = float(log_intervals.max() - log_intervals.min())
    if spread < min_separation_decades:
        return None  # everything within one decade: nothing to separate

    counts, edges = np.histogram(log_intervals, bins=bins)
    centres = (edges[:-1] + edges[1:]) / 2.0
    total = counts.sum()
    if total == 0:
        return None

    weights = counts / total
    # Cumulative mass and mean below each candidate split.
    mass_below = np.cumsum(weights)[:-1]
    mass_above = 1.0 - mass_below
    mean_total = float(np.dot(weights, centres))
    mean_below_cum = np.cumsum(weights * centres)[:-1]

    valid = (mass_below > 0) & (mass_above > 0)
    if not valid.any():
        return None

    between_variance = np.where(
        valid,
        (mean_total * mass_below - mean_below_cum) ** 2 / np.maximum(mass_below * mass_above, _EPS),
        -1.0,
    )
    split = int(np.argmax(between_variance))

    below = log_intervals[log_intervals <= centres[split]]
    above = log_intervals[log_intervals > centres[split]]
    if below.size == 0 or above.size == 0:
        return None

    share = min(below.size, above.size) / log_intervals.size
    separation = float(above.mean() - below.mean())
    if separation < min_separation_decades or share < min_mass:
        return None

    return float(10 ** centres[split])


def coalesce_bursts(
    timestamps: np.ndarray,
    values: np.ndarray,
    threshold: float,
) -> tuple[np.ndarray, np.ndarray]:
    """Collapse runs of closely-spaced events into one event each.

    Returns the timestamp that *started* each burst, paired with the summed
    values across it. The start is the meaningful instant — it is when the
    implant decided to call home — and summing bytes keeps the payload figure
    describing one whole check-in rather than one fragment of it.

    A burst holding no finite value at all sums to NaN rather than to zero.
    The distinction matters: zero means the sensor saw an empty payload, NaN
    means it recorded no payload figure, and only the second should cause the
    payload measurement to be dropped and its weight redistributed.
    """
    if timestamps.size == 0:
        return timestamps, values

    order = np.argsort(timestamps)
    timestamps, values = timestamps[order], values[order]

    is_start = np.concatenate([[True], np.diff(timestamps) > threshold])
    starts = timestamps[is_start]

    group = np.cumsum(is_start) - 1
    finite = np.isfinite(values)
    totals = np.bincount(group, weights=np.where(finite, values, 0.0))
    measured = np.bincount(group, weights=finite.astype(np.float64))
    totals[measured == 0] = np.nan

    return starts, totals


def robust_deviation(value: float, baseline: np.ndarray) -> float | None:
    """How far `value` sits from a baseline, in robust standard deviations.

    The modified z-score, `(value - median) / (1.4826 * MAD)`. The constant
    rescales MAD onto the standard deviation of a normal distribution, so the
    result reads on the familiar sigma scale while keeping MAD's 50% breakdown
    point — which matters here, because the baseline this is measured against
    is a host's own byte volumes and those are heavy-tailed by nature.

    Returns `None` — not zero — when the baseline cannot support an estimate:
    fewer than three samples, or a MAD of zero because the samples are
    identical. The distinction is the same one `autocorrelation_at_period`
    draws. An unmeasurable deviation has to be dropped from a score and its
    weight redistributed, whereas a zero asserts that the value is *typical*,
    which is a different claim and an unearned one.
    """
    if baseline.size < 3:
        return None
    median = float(np.median(baseline))
    mad = median_absolute_deviation(baseline)
    if mad < _EPS:
        return None
    return (value - median) / (1.4826 * mad)


def destination_rarity(contacting_hosts: int) -> float:
    """Prior on a destination being adversary infrastructure, from prevalence.

    Estate-wide frequency analysis — "stacking", in hunt parlance. A C2
    endpoint is typically reached by one or a handful of compromised hosts. A
    software update endpoint is reached by everything you own. One host scores
    1.0, four score 0.5, twelve score 0.29.

    This is a prior, not proof: widely-deployed malware inverts it. It is
    weighted lightly for that reason, and it can only ever attenuate a score
    that the behavioural measurements already support.
    """
    return 1.0 / math.sqrt(max(contacting_hosts, 1))


def shannon_entropy(text: str) -> float:
    """Per-character Shannon entropy in bits.

    Used by the DNS analyzer: an encoded exfiltration label approaches the
    ~4.7 bits of uniform base32, while English-like hostnames sit near 3.2.
    """
    if not text:
        return 0.0
    counts = np.bincount(np.frombuffer(text.encode("utf-8", "replace"), dtype=np.uint8))
    counts = counts[counts > 0].astype(np.float64)
    probabilities = counts / counts.sum()
    return float(-np.sum(probabilities * np.log2(probabilities)))


def saturating(value: float, target: float) -> float:
    """Map [0, ∞) to [0, 1), reaching ~0.63 at `target`.

    Used for "more is better, but with diminishing returns" quantities such as
    connection counts, where 500 samples is not meaningfully stronger evidence
    than 200.
    """
    if target <= 0:
        return 0.0
    return 1.0 - math.exp(-max(value, 0.0) / target)


def weighted_geometric_mean(scores: dict[str, float], weights: dict[str, float], floor: float = 0.01) -> float:
    """Combine sub-scores multiplicatively rather than additively.

    An arithmetic mean lets one strong signal carry a detection over the
    threshold on its own — which is precisely how a periodic software updater
    gets reported as command-and-control. A geometric mean requires every
    dimension to hold up: a near-zero component drags the result down no
    matter how good the others look.

    `floor` keeps a single zero from annihilating the product outright, so the
    ranking below threshold stays informative.

    Components absent from `scores` are dropped and the weights renormalise
    over what remains. A sensor that does not log payload bytes therefore
    yields a score computed from the signals that *were* observable, rather
    than one silently penalised for a missing column.
    """
    total_weight = sum(weights.get(k, 0.0) for k in scores)
    if total_weight <= 0:
        return 0.0
    accumulated = sum(
        weights.get(name, 0.0) * math.log(max(score, floor)) for name, score in scores.items()
    )
    return float(np.clip(math.exp(accumulated / total_weight), 0.0, 1.0))
