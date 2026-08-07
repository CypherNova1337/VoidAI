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
        # All values are ~0. Uniform, but degenerate — treat as maximally
        # dispersed rather than perfectly regular, so an all-zero byte count
        # cannot manufacture a high score.
        return 0.0 if float(np.max(np.abs(values))) < _EPS else 1.0
    return median_absolute_deviation(values) / abs(median)


def bowley_skewness(values: np.ndarray) -> float:
    """Quartile-based skewness, bounded to [-1, 1].

    Automated check-ins produce a symmetric interval distribution: jitter is
    applied evenly around a target period. Human-driven traffic skews right,
    with a long tail of idle gaps. Unlike the third-moment skewness this needs
    no variance and does not explode on outliers.
    """
    if values.size < 4:
        return 0.0
    q1, q2, q3 = (float(x) for x in np.percentile(values, [25, 50, 75]))
    spread = q3 - q1
    if spread < _EPS:
        return 0.0  # a perfectly tight distribution is perfectly symmetric
    return (q1 + q3 - 2 * q2) / spread


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
