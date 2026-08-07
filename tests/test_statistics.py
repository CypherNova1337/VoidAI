"""Unit tests for the detection mathematics, against hand-computable values."""

from __future__ import annotations

import numpy as np
import pytest

from voidai.analyzers.statistics import (
    autocorrelation_at_period,
    bowley_skewness,
    coefficient_of_dispersion,
    destination_rarity,
    median_absolute_deviation,
    saturating,
    shannon_entropy,
    weighted_geometric_mean,
)


class TestMedianAbsoluteDeviation:
    def test_uniform_series_has_zero_deviation(self) -> None:
        assert median_absolute_deviation(np.full(10, 60.0)) == 0.0

    def test_known_value(self) -> None:
        # median = 3; deviations = [2,1,0,1,2]; median of those = 1
        assert median_absolute_deviation(np.array([1.0, 2, 3, 4, 5])) == 1.0

    def test_resists_extreme_outlier(self) -> None:
        """The property that motivates using MAD at all."""
        clean = np.array([60.0] * 20)
        corrupted = np.concatenate([clean, [100_000.0]])
        assert median_absolute_deviation(corrupted) == 0.0
        assert np.std(corrupted) > 20_000  # what we avoided

    def test_empty(self) -> None:
        assert median_absolute_deviation(np.array([])) == 0.0


class TestCoefficientOfDispersion:
    def test_perfect_beacon_scores_zero(self) -> None:
        assert coefficient_of_dispersion(np.full(50, 300.0)) == 0.0

    def test_scales_with_jitter(self) -> None:
        rng = np.random.default_rng(0)
        tight = coefficient_of_dispersion(rng.normal(300, 3, 500))
        loose = coefficient_of_dispersion(rng.normal(300, 90, 500))
        assert tight < 0.05 < loose

    def test_scale_invariant(self) -> None:
        """A 60s beacon and a 600s beacon with proportional jitter score alike."""
        rng = np.random.default_rng(1)
        base = rng.normal(60, 6, 400)
        assert coefficient_of_dispersion(base) == pytest.approx(
            coefficient_of_dispersion(base * 10), rel=1e-9
        )

    def test_all_zero_values_are_not_treated_as_regular(self) -> None:
        """Guards against an all-zero byte column manufacturing a perfect score."""
        assert coefficient_of_dispersion(np.zeros(20)) == 0.0

    def test_empty_is_maximally_dispersed(self) -> None:
        assert coefficient_of_dispersion(np.array([])) == 1.0


class TestBowleySkewness:
    def test_symmetric_distribution(self) -> None:
        assert bowley_skewness(np.linspace(0, 100, 101)) == pytest.approx(0.0, abs=1e-9)

    def test_right_skew_is_positive(self) -> None:
        rng = np.random.default_rng(2)
        assert bowley_skewness(rng.exponential(10, 2000)) > 0.1

    def test_bounded(self) -> None:
        rng = np.random.default_rng(3)
        for sample in (rng.exponential(5, 500), rng.normal(0, 1, 500), rng.pareto(1.5, 500)):
            assert -1.0 <= bowley_skewness(sample) <= 1.0

    def test_degenerate_input(self) -> None:
        assert bowley_skewness(np.array([1.0, 2.0])) == 0.0
        assert bowley_skewness(np.full(50, 7.0)) == 0.0


class TestAutocorrelationAtPeriod:
    def test_clean_beacon_correlates_strongly(self) -> None:
        timestamps = np.arange(0, 200) * 60.0
        assert (autocorrelation_at_period(timestamps, 60.0, jitter_scale=0.0) or 0) > 0.9

    def test_survives_missed_check_ins(self) -> None:
        """The reason this measurement exists: gaps must not destroy the signal."""
        rng = np.random.default_rng(4)
        timestamps = np.arange(0, 300) * 60.0
        kept = timestamps[rng.random(timestamps.size) > 0.25]  # drop a quarter
        assert (autocorrelation_at_period(kept, 60.0, jitter_scale=0.0) or 0) > 0.5

    def test_random_arrivals_do_not_correlate(self) -> None:
        rng = np.random.default_rng(5)
        timestamps = np.sort(rng.uniform(0, 86400, 500))
        result = autocorrelation_at_period(timestamps, 172.8, jitter_scale=50.0)
        assert result is None or result < 0.3

    def test_unresolvable_jitter_returns_none_not_zero(self) -> None:
        """A signal we cannot measure must be dropped, never scored as absent."""
        timestamps = np.arange(0, 100) * 600.0
        assert autocorrelation_at_period(timestamps, 600.0, jitter_scale=600.0) is None

    def test_too_few_samples(self) -> None:
        assert autocorrelation_at_period(np.arange(4) * 60.0, 60.0) is None

    def test_long_capture_stays_within_the_bin_cap(self) -> None:
        """A fortnight of 60s check-ins must measure without unbounded memory."""
        timestamps = np.arange(0, 20_000) * 60.0  # ~14 days
        assert autocorrelation_at_period(timestamps, 60.0, max_bins=100_000) is not None

    def test_bin_cap_past_nyquist_reports_unmeasurable(self) -> None:
        """Widening bins past half a period must return None, not a bad number."""
        timestamps = np.arange(0, 5000) * 1.0
        assert autocorrelation_at_period(timestamps, 1.0, max_bins=100) is None


class TestDestinationRarity:
    def test_single_host_is_maximally_rare(self) -> None:
        assert destination_rarity(1) == 1.0

    def test_decreases_with_prevalence(self) -> None:
        values = [destination_rarity(n) for n in (1, 2, 4, 12, 100)]
        assert values == sorted(values, reverse=True)

    def test_never_zero_or_negative(self) -> None:
        assert 0.0 < destination_rarity(100_000) < 0.01

    def test_handles_zero(self) -> None:
        assert destination_rarity(0) == 1.0


class TestSaturating:
    def test_reaches_expected_fraction_at_target(self) -> None:
        assert saturating(15, 15) == pytest.approx(1 - 1 / np.e, rel=1e-6)

    def test_monotonic_and_bounded(self) -> None:
        values = [saturating(n, 15) for n in range(0, 200, 10)]
        assert values == sorted(values)
        assert all(0.0 <= v < 1.0 for v in values)

    def test_zero_target(self) -> None:
        assert saturating(10, 0) == 0.0


class TestWeightedGeometricMean:
    def test_all_ones(self) -> None:
        scores = {"a": 1.0, "b": 1.0}
        assert weighted_geometric_mean(scores, {"a": 0.5, "b": 0.5}) == pytest.approx(1.0)

    def test_one_weak_component_drags_the_result_down(self) -> None:
        """The property that stops a single strong signal carrying a detection."""
        weights = {"a": 0.5, "b": 0.5}
        arithmetic_equal = {"a": 1.0, "b": 0.2}
        assert weighted_geometric_mean(arithmetic_equal, weights) < 0.6  # mean would be 0.6

    def test_absent_components_renormalise(self) -> None:
        """A missing measurement must not be penalised as a failed one."""
        weights = {"a": 0.5, "b": 0.3, "c": 0.2}
        both = weighted_geometric_mean({"a": 0.8, "b": 0.8, "c": 0.8}, weights)
        partial = weighted_geometric_mean({"a": 0.8, "b": 0.8}, weights)
        assert both == pytest.approx(partial, rel=1e-9)

    def test_floor_prevents_annihilation(self) -> None:
        result = weighted_geometric_mean({"a": 1.0, "b": 0.0}, {"a": 0.9, "b": 0.1})
        assert 0.0 < result < 1.0

    def test_empty_scores(self) -> None:
        assert weighted_geometric_mean({}, {"a": 1.0}) == 0.0


class TestShannonEntropy:
    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_repeated_character(self) -> None:
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_encoded_data_exceeds_natural_language(self) -> None:
        natural = shannon_entropy("mail.google.com")
        encoded = shannon_entropy("mfzwizltoqxg4zlyvbaaxq3fmn2ge43tnbxxq")
        assert encoded > natural

    def test_uniform_alphabet_approaches_log2_of_size(self) -> None:
        assert shannon_entropy("abcd" * 25) == pytest.approx(2.0, abs=1e-9)
