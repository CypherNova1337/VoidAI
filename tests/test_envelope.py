"""Tests for the Pi resource-envelope harness.

The harness makes a claim about the world — "this workload survives a 4GB
board" — so the way it fails matters as much as the way it works. A ceiling
that silently did not apply would turn every result it prints into a
fabrication, which is the one outcome this project cannot tolerate anywhere.

The cgroup tests need root and cgroup v1, so they skip rather than fail
elsewhere. The skip is deliberate and visible: a green suite on a machine that
cannot enforce a ceiling has not verified that ceilings are enforced.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from envelope import BOARDS, CgroupUnavailableError, Envelope, Result, run_once

CGROUP_V1_MEMORY = Path("/sys/fs/cgroup/memory")
MIB = 1024 * 1024

needs_cgroups = pytest.mark.skipif(
    os.geteuid() != 0 or not CGROUP_V1_MEMORY.is_dir(),
    reason="needs root and a cgroup v1 memory controller",
)


class TestBoards:
    def test_every_board_declares_memory_and_cores(self) -> None:
        for name, (memory, cores) in BOARDS.items():
            assert memory > 0, name
            assert cores > 0, name

    def test_the_pi5_variants_differ_only_in_memory(self) -> None:
        assert BOARDS["pi5-4gb"][1] == BOARDS["pi5-8gb"][1] == 4
        assert BOARDS["pi5-8gb"][0] == 2 * BOARDS["pi5-4gb"][0]


class TestResultReporting:
    def _result(self, **kwargs: object) -> Result:
        base = dict(
            board="pi5-4gb",
            limit_bytes=4096 * MIB,
            cpu_quota_percent=None,
            command="voidai demo",
            exit_code=0,
            wall_seconds=1.0,
            peak_bytes=231 * MIB,
            limit_hits=0,
            oom_killed=False,
        )
        base.update(kwargs)
        return Result(**base)  # type: ignore[arg-type]

    def test_a_completed_run_reports_headroom(self) -> None:
        text = self._result().describe()
        assert "completed" in text
        assert "headroom" in text

    def test_an_oom_is_never_described_as_completed(self) -> None:
        """The failure that must never be reported as a pass."""
        text = self._result(oom_killed=True, exit_code=-9).describe()
        assert "OOM-KILLED" in text
        assert "completed" not in text
        assert "headroom" not in text, "a killed run has no headroom to report"

    def test_a_nonzero_exit_is_not_a_pass(self) -> None:
        text = self._result(exit_code=1).describe()
        assert "completed" not in text
        assert "FAILED" in text


@needs_cgroups
class TestTheCeilingIsReal:
    """The property the whole harness rests on."""

    def test_an_allocation_under_the_ceiling_survives(self) -> None:
        result = run_once(
            "pi5-4gb",
            [
                sys.executable,
                "-c",
                "b = bytearray(64 * 1024 * 1024); b[0] = 1; print(len(b))",
            ],
            limit_mb=512,
        )
        assert result.exit_code == 0
        assert not result.oom_killed

    def test_an_allocation_over_the_ceiling_is_killed(self) -> None:
        """Touched, not merely requested — an untouched page costs nothing."""
        result = run_once(
            "pi5-4gb",
            [
                sys.executable,
                "-c",
                "b = bytearray(1024 * 1024 * 1024)\n"
                "for i in range(0, len(b), 4096): b[i] = 1\n"
                "print('should not reach here')",
            ],
            limit_mb=256,
        )
        assert result.oom_killed, "the ceiling did not apply"
        assert result.exit_code != 0

    def test_peak_usage_never_exceeds_the_ceiling(self) -> None:
        result = run_once(
            "pi5-4gb",
            [sys.executable, "-c", "b = bytearray(200 * 1024 * 1024); b[0] = 1"],
            limit_mb=512,
        )
        assert result.peak_bytes <= result.limit_bytes

    def test_the_cgroup_is_torn_down(self) -> None:
        name = f"voidai-envelope-test-{os.getpid()}"
        with Envelope(name, 256 * MIB, None) as envelope:
            assert envelope.memory.is_dir()
            path = envelope.memory
        assert not path.is_dir(), "left a cgroup behind"

    def test_a_cpu_quota_slows_the_same_work_down(self) -> None:
        """A quota that changed nothing would make every CPU row meaningless."""
        spin = [
            sys.executable,
            "-c",
            "x = 0\nfor i in range(6_000_000): x += i * i\nprint(x)",
        ]
        fast = run_once("pi5-4gb", spin, quota_percent=100, limit_mb=512)
        slow = run_once("pi5-4gb", spin, quota_percent=20, limit_mb=512)
        assert fast.exit_code == 0 and slow.exit_code == 0
        assert slow.wall_seconds > fast.wall_seconds * 1.8


class TestUnavailableEnvironment:
    def test_a_missing_controller_is_reported_not_ignored(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Silently skipping the limit would make every result a fabrication."""
        import envelope as module

        monkeypatch.setattr(module, "CGROUP_ROOT", tmp_path / "absent")
        with pytest.raises(CgroupUnavailableError), module.Envelope("x", 256 * MIB, None):
            pass
