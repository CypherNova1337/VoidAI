"""The analyzer registry is the single source of truth.

`voidai doctor` reports which analyzers exist and `voidai run` executes them.
If those two lists could drift apart, the diagnostic command would be lying
about the system it is diagnosing — which is the one thing a diagnostic
command must never do.
"""

from __future__ import annotations

import inspect

from voidai.analyzers import DEFAULT_ANALYZERS, AnalysisContext, BaseAnalyzer


def test_registry_is_not_empty() -> None:
    assert DEFAULT_ANALYZERS


def test_every_registered_analyzer_implements_the_contract() -> None:
    for analyzer in DEFAULT_ANALYZERS:
        assert issubclass(analyzer, BaseAnalyzer)
        assert analyzer.name != BaseAnalyzer.name, f"{analyzer} did not set a name"
        assert analyzer.version != BaseAnalyzer.version, f"{analyzer} did not set a version"


def test_names_are_unique() -> None:
    """Names appear in every Finding; a collision makes provenance ambiguous."""
    names = [a.name for a in DEFAULT_ANALYZERS]
    assert len(names) == len(set(names))


def test_every_analyzer_constructs_with_no_arguments() -> None:
    """`run` instantiates them bare, so a required argument would break it."""
    for analyzer in DEFAULT_ANALYZERS:
        assert analyzer() is not None


def test_every_analyzer_tolerates_an_empty_context() -> None:
    """A capture missing one telemetry type must not fail the whole run."""
    for analyzer in DEFAULT_ANALYZERS:
        assert analyzer().analyze(AnalysisContext()) == []


def test_detection_iterates_the_registry_rather_than_a_hardcoded_list() -> None:
    """Guards the drift this module exists to prevent.

    `doctor` reports DEFAULT_ANALYZERS; the detection path must execute the
    same tuple, not a second list that happens to agree today.
    """
    from voidai import cli

    source = inspect.getsource(cli._detect)
    assert "DEFAULT_ANALYZERS" in source
    for analyzer in DEFAULT_ANALYZERS:
        assert f"{analyzer.__name__}()" not in source, (
            f"{analyzer.__name__} is hardcoded in _detect(); iterate the registry instead"
        )


def test_every_command_detects_through_the_same_path() -> None:
    """One pipeline, not one per command.

    `run` and `hunt` analyse the same directory and must reach the same
    findings. Two copies of the ingest-and-analyse sequence would eventually
    disagree — and the disagreement would show up as a hunt query for an
    incident `run` never reported.
    """
    from voidai import cli

    for command in (cli.run, cli.hunt):
        source = inspect.getsource(command)
        assert "_detect(" in source, f"{command.__name__} builds its own pipeline"
