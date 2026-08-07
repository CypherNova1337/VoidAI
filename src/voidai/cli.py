"""Command-line interface.

The operator surface is deliberately small and deliberately textual. A SOC
analyst at 3am wants a ranked list and a way to pull the evidence behind any
line of it, not a dashboard.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from voidai import __version__
from voidai.analyzers import AnalysisContext, BeaconingAnalyzer
from voidai.ingest.zeek import load_connections, load_dns
from voidai.lexicon import GRAMMAR, EntityType, Finding, Severity
from voidai.telemetry import EnergyMeter, RunReceipt, detect_platform

app = typer.Typer(
    name="voidai",
    help="Local-first, evidence-bound agent runtime for cyber defence.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _severity_text(severity: Severity | None) -> Text:
    severity = severity or Severity.INFO
    return Text(severity.value.upper(), style=_SEVERITY_STYLE[severity])


def _render_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("\n[green]No findings.[/green] Nothing in this telemetry met threshold.\n")
        return

    table = Table(title=f"{len(findings)} finding(s)", title_justify="left", expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Proposition")
    table.add_column("ATT&CK", no_wrap=True)

    for finding in findings:
        table.add_row(
            _severity_text(finding.severity),
            f"{finding.confidence:.2f}",
            escape(finding.sentence()),
            escape(", ".join(finding.attack_techniques)) or "—",
        )
    console.print()
    console.print(table)


def _render_evidence(findings: list[Finding]) -> None:
    """Print the chain of custody for each finding.

    Every dynamic string here is escaped. Evidence text is derived from log
    data, and log data contains brackets — an attacker-controlled User-Agent
    or a component list like [regularity=1.00] would otherwise be swallowed by
    the console's markup parser. Silently mangled evidence is worse than no
    evidence, and this is the one display where that is least acceptable.
    """
    console.print("\n[bold]Evidence chain[/bold]")
    for finding in findings:
        console.print(f"\n  [bold]{finding.id}[/bold]  {escape(finding.sentence())}")
        console.print(f"  [dim]basis:[/dim] {escape(finding.basis)}")
        for evidence in finding.evidence:
            console.print(f"    [cyan]{evidence.id}[/cyan]  {escape(evidence.summary)}")
            for artifact in evidence.artifacts[:3]:
                location = escape(f"{artifact.source}:{artifact.locator}")
                console.print(f"      [dim]{location}[/dim]")
            if len(evidence.artifacts) > 3:
                console.print(f"      [dim]… and {len(evidence.artifacts) - 3} more[/dim]")


def _render_receipt(receipt: RunReceipt) -> None:
    energy = receipt.energy
    table = Table(title="Run receipt", title_justify="left", show_header=False, expand=False)
    table.add_column(style="dim")
    table.add_column()

    if energy:
        marker = "measured" if energy.is_measured else "estimated"
        style = "green" if energy.is_measured else "yellow"
        table.add_row(
            "energy",
            f"[{style}]{energy.joules:.2f} J[/{style}] "
            f"({energy.average_watts:.1f} W avg, [{style}]{marker}[/{style}])",
        )
        table.add_row("method", escape(energy.method))
        table.add_row("time", f"{energy.wall_seconds:.2f} s wall / {energy.cpu_seconds:.2f} s cpu")

    table.add_row("memory", f"{receipt.peak_rss_mb:.0f} MB peak")
    table.add_row(
        "tokens",
        f"{receipt.tokens.total} ({receipt.tokens.model or 'no model used'})",
    )
    table.add_row(
        "work",
        f"{receipt.records_ingested:,} records → {receipt.findings_emitted} findings "
        f"({receipt.records_per_second:,.0f} rec/s)",
    )
    table.add_row("host", f"{receipt.host} · {receipt.machine} · {receipt.cores} cores")
    console.print()
    console.print(table)


@app.command()
def run(
    path: Path = typer.Argument(..., help="Directory of Zeek logs to analyse."),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Skip the language layer. Detection is unaffected."
    ),
    evidence: bool = typer.Option(
        False, "--evidence", help="Print the full evidence chain for every finding."
    ),
    receipt: bool = typer.Option(True, "--receipt/--no-receipt", help="Print the run receipt."),
) -> None:
    """Run the detection pipeline over a directory of telemetry."""
    if not path.exists():
        console.print(f"[red]No such path:[/red] {path}")
        raise typer.Exit(code=2)

    run_receipt = RunReceipt()

    with EnergyMeter() as meter:
        connections = load_connections(path)
        dns = load_dns(path)
        ctx = AnalysisContext(connections=connections, dns=dns)
        findings = BeaconingAnalyzer().analyze(ctx)

    run_receipt.records_ingested = ctx.record_count()
    run_receipt.findings_emitted = len(findings)
    run_receipt.finalize(meter.reading)

    if run_receipt.records_ingested == 0:
        console.print(f"[yellow]No parseable telemetry found under[/yellow] {path}")
        raise typer.Exit(code=1)

    _render_findings(findings)
    if evidence:
        _render_evidence(findings)

    if not no_llm:
        console.print(
            "\n[dim]The language layer is not yet wired up; this run was "
            "detection-only. Findings above are complete.[/dim]"
        )

    if receipt:
        _render_receipt(run_receipt)


def _bench_real(path: Path, limit: int) -> None:
    """Score against a labelled real capture — currently the CTU-13 dialect.

    Reported separately from the synthetic benchmark and never averaged with
    it. See docs/benchmarks.md for why pair precision reads near zero here and
    what it does and does not mean.
    """
    from voidai.analyzers.beaconing import BeaconingConfig
    from voidai.eval.ctu13 import SCENARIOS, Scenario, evaluate

    scenario = next(
        (s for key, s in SCENARIOS.items() if key in path.name or s.filename == path.name),
        Scenario(key="unknown", filename=path.name, malware="unknown", duration_hours=0.0),
    )

    console.print(f"[dim]Scoring {path.name} ({scenario.malware})…[/dim]")
    result = evaluate(path, scenario, config=BeaconingConfig(max_findings=limit))

    detected = result.true_positive_pairs
    ranked = sorted((f.confidence for f in result.findings), reverse=True)
    best = max((f.confidence for f in result.findings
                if (f.subject.value, f.object.value) in result.botnet_pairs), default=None)

    table = Table(title="Real capture", title_justify="left", show_header=False)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("capture", f"{escape(path.name)} · {scenario.malware}")
    table.add_row("volume", f"{result.flow_count:,} flows over {result.span_hours:.2f}h")
    table.add_row(
        "infected host",
        (
            f"[green]detected[/green] — {', '.join(sorted(result.flagged_infected_hosts))}"
            if result.infected_host_detected
            else "[red]not detected[/red]"
        ),
    )
    if best is not None:
        table.add_row("c2 confidence", f"{best:.3f} (rank {ranked.index(best) + 1} of {len(ranked)})")
    table.add_row(
        "alert burden",
        f"{len(result.findings)} findings · [{'yellow' if result.findings_per_hour > 20 else 'green'}]"
        f"{result.findings_per_hour:.1f}/hour[/]",
    )
    table.add_row("pair precision", f"{result.pair_precision:.4f} ({len(detected)} on labelled pairs)")
    table.add_row(
        "ground truth",
        f"{len(result.botnet_pairs):,} botnet pairs · {len(result.infected_hosts)} infected hosts",
    )
    console.print()
    console.print(table)
    console.print(
        "\n[dim]'Background' in CTU-13 means unlabelled, not benign, so pair precision is a "
        "lower bound rather than an estimate. See docs/benchmarks.md.[/dim]"
    )
    _render_receipt(result.receipt)


@app.command()
def bench(
    seed: int = typer.Option(1337, help="Corpus seed. Same seed, same corpus, forever."),
    hours: float = typer.Option(24.0, help="Hours of synthetic telemetry to generate."),
    real: Path | None = typer.Option(
        None, "--real", help="Score against a labelled real capture instead (CTU-13 format)."
    ),
    limit: int = typer.Option(100_000, help="Cap on findings emitted, highest-scoring first."),
) -> None:
    """Score the analyzers against a labelled corpus, and meter the run."""
    from voidai.eval.benchmark import run_benchmark

    if real is not None:
        if not real.is_file():
            console.print(f"[red]No such capture:[/red] {real}")
            raise typer.Exit(code=2)
        _bench_real(real, limit)
        return

    console.print(f"[dim]Generating {hours:g}h corpus (seed {seed})…[/dim]")
    result = run_benchmark(seed=seed, hours=hours)
    detection = result.detection

    table = Table(title="Detection accuracy", title_justify="left", show_header=False)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("precision", f"{detection.precision:.3f}")
    table.add_row("recall", f"{detection.recall:.3f}")
    table.add_row("f1", f"{detection.f1:.3f}")
    table.add_row(
        "confusion",
        f"{detection.true_positives} TP · {detection.false_positives} FP "
        f"· {detection.false_negatives} FN",
    )
    if detection.missed_labels:
        table.add_row("missed", ", ".join(detection.missed_labels))
    if detection.false_positive_pairs:
        table.add_row("false alarms", ", ".join(detection.false_positive_pairs[:5]))

    console.print()
    console.print(table)
    _render_findings(result.findings)
    _render_receipt(result.receipt)


@app.command()
def lexicon() -> None:
    """Print the complete grammar: everything VoidAI is able to say."""
    # Not expanded: on a narrow terminal `expand` steals width from the
    # fixed columns to feed the description and collapses the predicate name
    # to nothing. Sizing to content and letting the description wrap keeps
    # the table readable at any width.
    table = Table(title="The Lexicon", title_justify="left")
    table.add_column("Predicate", no_wrap=True, style="bold")
    table.add_column("Subject", no_wrap=True)
    table.add_column("Object", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Meaning", min_width=30)

    def render_types(types: frozenset[EntityType] | None) -> str:
        """Collapse a universal type set to 'any' rather than listing all ten.

        Without this, the one relational predicate that accepts every entity
        type forces both type columns wide enough to squeeze everything else
        off the terminal.
        """
        if types is None:
            return "—"
        if set(types) == set(EntityType):
            return "any"
        return "|".join(sorted(t.value for t in types))

    for predicate, spec in GRAMMAR.items():
        table.add_row(
            predicate.value,
            render_types(spec.subject_types),
            "—" if spec.is_unary() else render_types(spec.object_types),
            _severity_text(spec.default_severity),
            escape(spec.description),
        )

    console.print()
    console.print(table)
    console.print(
        f"\n[dim]{len(GRAMMAR)} predicates. An assertion outside this set has no "
        "representation and cannot reach an analyst.[/dim]\n"
    )


@app.command()
def version() -> None:
    """Print version and detected platform."""
    profile = detect_platform()
    console.print(f"voidai {__version__}")
    console.print(f"[dim]platform:[/dim] {profile.citation}")


if __name__ == "__main__":  # pragma: no cover
    app()
