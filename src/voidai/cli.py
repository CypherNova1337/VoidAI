"""Command-line interface.

The operator surface is deliberately small and deliberately textual. A SOC
analyst at 3am wants a ranked list and a way to pull the evidence behind any
line of it, not a dashboard.
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from voidai import __version__
from voidai.analyzers import (
    DEFAULT_ANALYZERS,
    AlertTriageAnalyzer,
    AnalysisContext,
    BeaconingAnalyzer,
    DnsTunnelAnalyzer,
    FanoutAnalyzer,
)
from voidai.correlate import IncidentQueue, build_queue
from voidai.ingest.passivedns import load_passivedns
from voidai.ingest.suricata import load_alerts
from voidai.ingest.zeek import load_connections, load_dns
from voidai.lexicon import GRAMMAR, EntityType, Finding, Severity
from voidai.reason import Reasoner, ReasoningConfig, ReasoningResult, default_backend
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


def _render_queue(queue: IncidentQueue, limit: int = 20) -> None:
    """Print the analyst-facing queue, highest priority first.

    Incidents rather than findings, because a host is the unit a responder
    works in, and because ranking by corroboration is what separates a
    compromised machine from a merely periodic one.
    """
    if not len(queue):
        console.print("\n[green]No incidents.[/green] Nothing met threshold.\n")
        return

    table = Table(
        title=f"{len(queue)} incident(s) · {len(queue.corroborated)} corroborated",
        title_justify="left",
        expand=True,
    )
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Prio", justify="right", no_wrap=True)
    table.add_column("Subject", no_wrap=True)
    table.add_column("Behaviours", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)

    for position, ranked in enumerate(queue.top(limit), start=1):
        behaviours = ", ".join(p.value for p in ranked.corroborating_predicates)
        multiple = len(ranked.corroborating_predicates) > 1
        table.add_row(
            str(position),
            _severity_text(ranked.incident.severity),
            f"{ranked.priority:.2f}",
            escape(str(ranked.subject)),
            f"[bold yellow]{escape(behaviours)}[/bold yellow]" if multiple else escape(behaviours),
            str(len(ranked.incident.findings)),
        )

    console.print()
    console.print(table)
    if len(queue) > limit:
        console.print(f"[dim]… {len(queue) - limit} lower-priority incidents not shown[/dim]")

    corroborated = queue.corroborated
    if corroborated:
        console.print("\n[bold]Corroborated — more than one independent behaviour[/bold]")
        for ranked in corroborated[:5]:
            console.print(f"\n  [bold]{escape(str(ranked.subject))}[/bold]")
            console.print(f"  [dim]{escape(ranked.rationale)}[/dim]")
            for finding in ranked.incident.findings[:4]:
                console.print(
                    f"    {finding.confidence:.2f}  {escape(finding.sentence())}"
                )


def _render_reasoning(results: list[ReasoningResult]) -> None:
    """Print the language layer's output, with struck claims shown as struck.

    Struck claims are displayed rather than hidden. An analyst evaluating
    whether to trust this tool needs to see what it refused to say, and a
    silent filter would deny them that.
    """
    for result in results:
        console.print(f"\n[bold]{escape(result.incident.title)}[/bold]")

        if result.report.narrative:
            console.print(f"  {escape(result.report.narrative)}")
        elif result.report.narrative_struck:
            console.print(
                "  [red]narrative struck[/red] [dim]— named an entity the evidence "
                "does not contain[/dim]"
            )

        for claim in result.report.verified:
            console.print(f"  [green]✓[/green] {escape(claim.text)}")
            console.print(f"      [dim]cites {', '.join(claim.cites)}[/dim]")
        for claim in result.report.struck:
            console.print(f"  [red]✗[/red] [strike]{escape(claim.text)}[/strike]")
            console.print(f"      [red dim]struck: {escape(claim.rejection_reason or '')}[/red dim]")

        if result.report.actions:
            console.print("  [dim]suggested next steps:[/dim]")
            for action in result.report.actions:
                console.print(f"    → {escape(action)}")


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
            f"[{style}]{receipt.total_joules:.2f} J[/{style}] "
            f"total, [{style}]{marker}[/{style}]",
        )
        table.add_row("method", escape(energy.method))
        table.add_row(
            "detection", f"{energy.wall_seconds:.2f} s wall / {energy.cpu_seconds:.2f} s cpu"
        )
        if receipt.reasoning:
            table.add_row(
                "reasoning",
                f"{receipt.reasoning.wall_seconds:.2f} s wall · "
                f"{receipt.reasoning.joules:.0f} J ({receipt.tokens.total} tokens)",
            )

    table.add_row("memory", f"{receipt.peak_rss_mb:.0f} MB peak")
    table.add_row(
        "tokens",
        f"{receipt.tokens.total} ({receipt.tokens.model or 'no model used'})"
        + (f", {receipt.claims_struck} claim(s) struck" if receipt.claims_struck else ""),
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
    model: Path | None = typer.Option(
        None, "--model", help="GGUF model for the narrative layer. Detection runs without it."
    ),
    explain: int = typer.Option(
        3, "--explain", help="Incidents to narrate, highest priority first."
    ),
) -> None:
    """Run the detection pipeline over a directory of telemetry."""
    if not path.exists():
        console.print(f"[red]No such path:[/red] {path}")
        raise typer.Exit(code=2)

    run_receipt = RunReceipt()

    with EnergyMeter() as meter:
        connections = load_connections(path)
        # Zeek dns.log if present, else passivedns from a Stratosphere-style
        # capture. Either yields real query names; neither is required.
        dns = load_dns(path)
        if dns.is_empty():
            dns = load_passivedns(path)
        alerts = load_alerts(path)
        ctx = AnalysisContext(connections=connections, dns=dns, alerts=alerts)
        findings = (
            BeaconingAnalyzer().analyze(ctx)
            + FanoutAnalyzer().analyze(ctx)
            + DnsTunnelAnalyzer().analyze(ctx)
            + AlertTriageAnalyzer().analyze(ctx)
        )
        queue = build_queue(findings)

    run_receipt.records_ingested = ctx.record_count()
    run_receipt.findings_emitted = len(findings)
    run_receipt.finalize(meter.reading)

    if run_receipt.records_ingested == 0:
        console.print(f"[yellow]No parseable telemetry found under[/yellow] {path}")
        raise typer.Exit(code=1)

    _render_queue(queue)
    if evidence:
        _render_evidence(findings)

    if no_llm:
        console.print(
            "\n[dim]--no-llm: detection only. The findings above are complete; "
            "only the narrative is absent.[/dim]"
        )
    else:
        reasoner = Reasoner(
            backend=default_backend(model),
            config=ReasoningConfig(max_incidents=explain),
        )
        if not reasoner.available():
            console.print(
                f"\n[dim]No narrative: {reasoner.backend.reason}. "
                "Detection is unaffected.[/dim]"
            )
        else:
            with EnergyMeter() as reasoning_meter:
                results = reasoner.explain_queue(queue.incidents, run_receipt.tokens)
            run_receipt.claims_struck = sum(r.strike_count for r in results)
            run_receipt.reasoning = reasoning_meter.reading
            console.print("\n[bold]Analysis[/bold]")
            _render_reasoning(results)

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
    rank = result.best_infected_rank
    table.add_row(
        "queue position",
        (
            f"[green]rank {rank} of {len(result.queue)}[/green]"
            if rank is not None and rank <= 5
            else f"rank {rank} of {len(result.queue)}"
            if rank is not None
            else "[red]absent from queue[/red]"
        ),
    )
    table.add_row(
        "alert burden",
        f"{len(result.findings)} findings → {len(result.queue)} incidents, "
        f"{len(result.queue.corroborated)} corroborated",
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
    _render_queue(result.queue, limit=10)
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
def doctor(
    model: Path | None = typer.Option(None, "--model", help="GGUF model to check for."),
) -> None:
    """Pre-flight check: platform, energy source, optional components.

    Written for bring-up on new hardware. The question that matters on a Pi is
    whether energy will be *measured* or *estimated*, and this answers it
    before a benchmark is run rather than after.
    """
    from voidai.telemetry.power import (
        EstimatedSource,
        HwmonSource,
        RaplSource,
        best_available_source,
    )

    table = Table(title="VoidAI pre-flight", title_justify="left", show_header=False)
    table.add_column(style="dim")
    table.add_column()

    profile = detect_platform()
    table.add_row("version", __version__)
    table.add_row("platform", escape(profile.name))
    table.add_row("machine", f"{os.uname().machine} · {os.cpu_count() or 1} cores")

    source = best_available_source()
    measured = not isinstance(source, EstimatedSource)
    table.add_row(
        "energy",
        f"[green]measured[/green] — {escape(source.method)}"
        if measured
        else f"[yellow]estimated[/yellow] — {escape(source.method)}",
    )
    if not measured:
        table.add_row(
            "",
            "[dim]RAPL: "
            + ("present but unreadable" if Path("/sys/class/powercap").is_dir() else "absent")
            + f"; hwmon power rails: {len(HwmonSource.available())} found"
            + f"; RAPL domains: {len(RaplSource.available())}[/dim]",
        )
        table.add_row("", "[dim]see docs/deployment.md to wire a shunt for real figures[/dim]")

    try:
        import llama_cpp

        table.add_row("llama-cpp", f"[green]installed[/green] ({llama_cpp.__version__})")
    except ImportError:
        table.add_row("llama-cpp", "[yellow]absent[/yellow] — narrative layer disabled")

    if model is not None:
        size = model.stat().st_size / 1e9 if model.is_file() else 0.0
        table.add_row(
            "model",
            f"[green]{escape(model.name)}[/green] ({size:.1f} GB)"
            if model.is_file()
            else f"[red]not found:[/red] {escape(str(model))}",
        )
    else:
        table.add_row("model", "[dim]none given — pass --model to check one[/dim]")

    table.add_row("analyzers", ", ".join(a.name for a in DEFAULT_ANALYZERS))
    table.add_row("predicates", f"{len(GRAMMAR)} in the Lexicon")

    console.print()
    console.print(table)
    console.print(
        "\n[dim]Energy reads 'estimated' unless a real counter is present. An estimate "
        "is never reported as a measurement.[/dim]\n"
    )


@app.command()
def version() -> None:
    """Print version and detected platform."""
    profile = detect_platform()
    console.print(f"voidai {__version__}")
    console.print(f"[dim]platform:[/dim] {profile.citation}")


if __name__ == "__main__":  # pragma: no cover
    app()
