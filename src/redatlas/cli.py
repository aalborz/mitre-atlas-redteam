from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from redatlas.data.cache import DataSourceError, get_cache_dir
from redatlas.data.schema import Domain, Framework
from redatlas.data.store import DataStore
from redatlas.llm.client import MissingAPIKeyError

app = typer.Typer(
    add_completion=False, help="Threat-modeling and red-team advisory CLI for MITRE ATT&CK + ATLAS."
)
data_app = typer.Typer(add_completion=False, help="Fetch, search, and inspect ATT&CK/ATLAS data.")
model_app = typer.Typer(
    add_completion=False, help="Generate threat models from a system description."
)
chat_app = typer.Typer(add_completion=False, help="Interactive red-team advisor chat.")
coverage_app = typer.Typer(
    add_completion=False, help="Coverage/gap dashboard against your detections."
)
exec_app = typer.Typer(
    add_completion=False, help="Execution hooks (Atomic Red Team), gated by authorization."
)
app.add_typer(data_app, name="data")
app.add_typer(model_app, name="model")
app.add_typer(chat_app, name="chat")
app.add_typer(coverage_app, name="coverage")
app.add_typer(exec_app, name="exec")

console = Console()

_FRAMEWORK_CHOICES = ["attack", "atlas", "all"]
_DOMAIN_CHOICES = ["enterprise", "ics", "mobile"]
_DOMAIN_TO_FRAMEWORK = {
    "enterprise": Framework.ATTACK,
    "ics": Framework.ATTACK,
    "mobile": Framework.ATTACK,
    "atlas": Framework.ATLAS,
}


def _parse_attack_domains(domains: str) -> tuple[Domain, ...]:
    return tuple(Domain(d.strip()) for d in domains.split(",") if d.strip())


def _load_store(*, framework: str, attack_domains: str, refresh: bool) -> DataStore:
    include_atlas = framework in ("atlas", "all")
    include_attack = framework in ("attack", "all")
    domains = _parse_attack_domains(attack_domains) if include_attack else ()
    try:
        with console.status("Loading ATT&CK/ATLAS data (downloads on first run)..."):
            return DataStore.load(
                get_cache_dir(),
                refresh=refresh,
                attack_domains=domains,
                include_atlas=include_atlas,
            )
    except DataSourceError as exc:
        console.print(f"[red]Failed to load data:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@data_app.command("fetch")
def data_fetch(
    framework: str = typer.Option("all", help="attack | atlas | all"),
    attack_domains: str = typer.Option(
        "enterprise", "--attack-domain", help="Comma-separated: enterprise,ics,mobile"
    ),
    refresh: bool = typer.Option(False, help="Force re-download even if cached."),
) -> None:
    """Download and cache ATT&CK/ATLAS data."""
    store = _load_store(framework=framework, attack_domains=attack_domains, refresh=refresh)
    console.print(
        f"[green]Loaded[/green] {len(store.all_techniques())} techniques, "
        f"{len(store.get_tactics())} tactics."
    )


@data_app.command("search")
def data_search(
    query: str,
    framework: str = typer.Option("all", help="attack | atlas | all"),
    domain: str | None = typer.Option(None, help="enterprise | ics | mobile | atlas"),
    limit: int = typer.Option(10),
) -> None:
    """Search techniques by keyword."""
    store = _load_store(framework=framework, attack_domains="enterprise,ics,mobile", refresh=False)
    fw = None if framework == "all" else Framework(framework)
    dom = Domain(domain) if domain else None
    results = store.search(query, framework=fw, domain=dom, limit=limit)

    if not results:
        console.print("[yellow]No matches found.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"Search results for {query!r}")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Framework")
    for technique in results:
        table.add_row(technique.id, technique.name, technique.framework.value)
    console.print(table)


@data_app.command("show")
def data_show(technique_id: str) -> None:
    """Show full details for a technique ID."""
    store = _load_store(framework="all", attack_domains="enterprise,ics,mobile", refresh=False)
    technique = store.get_technique(technique_id)
    if not technique:
        console.print(f"[red]Unknown technique id:[/red] {technique_id}")
        raise typer.Exit(code=1)

    console.print(f"[bold]{technique.id}[/bold] — {technique.name} ({technique.framework.value})")
    console.print(technique.description)
    if technique.platforms:
        console.print(f"[bold]Platforms:[/bold] {', '.join(technique.platforms)}")
    mitigations = store.get_mitigations_for(technique_id)
    if mitigations:
        console.print("[bold]Mitigations:[/bold]")
        for m in mitigations:
            console.print(f"  - {m.id}: {m.name}")
    if technique.external_url:
        console.print(f"[bold]Reference:[/bold] {technique.external_url}")


@model_app.command("generate")
def model_generate(
    system_file: Path,
    output: Path = typer.Option(
        Path("report"), help="Output path prefix (writes <prefix>.md and <prefix>.json)."
    ),
    top_k: int = typer.Option(25),
    model: str | None = typer.Option(None, help="Override the Claude model."),
) -> None:
    """Generate a threat model report from a system/architecture YAML description."""
    from redatlas.modeling.generator import generate_report
    from redatlas.modeling.inputs import load_system_model

    if not system_file.exists():
        console.print(f"[red]File not found:[/red] {system_file}")
        raise typer.Exit(code=1)

    system = load_system_model(system_file)
    store = _load_store(framework="all", attack_domains="enterprise,ics,mobile", refresh=False)

    try:
        with console.status("Generating threat model..."):
            report = generate_report(system, store, model=model, top_k=top_k)
    except MissingAPIKeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    md_path = output.with_suffix(".md")
    json_path = output.with_suffix(".json")
    md_path.write_text(report.to_markdown(), encoding="utf-8")
    json_path.write_text(_to_json(report), encoding="utf-8")
    console.print(f"[green]Wrote[/green] {md_path} and {json_path}")


def _to_json(report) -> str:
    import json

    return json.dumps(report.to_dict(), indent=2)


@coverage_app.command("report")
def coverage_report(
    covered_file: Path,
    domain: str = typer.Option("enterprise", help="enterprise | ics | mobile | atlas"),
    output: Path = typer.Option(Path("coverage-layer.json")),
    name: str = typer.Option("redatlas coverage", help="Layer name shown in the Navigator."),
) -> None:
    """Generate an ATT&CK/ATLAS Navigator layer of covered vs. gap techniques."""
    from redatlas.dashboard.coverage import compute_coverage, load_coverage
    from redatlas.dashboard.navigator import write_layer

    if not covered_file.exists():
        console.print(f"[red]File not found:[/red] {covered_file}")
        raise typer.Exit(code=1)
    if domain not in _DOMAIN_TO_FRAMEWORK:
        console.print(f"[red]Unknown domain:[/red] {domain}")
        raise typer.Exit(code=1)

    dom = Domain(domain)
    framework = _DOMAIN_TO_FRAMEWORK[domain]

    coverage_input = load_coverage(covered_file)
    store = _load_store(
        framework=framework.value, attack_domains="enterprise,ics,mobile", refresh=False
    )
    report = compute_coverage(store, set(coverage_input.covered), framework=framework, domain=dom)

    write_layer(
        report,
        domain=dom,
        name=name,
        description=f"{report.covered_count}/{report.total} techniques covered",
        path=output,
    )
    console.print(
        f"[green]Wrote[/green] {output} — {report.covered_count}/{report.total} covered "
        f"({report.gap_count} gaps)."
    )


@chat_app.command("start")
def chat_start(
    model: str | None = typer.Option(None, help="Override the Claude model."),
    framework: str = typer.Option("all", help="attack | atlas | all"),
) -> None:
    """Start an interactive red-team advisor chat session."""
    from redatlas.chat.advisor import run_repl

    store = _load_store(framework=framework, attack_domains="enterprise,ics,mobile", refresh=False)
    try:
        run_repl(store, model=model)
    except MissingAPIKeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


@exec_app.command("run")
def exec_run(
    technique_id: str,
    target: str = typer.Option(
        "localhost", help="Target host. Only 'localhost' is supported for --execute in this MVP."
    ),
    authorization: Path = typer.Option(
        Path("authorization.yaml"), help="Path to the authorization file."
    ),
    test_number: list[int] = typer.Option(
        None, "--test-number", help="Specific Atomic test number(s) to run."
    ),
    execute: bool = typer.Option(
        False, help="Actually run the test. Without this, only validates authorization (dry run)."
    ),
    cleanup: bool = typer.Option(False, help="Run the Atomic test's cleanup commands."),
) -> None:
    """Run (or dry-run) an Atomic Red Team test, gated by an authorization file."""
    from redatlas.exec.atomic_red_team import AtomicRedTeamNotAvailableError, run_technique
    from redatlas.exec.authorization import AuthorizationError, load_authorization

    try:
        scope = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    try:
        result = run_technique(
            technique_id,
            target,
            scope,
            test_numbers=test_number or None,
            execute=execute,
            cleanup=cleanup,
        )
    except AuthorizationError as exc:
        console.print(f"[red]Authorization refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except (AtomicRedTeamNotAvailableError, NotImplementedError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if result.dry_run:
        console.print(
            f"[yellow]Dry run[/yellow]: authorization OK for {technique_id} against {target}. "
            "Pass --execute to actually run it."
        )
        return

    console.print(
        f"[green]Executed[/green] {technique_id} against {target}, exit code {result.return_code}"
    )
    if result.stdout:
        console.print(result.stdout)
    if result.stderr:
        console.print(f"[red]{result.stderr}[/red]")


if __name__ == "__main__":
    app()
