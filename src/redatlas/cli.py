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
app.add_typer(data_app, name="data")
app.add_typer(model_app, name="model")
app.add_typer(chat_app, name="chat")

console = Console()

_FRAMEWORK_CHOICES = ["attack", "atlas", "all"]
_DOMAIN_CHOICES = ["enterprise", "ics", "mobile"]


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


if __name__ == "__main__":
    app()
