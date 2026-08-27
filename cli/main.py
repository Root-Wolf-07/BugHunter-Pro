"""
Bug Hunter AI — Pure Terminal CLI & Interactive TUI
100% Local-First • No Web Server • Direct In-Process Engine
"""
from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from cli.banner import get_banner

app = typer.Typer(
    name="bug-hunter",
    help="Bug Hunter AI — Local Terminal Cybersecurity Assistant",
    no_args_is_help=False,
    add_completion=False,
)

console = Console()

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "blue",
}


def _print_banner() -> None:
    console.print(f"[bold cyan]{get_banner()}[/bold cyan]")


# ─────────────────────────────────────────────────────────────────────────────
# In-Process Scan Engine
# ─────────────────────────────────────────────────────────────────────────────
async def _execute_scan_in_process(
    target_value: str,
    target_name: Optional[str] = None,
    target_type: str = "hostname",
    tools: Optional[List[str]] = None,
) -> str:
    """Execute full scan pipeline in-process without any web server."""
    from app.config import get_settings
    from app.database.session import db_session, init_db
    from app.database.repository import (
        TargetRepository,
        ScanRepository,
        ScanResultRepository,
        FindingRepository,
        ActivityRepository,
    )
    from app.scanners.registry import ScannerRegistry
    from app.findings.parser import FindingParser
    from app.findings.deduplicator import Deduplicator
    from app.ai.analyzer import AIAnalyzer

    init_db()
    settings = get_settings()
    registry = ScannerRegistry()
    tools_to_use = tools or ["nmap", "nuclei", "nikto", "ffuf"]

    with db_session() as db:
        target_repo = TargetRepository(db)
        scan_repo = ScanRepository(db)
        scan_result_repo = ScanResultRepository(db)
        finding_repo = FindingRepository(db)
        activity_repo = ActivityRepository(db)

        # 1. Target record
        target = target_repo.create(
            name=target_name or target_value,
            target_type=target_type,
            value=target_value,
            authorization_confirmed=True,
        )

        # 2. Scan record
        scan = scan_repo.create(
            target_id=target.id,
            scan_type="terminal_scan",
            tools_used=tools_to_use,
            authorization_confirmed=True,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        scan_id = scan.id

        activity_repo.log(
            "SCAN_STARTED",
            f"Terminal scan started on {target.value}",
            scan_id=scan_id,
            target_id=target.id,
        )

    all_raw_results = []

    # 3. Run security scanner tools
    console.print(f"\n[bold cyan]Target:[/bold cyan] {target_value}")
    console.print(f"[bold cyan]Scan ID:[/bold cyan] {scan_id}\n")

    for tool_name in tools_to_use:
        scanner = registry.get(tool_name)
        if not scanner:
            console.print(f"  [yellow]⚠ Tool '{tool_name}' not registered, skipping.[/yellow]")
            continue

        if not scanner.is_available():
            console.print(f"  [dim yellow]⚠ Tool '{tool_name}' is not installed locally, skipping.[/dim yellow]")
            with db_session() as db:
                ActivityRepository(db).log(
                    "TOOL_MISSING", f"Tool '{tool_name}' not installed", level="WARNING", scan_id=scan_id
                )
            continue

        with console.status(f"[bold green]Running {tool_name.upper()} scanner against {target_value}...[/bold green]", spinner="dots"):
            try:
                raw_output, parsed = await asyncio.to_thread(
                    scanner.scan, target_value, scan_id, {}
                )
                with db_session() as db:
                    ScanResultRepository(db).create(
                        scan_id=scan_id,
                        tool_name=tool_name,
                        raw_output=raw_output,
                        parsed_data=parsed,
                        success=True,
                    )
                    ActivityRepository(db).log(
                        "TOOL_COMPLETED", f"{tool_name} completed successfully", scan_id=scan_id
                    )
                all_raw_results.append((tool_name, parsed))
                console.print(f"  [bold green]✓[/bold green] {tool_name.upper()} scan completed")
            except Exception as exc:
                console.print(f"  [bold red]✗[/bold red] {tool_name.upper()} error: {exc}")
                with db_session() as db:
                    ScanResultRepository(db).create(
                        scan_id=scan_id,
                        tool_name=tool_name,
                        success=False,
                        error_message=str(exc),
                    )

    # 4. Parse & Deduplicate findings
    parser = FindingParser()
    dedup = Deduplicator()
    raw_findings = []
    for tool_name, parsed in all_raw_results:
        raw_findings.extend(parser.parse(tool_name, parsed, target.id, scan_id))

    unique_findings = dedup.deduplicate(raw_findings)
    console.print(f"\n[dim]Discovered {len(raw_findings)} raw findings → {len(unique_findings)} unique after deduplication.[/dim]")

    # 5. AI Enrichment
    analyzed_findings = []
    if unique_findings:
        with console.status(f"[bold cyan]Running Local AI Analysis ({settings.ollama_model})...[/bold cyan]", spinner="arc"):
            analyzer = AIAnalyzer(settings)
            for finding_data in unique_findings:
                try:
                    enriched = await analyzer.analyze_finding(finding_data)
                    analyzed_findings.append(enriched)
                except Exception as exc:
                    analyzed_findings.append(finding_data)
    else:
        analyzed_findings = unique_findings

    # 6. Save findings to database
    with db_session() as db:
        finding_repo = FindingRepository(db)
        scan_repo = ScanRepository(db)
        activity_repo = ActivityRepository(db)

        for finding_data in analyzed_findings:
            existing = finding_repo.get_by_fingerprint(finding_data.get("fingerprint", ""))
            if not existing:
                finding_repo.create(**finding_data)

        scan_repo.update_status(
            scan_id,
            "completed",
            completed_at=datetime.now(timezone.utc),
        )
        activity_repo.log(
            "SCAN_COMPLETED",
            f"Scan completed with {len(analyzed_findings)} findings.",
            scan_id=scan_id,
        )

    # 7. Print summary table
    _display_findings_table(analyzed_findings)
    return scan_id


def _display_findings_table(findings: List[dict]) -> None:
    """Print formatted findings table in terminal."""
    if not findings:
        console.print(Panel("[green]✓ No security vulnerabilities detected on target.[/green]", border_style="green"))
        return

    table = Table(title="SECURITY FINDINGS SUMMARY", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=12)
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Component", style="dim")
    table.add_column("Tool", style="dim")

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "LOW")
        color = SEV_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[{color}]{sev}[/{color}]",
            f.get("title", "Untitled")[:60],
            f.get("category", "-"),
            f.get("affected_component", "-") or "-",
            f.get("detected_by", "-"),
        )

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# CLI Commands
# ─────────────────────────────────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Bug Hunter AI — Terminal-Only Cybersecurity Assistant."""
    if ctx.invoked_subcommand is None:
        _print_banner()
        _run_interactive_menu()


@app.command("interactive")
def interactive_cmd() -> None:
    """Start the interactive terminal dashboard menu."""
    _print_banner()
    _run_interactive_menu()


def _run_interactive_menu() -> None:
    """Interactive loop for all Bug Hunter terminal operations."""
    while True:
        console.print("\n[bold cyan]Bug Hunter AI — Main Menu[/bold cyan]")
        console.print("[dim]Select an option by number:[/dim]\n")
        console.print("  [bold]1[/bold] • Quick System Status & Tool Check")
        console.print("  [bold]2[/bold] • Start Security Scan")
        console.print("  [bold]3[/bold] • View Findings & AI Explanations")
        console.print("  [bold]4[/bold] • AI Remediation & Patch Review")
        console.print("  [bold]5[/bold] • Verify Security Fixes")
        console.print("  [bold]6[/bold] • Manage Targets")
        console.print("  [bold]7[/bold] • Generate Report (Markdown/HTML/JSON)")
        console.print("  [bold]8[/bold] • View Local Activity Log")
        console.print("  [bold]9[/bold] • Configuration Settings")
        console.print("  [bold]0[/bold] • Exit\n")

        choice = Prompt.ask("[bold]Enter choice[/bold]", default="1")

        if choice == "1":
            _run_setup_check()
        elif choice == "2":
            _interactive_scan()
        elif choice == "3":
            _interactive_findings()
        elif choice == "4":
            _interactive_remediation()
        elif choice == "5":
            _interactive_verify()
        elif choice == "6":
            _interactive_targets()
        elif choice == "7":
            _interactive_report()
        elif choice == "8":
            _interactive_activity()
        elif choice == "9":
            config_cmd()
        elif choice in ("0", "q", "exit"):
            console.print("[bold cyan]Exiting Bug Hunter AI. Stay secure![/bold cyan]")
            break
        else:
            console.print("[yellow]Invalid option, please try again.[/yellow]")


def _run_setup_check() -> None:
    """Run local environment and tool checks."""
    from app.config import get_settings
    from app.scanners.registry import ScannerRegistry
    from app.database.session import init_db

    settings = get_settings()
    console.print("\n[bold]System Check (Local Environment)[/bold]\n")

    # Python
    v = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    _status_row("Python", True, v)

    # Database
    try:
        init_db()
        _status_row("Database (SQLite)", True, str(settings.db_path))
    except Exception as exc:
        _status_row("Database (SQLite)", False, str(exc))

    # Ollama
    ollama_ok, model_ok = asyncio.run(_check_ollama(settings))
    _status_row("Ollama Service", ollama_ok, settings.ollama_host)
    _status_row(f"AI Model ({settings.ollama_model})", model_ok)

    # Security Scanners
    registry = ScannerRegistry()
    for scanner in registry.all_scanners():
        available = scanner.is_available()
        version = scanner.get_version() if available else None
        _status_row(scanner.name.capitalize(), available, version)


async def _check_ollama(settings):
    from app.ai.ollama_client import OllamaClient
    try:
        client = OllamaClient(settings)
        reachable = await client.is_reachable()
        model_ok = await client.model_exists() if reachable else False
        return reachable, model_ok
    except Exception:
        return False, False


def _status_row(name: str, ok: bool, detail: Optional[str] = None) -> None:
    icon = "[bold green]✓[/bold green]" if ok else "[bold red]✗[/bold red]"
    detail_str = f"  [dim]{detail}[/dim]" if detail else ""
    label = f"  {name:<24}"
    console.print(f"{label} {icon}{detail_str}")


def _interactive_scan() -> None:
    target = Prompt.ask("\n[bold]Enter target (IP, hostname, or URL)[/bold]", default="127.0.0.1")
    console.print(
        Panel(
            "[bold yellow]⚠ AUTHORIZATION REQUIRED[/bold yellow]\n"
            "Only scan systems you own or are explicitly authorized to test.",
            border_style="yellow"
        )
    )
    if not Confirm.ask("Do you confirm you are authorized to scan this target?", default=True):
        console.print("[red]Scan aborted: Authorization not confirmed.[/red]")
        return

    tools_input = Prompt.ask("Select scanners (comma-separated)", default="nmap,nuclei,nikto,ffuf")
    tools = [t.strip() for t in tools_input.split(",") if t.strip()]

    asyncio.run(_execute_scan_in_process(target_value=target, tools=tools))


def _interactive_findings() -> None:
    from app.database.session import db_session, init_db
    from app.database.repository import FindingRepository

    init_db()
    with db_session() as db:
        repo = FindingRepository(db)
        findings = repo.list(limit=50)

    if not findings:
        console.print("[dim]No findings recorded yet. Run a scan first.[/dim]")
        return

    table = Table(title="DISCOVERED FINDINGS", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=12)
    table.add_column("Title")
    table.add_column("Component", style="dim")
    table.add_column("Status", width=12)

    for i, f in enumerate(findings, 1):
        color = SEV_COLORS.get(f.severity, "white")
        table.add_row(
            str(i),
            f"[{color}]{f.severity}[/{color}]",
            f.title[:60],
            f.affected_component or "-",
            f.status,
        )

    console.print(table)

    idx_str = Prompt.ask("\nEnter finding number to view full details (or press Enter to return)", default="")
    if idx_str.isdigit() and 1 <= int(idx_str) <= len(findings):
        f = findings[int(idx_str) - 1]
        _show_finding_detail(f)


def _show_finding_detail(f) -> None:
    color = SEV_COLORS.get(f.severity, "white")
    console.print(f"\n[bold]Finding:[/bold] [{color}]{f.severity}[/{color}] {f.title}")
    console.print(f"[dim]Category: {f.category} | Component: {f.affected_component} | Detected by: {f.detected_by}[/dim]\n")

    if f.description:
        console.print(f"[bold]Description:[/bold]\n{f.description}\n")

    if f.ai_analysis:
        console.print(Panel(f.ai_analysis, title="[bold cyan]AI Analysis & Reasoning[/bold cyan]", border_style="cyan"))

    if f.evidence:
        console.print("[bold]Evidence:[/bold]")
        console.print(Panel(f.evidence, style="dim green", border_style="dim"))

    if f.remediation:
        console.print(f"[bold green]Recommended Fix:[/bold green]\n{f.remediation}\n")


def _interactive_remediation() -> None:
    from app.database.session import db_session, init_db
    from app.database.repository import FindingRepository, RemediationRepository
    from app.ai.remediation import RemediationAdvisor
    from app.remediation.patch_generator import PatchApplicator
    from app.config import get_settings

    init_db()
    with db_session() as db:
        findings = FindingRepository(db).list(limit=20)

    if not findings:
        console.print("[dim]No findings found.[/dim]")
        return

    console.print("\n[bold]Select a finding to generate / apply remediation:[/bold]")
    for i, f in enumerate(findings, 1):
        color = SEV_COLORS.get(f.severity, "white")
        console.print(f"  {i}. [{color}]{f.severity}[/{color}] {f.title} ({f.affected_component or 'N/A'})")

    choice = Prompt.ask("\nEnter number", default="1")
    if not (choice.isdigit() and 1 <= int(choice) <= len(findings)):
        return

    finding = findings[int(choice) - 1]

    with console.status("[bold cyan]Generating AI Remediation Plan...[/bold cyan]", spinner="dots"):
        advisor = RemediationAdvisor(get_settings())
        plan = asyncio.run(advisor.generate(finding))

    console.print(Panel(
        f"[bold]{plan.get('title', 'Remediation Plan')}[/bold]\n\n"
        f"{plan.get('description', '')}\n\n"
        "[bold]Steps:[/bold]\n" +
        "\n".join(f"{i+1}. {step}" for i, step in enumerate(plan.get("steps", []))),
        title="[bold green]AI Remediation Plan[/bold green]",
        border_style="green",
    ))

    if plan.get("patch_diff"):
        console.print("\n[bold]Proposed Patch Diff:[/bold]")
        console.print(Syntax(plan["patch_diff"], "diff", theme="monokai", line_numbers=True))

        if Confirm.ask("\nDo you want to save and review this remediation action?", default=True):
            with db_session() as db:
                action = RemediationRepository(db).create(
                    finding_id=finding.id,
                    action_type=plan.get("action_type", "PATCH"),
                    title=plan.get("title", "Remediation Plan"),
                    description=plan.get("description"),
                    steps=plan.get("steps"),
                    patch_diff=plan.get("patch_diff"),
                    target_file=plan.get("target_file"),
                    status="APPROVED" if Confirm.ask("Approve this patch?", default=False) else "PROPOSED",
                )
                console.print(f"[bold green]✓ Action recorded (ID: {action.id[:8]})[/bold green]")


def _interactive_verify() -> None:
    from app.database.session import db_session, init_db
    from app.database.repository import FindingRepository
    from app.remediation.verifier import VerificationEngine
    from app.config import get_settings

    init_db()
    with db_session() as db:
        findings = FindingRepository(db).list(limit=20)

    if not findings:
        console.print("[dim]No findings found to verify.[/dim]")
        return

    console.print("\n[bold]Select finding to verify:[/bold]")
    for i, f in enumerate(findings, 1):
        console.print(f"  {i}. {f.title} ({f.affected_component or 'N/A'})")

    choice = Prompt.ask("\nEnter number", default="1")
    if not (choice.isdigit() and 1 <= int(choice) <= len(findings)):
        return

    finding = findings[int(choice) - 1]
    verifier = VerificationEngine(get_settings())

    with console.status(f"[bold cyan]Verifying finding '{finding.title}'...[/bold cyan]"):
        result = asyncio.run(verifier.verify(finding))

    if result.get("passed"):
        console.print(Panel(f"[bold green]✓ VERIFIED FIXED[/bold green]\nMethod: {result.get('method')}\nNotes: {result.get('notes')}", border_style="green"))
    else:
        console.print(Panel(f"[bold red]✗ NOT FIXED / MANUAL CHECK REQUIRED[/bold red]\nMethod: {result.get('method')}\nNotes: {result.get('notes')}", border_style="red"))


def _interactive_targets() -> None:
    from app.database.session import db_session, init_db
    from app.database.repository import TargetRepository

    init_db()
    with db_session() as db:
        targets = TargetRepository(db).list()

    table = Table(title="REGISTERED TARGETS", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Authorized")

    for i, t in enumerate(targets, 1):
        table.add_row(
            str(i),
            t.name,
            t.target_type,
            t.value,
            "[green]YES[/green]" if t.authorization_confirmed else "[red]NO[/red]",
        )
    console.print(table)


def _interactive_report() -> None:
    from app.database.session import db_session, init_db
    from app.database.repository import ScanRepository, TargetRepository, FindingRepository
    from app.utils.reporter import ReportGenerator

    init_db()
    with db_session() as db:
        scans = ScanRepository(db).list(limit=10)

    if not scans:
        console.print("[dim]No scans available to report on.[/dim]")
        return

    console.print("\n[bold]Select a scan to export:[/bold]")
    for i, s in enumerate(scans, 1):
        console.print(f"  {i}. #{s.id[:8]} ({s.status}) - {s.created_at.strftime('%Y-%m-%d %H:%M')}")

    choice = Prompt.ask("Enter scan number", default="1")
    if not (choice.isdigit() and 1 <= int(choice) <= len(scans)):
        return

    scan = scans[int(choice) - 1]
    fmt = Prompt.ask("Select format", choices=["markdown", "html", "json"], default="markdown")

    with db_session() as db:
        target = TargetRepository(db).get(scan.target_id)
        findings = FindingRepository(db).list(scan_id=scan.id)

    generator = ReportGenerator()
    content, _ = generator.generate(scan, target, findings, fmt=fmt)

    ext = "md" if fmt == "markdown" else fmt
    out_file = f"bug-hunter-report-{scan.id[:8]}.{ext}"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(content)

    console.print(f"[bold green]✓ Report exported successfully to:[/bold green] [bold]{out_file}[/bold]")


def _interactive_activity() -> None:
    from app.database.session import db_session, init_db
    from app.database.repository import ActivityRepository

    init_db()
    with db_session() as db:
        logs = ActivityRepository(db).list(limit=25)

    table = Table(title="LOCAL AUDIT & ACTIVITY LOG", border_style="cyan")
    table.add_column("Time", style="dim", width=12)
    table.add_column("Level", width=10)
    table.add_column("Event Type", width=22)
    table.add_column("Message")

    for l in logs:
        lvl_color = "red" if l.level == "ERROR" else "yellow" if l.level == "WARNING" else "green"
        table.add_row(
            l.created_at.strftime("%H:%M:%S"),
            f"[{lvl_color}]{l.level}[/{lvl_color}]",
            l.event_type,
            l.message,
        )
    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Direct CLI commands
# ─────────────────────────────────────────────────────────────────────────────

@app.command("status")
def status_cmd() -> None:
    """Show system status and tool availability."""
    _print_banner()
    _run_setup_check()


@app.command("tools")
def tools_cmd() -> None:
    """Show installed security scanner status."""
    _print_banner()
    from app.scanners.registry import ScannerRegistry
    from app.config import get_settings

    settings = get_settings()
    registry = ScannerRegistry()

    table = Table(title="BUG HUNTER — SECURITY TOOL STATUS", border_style="cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Version", style="dim")
    table.add_column("Install (Linux)")
    table.add_column("Install (macOS)")

    install_info = {
        "nmap": ("sudo apt install nmap", "brew install nmap"),
        "nuclei": ("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "brew install nuclei"),
        "nikto": ("sudo apt install nikto", "brew install nikto"),
        "ffuf": ("go install github.com/ffuf/ffuf/v2@latest", "brew install ffuf"),
    }

    for scanner in registry.all_scanners():
        available = scanner.is_available()
        version = scanner.get_version() if available else "-"
        status_str = "[bold green]INSTALLED[/bold green]" if available else "[bold red]NOT INSTALLED[/bold red]"
        linux_cmd, macos_cmd = install_info.get(scanner.name, ("see docs", "see docs"))
        table.add_row(scanner.name.upper(), status_str, version or "-", linux_cmd, macos_cmd)

    ollama_ok, model_ok = asyncio.run(_check_ollama(settings))
    table.add_row(
        "OLLAMA",
        "[bold green]RUNNING[/bold green]" if ollama_ok else "[bold red]NOT RUNNING[/bold red]",
        "-",
        "curl -fsSL https://ollama.com/install.sh | sh",
        "brew install ollama",
    )
    table.add_row(
        f"MODEL ({settings.ollama_model})",
        "[bold green]READY[/bold green]" if model_ok else "[bold yellow]NOT PULLED[/bold yellow]",
        "-",
        f"ollama pull {settings.ollama_model}",
        f"ollama pull {settings.ollama_model}",
    )
    console.print(table)


@app.command("scan")
def scan_cmd(
    target: str = typer.Argument(..., help="Target to scan (IP, hostname, URL)"),
    tools: Optional[str] = typer.Option(
        "nmap,nuclei,nikto,ffuf", "--tools", "-t",
        help="Comma-separated list of tools to use"
    ),
    authorize: bool = typer.Option(
        False, "--authorize", "-a",
        help="Confirm you are authorized to scan this target"
    ),
) -> None:
    """Start an authorized security scan directly from terminal."""
    _print_banner()

    if not authorize:
        console.print(
            Panel(
                "[bold yellow]⚠ AUTHORIZATION REQUIRED[/bold yellow]\n\n"
                "You must confirm you are authorized to scan this target.\n"
                "Re-run with: [bold]python3 -m cli.main scan {target} --authorize[/bold]",
                border_style="yellow",
            )
        )
        raise typer.Exit(1)

    tool_list = [t.strip() for t in tools.split(",") if t.strip()]
    asyncio.run(_execute_scan_in_process(target_value=target, tools=tool_list))


@app.command("findings")
def findings_cmd(
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max findings to show"),
) -> None:
    """List security findings."""
    _print_banner()
    from app.database.session import db_session, init_db
    from app.database.repository import FindingRepository

    init_db()
    with db_session() as db:
        findings = FindingRepository(db).list(severity=severity, limit=limit)

    _display_findings_table(findings)


@app.command("config")
def config_cmd() -> None:
    """Show configuration settings."""
    from app.config import get_settings
    settings = get_settings()

    table = Table(title="Bug Hunter Configuration", border_style="cyan")
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    table.add_row("Execution Mode", "100% Local Terminal CLI")
    table.add_row("Ollama Host", settings.ollama_host)
    table.add_row("AI Model", settings.ollama_model)
    table.add_row("Database Path", str(settings.db_path))
    table.add_row("Log Level", settings.log_level)
    table.add_row("Require Authorization", str(settings.require_authorization))
    table.add_row("Auto Apply Fixes", str(settings.auto_apply_fixes))

    console.print(table)


@app.command("report")
def report_cmd(
    scan_id: str = typer.Argument(..., help="Scan ID to generate report for"),
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown|html|json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate a security report for a scan directly to a file."""
    from app.database.session import db_session, init_db
    from app.database.repository import ScanRepository, TargetRepository, FindingRepository
    from app.utils.reporter import ReportGenerator

    init_db()
    with db_session() as db:
        scan = ScanRepository(db).get(scan_id)
        if not scan:
            console.print(f"[bold red]Scan '{scan_id}' not found.[/bold red]")
            raise typer.Exit(1)
        target = TargetRepository(db).get(scan.target_id)
        findings = FindingRepository(db).list(scan_id=scan_id)

    generator = ReportGenerator()
    content, _ = generator.generate(scan, target, findings, fmt=fmt)

    ext = "md" if fmt == "markdown" else fmt
    out_path = output or f"bug-hunter-report-{scan_id[:8]}.{ext}"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)

    console.print(f"[bold green]✓ Report generated successfully:[/bold green] {out_path}")


if __name__ == "__main__":
    app()
