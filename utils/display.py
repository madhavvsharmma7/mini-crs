from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.text import Text
from rich.rule import Rule
from rich import box

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan"
}

VERDICT_COLORS = {
    "PASS": "bold green",
    "PARTIAL": "bold yellow",
    "FAIL": "bold red"
}

def print_banner():
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Mini CRS[/bold cyan] [white]— Cyber Reasoning System[/white]\n"
        "[dim]LLM Orchestration Layer | AI Kavach / Delvox Labs[/dim]",
        border_style="cyan"
    ))
    console.print()

def print_agent_start(agent_num: int, name: str):
    console.print(f"[dim]▶ Agent {agent_num}:[/dim] [bold white]{name}[/bold white]", end=" ")

def print_agent_done():
    console.print("[green]✓[/green]")

def print_static_analysis(data: dict):
    console.print()
    console.print(Rule("[bold]Agent 1 — Static Analysis[/bold]", style="cyan"))
    
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        console.print("[green]No vulnerabilities found.[/green]")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Line", style="dim", width=6)
    table.add_column("Type", width=28)
    table.add_column("Description", width=48)
    table.add_column("Severity", width=10)

    for v in vulns:
        sev = v.get("severity", "LOW")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(v.get("line") or "—"),
            v.get("type", ""),
            v.get("description", ""),
            f"[{color}]{sev}[/{color}]"
        )

    console.print(table)
    console.print(f"[dim]Summary:[/dim] {data.get('summary', '')}")

def print_classification(data: dict):
    console.print()
    console.print(Rule("[bold]Agent 2 — CWE Classification[/bold]", style="cyan"))

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Vulnerability", width=28)
    table.add_column("CWE", width=12)
    table.add_column("CWE Name", width=30)
    table.add_column("CVSS", width=6)
    table.add_column("Attack Vector", width=36)

    for c in data.get("classifications", []):
        score = c.get("cvss_score", 0)
        score_color = "red" if score >= 7 else "yellow" if score >= 4 else "green"
        table.add_row(
            c.get("type", ""),
            c.get("cwe_id", ""),
            c.get("cwe_name", ""),
            f"[{score_color}]{score}[/{score_color}]",
            c.get("attack_vector", "")
        )

    console.print(table)

def print_patch(data: dict):
    console.print()
    console.print(Rule("[bold]Agent 3 — Patch Generator[/bold]", style="cyan"))

    for change in data.get("changes", []):
        console.print(f"  [green]✓[/green] [bold]{change['vulnerability']}[/bold]")
        console.print(f"    [dim]{change['fix_description']}[/dim]")

    console.print()
    patched = data.get("patched_code", "")
    # detect language
    lang = "python" if "def " in patched or "import " in patched else "c"
    syntax = Syntax(patched, lang, theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="[bold green]Patched Code[/bold green]", border_style="green"))

def print_verification(data: dict):
    console.print()
    console.print(Rule("[bold]Agent 4 — Patch Verification[/bold]", style="cyan"))

    verdict = data.get("verdict", "FAIL")
    color = VERDICT_COLORS.get(verdict, "white")
    confidence = data.get("confidence", 0)

    console.print(f"  Verdict:    [{color}]{verdict}[/{color}]")
    console.print(f"  Confidence: [bold]{confidence}%[/bold]")

    console.print()
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Vulnerability", width=28)
    table.add_column("Resolved", width=10)
    table.add_column("Reason", width=48)

    for r in data.get("resolved", []):
        resolved = r.get("resolved", False)
        status = "[green]✓ YES[/green]" if resolved else "[red]✗ NO[/red]"
        table.add_row(r.get("vulnerability", ""), status, r.get("reason", ""))

    console.print(table)

    new_issues = data.get("new_issues", [])
    if new_issues and any(new_issues):
        console.print()
        console.print("[yellow]⚠ New issues introduced:[/yellow]")
        for issue in new_issues:
            if issue:
                console.print(f"  [yellow]• {issue}[/yellow]")

def print_summary(results: dict):
    console.print()
    console.print(Rule("[bold]CRS Summary[/bold]", style="cyan"))

    vulns = results["static_analysis"].get("vulnerabilities", [])
    verdict = results["verification"].get("verdict", "FAIL")
    confidence = results["verification"].get("confidence", 0)
    patches = results["patch"].get("changes", [])

    console.print(f"  Vulnerabilities found:  [bold]{len(vulns)}[/bold]")
    console.print(f"  Patches applied:        [bold]{len(patches)}[/bold]")
    verdict_color = VERDICT_COLORS.get(verdict, "white")
    console.print(f"  Verification verdict:   [{verdict_color}]{verdict}[/{verdict_color}]")
    console.print(f"  Confidence:             [bold]{confidence}%[/bold]")
    console.print()
