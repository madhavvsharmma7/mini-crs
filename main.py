#!/usr/bin/env python3
import typer
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.orchestrator import run_crs, run_agent, AGENT_1_SYSTEM, AGENT_2_SYSTEM, AGENT_3_SYSTEM, AGENT_4_SYSTEM
from utils.display import (
    console, print_banner, print_agent_start, print_agent_done,
    print_static_analysis, print_classification, print_patch,
    print_verification, print_summary
)



app = typer.Typer(help="Mini CRS — Cyber Reasoning System (AI Kavach)", invoke_without_command=True, no_args_is_help=True)

def run_with_display(code: str):
    """Run all 4 agents with live status display."""
    results = {}

    # Agent 1
    print_agent_start(1, "Static Analyzer")
    raw = run_agent(AGENT_1_SYSTEM, f"Analyze this code for vulnerabilities:\n\n{code}")
    a1 = json.loads(raw)
    results["static_analysis"] = a1
    print_agent_done()

    # Agent 2
    print_agent_start(2, "CWE Classifier")
    a2_input = f"Original code:\n{code}\n\nVulnerabilities found:\n{json.dumps(a1, indent=2)}"
    raw = run_agent(AGENT_2_SYSTEM, a2_input)
    a2 = json.loads(raw)
    results["classification"] = a2
    print_agent_done()

    # Agent 3
    print_agent_start(3, "Patch Generator")
    a3_input = f"Vulnerable code:\n{code}\n\nVulnerabilities:\n{json.dumps(a1, indent=2)}\n\nClassifications:\n{json.dumps(a2, indent=2)}"
    raw = run_agent(AGENT_3_SYSTEM, a3_input)
    a3 = json.loads(raw)
    results["patch"] = a3
    print_agent_done()

    # Agent 4
    print_agent_start(4, "Patch Verifier")
    a4_input = f"Original code:\n{code}\n\nPatched code:\n{a3['patched_code']}\n\nVulnerabilities that should be fixed:\n{json.dumps(a1, indent=2)}"
    raw = run_agent(AGENT_4_SYSTEM, a4_input)
    a4 = json.loads(raw)
    results["verification"] = a4
    print_agent_done()

    return results


@app.callback()
def scan(
    file: Path = typer.Option(None, "--file", "-f", help="Path to source file to analyze"),
    code: str = typer.Option(None, "--code", "-c", help="Inline code string to analyze"),
    output: Path = typer.Option(None, "--output", "-o", help="Save JSON report to file"),
    demo: bool = typer.Option(False, "--demo", "-d", help="Run with built-in demo vulnerable code")
):
    """
    Scan source code for vulnerabilities, classify them, patch them, and verify the fix.
    """
    print_banner()

    # Get code input
    if demo:
        target_code = DEMO_CODE
        console.print("[dim]Running demo with built-in vulnerable Python code...[/dim]\n")
    elif file:
        if not file.exists():
            console.print(f"[red]Error: File not found: {file}[/red]")
            raise typer.Exit(1)
        target_code = file.read_text()
        console.print(f"[dim]Scanning:[/dim] [bold]{file}[/bold]\n")
    elif code:
        target_code = code
        console.print("[dim]Scanning inline code...[/dim]\n")
    else:
        console.print("[red]Provide --file, --code, or --demo[/red]")
        raise typer.Exit(1)

    # Run agents
    try:
        results = run_with_display(target_code)
    except json.JSONDecodeError as e:
        console.print(f"\n[red]Agent returned invalid JSON: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[red]API error: {e}[/red]")
        raise typer.Exit(1)

    # Display results
    print_static_analysis(results["static_analysis"])
    print_classification(results["classification"])
    print_patch(results["patch"])
    print_verification(results["verification"])
    print_summary(results)

    # Save output
    if output:
        output.write_text(json.dumps(results, indent=2))
        console.print(f"[dim]Report saved to:[/dim] [bold]{output}[/bold]\n")


DEMO_CODE = '''import sqlite3
import os
import subprocess

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable: SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def read_file(filename):
    # Vulnerable: Path traversal
    base_dir = "/var/app/files/"
    filepath = base_dir + filename
    with open(filepath, "r") as f:
        return f.read()

def run_command(user_input):
    # Vulnerable: Command injection
    result = subprocess.run("ping -c 1 " + user_input, shell=True, capture_output=True)
    return result.stdout

def store_password(password):
    # Vulnerable: Hardcoded secret + weak storage
    secret_key = "admin123"
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO passwords VALUES ('{password}')")
    conn.commit()
'''


if __name__ == "__main__":
    app()
