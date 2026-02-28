"""
main.py
-------
CLI entry point for nginx-log-analyzer.

Usage
-----
    python main.py --log /var/log/nginx/access.log
    python main.py --log access.log --blacklist data/blacklist.csv --top 15
    python main.py --log access.log --no-telegram   # skip Telegram even if configured

Options
-------
    --log        PATH   Nginx access log file (required)
    --blacklist  PATH   IP blacklist CSV  (optional, default: data/blacklist.csv)
    --top        INT    How many top IPs / paths to show (default: 10)
    --no-telegram       Disable Telegram notification for this run
    --verbose           Enable DEBUG-level logging
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import print as rprint

# ── project imports ──────────────────────────────────────────────────────────
# Support both  python main.py  (project root) and installed package layout
sys.path.insert(0, str(Path(__file__).parent))

from analyzer.parser  import parse_log_file
from analyzer.stats   import calculate, TOP_N
from analyzer.filter  import analyze as filter_analyze, ThreatLevel, ThreatResult
from notifiers.telegram import send_message

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# CLI definition
# ─────────────────────────────────────────────────────────────────────────────

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--log", "-l",
    required=True,
    type=click.Path(exists=True, readable=True, dir_okay=False),
    help="Path to the Nginx access log file.",
)
@click.option(
    "--blacklist", "-b",
    default="data/blacklist.csv",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Path to the IP blacklist CSV (ip, reason, added_date).",
)
@click.option(
    "--top", "-n",
    default=TOP_N,
    show_default=True,
    type=click.IntRange(1, 100),
    help="Number of top IPs / paths to display.",
)
@click.option(
    "--no-telegram",
    is_flag=True,
    default=False,
    help="Skip sending the Telegram alert even if HIGH-threat IPs are found.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable DEBUG-level logging.",
)
def main(
    log: str,
    blacklist: str,
    top: int,
    no_telegram: bool,
    verbose: bool,
) -> None:
    """🔍 Nginx Log Analyzer — parse, score threats, and alert."""

    # ── Logging setup ─────────────────────────────────────────────────────
    logging.basicConfig(
        level   = logging.DEBUG if verbose else logging.WARNING,
        format  = "%(levelname)s  %(name)s  %(message)s",
        stream  = sys.stderr,
    )

    console.rule("[bold cyan]Nginx Log Analyzer[/bold cyan]")

    # ── 1. Parse ──────────────────────────────────────────────────────────
    with console.status("[cyan]Parsing log file…[/cyan]"):
        try:
            entries: list[dict] = parse_log_file(log)
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            console.print(f"[bold red]✖ Cannot read log file:[/bold red] {exc}")
            sys.exit(1)

    console.print(f"[green]✔[/green] Parsed [bold]{len(entries):,}[/bold] entries from [italic]{log}[/italic]")

    if not entries:
        console.print("[yellow]⚠ Log file is empty — nothing to report.[/yellow]")
        sys.exit(0)

    # ── 2. Stats ──────────────────────────────────────────────────────────
    with console.status("[cyan]Calculating statistics…[/cyan]"):
        stats = calculate(entries)

    # ── 3. Filter + threat scoring ────────────────────────────────────────
    bl_path = blacklist if Path(blacklist).exists() else None
    if bl_path:
        console.print(f"[green]✔[/green] Blacklist loaded from [italic]{bl_path}[/italic]")
    else:
        console.print(f"[dim]ℹ No blacklist file found at {blacklist!r} — skipping.[/dim]")

    with console.status("[cyan]Scoring threats…[/cyan]"):
        _error_entries, threats = filter_analyze(entries, bl_path, use_abuseipdb=True)

    # ── 4. Render rich terminal report ────────────────────────────────────
    _render_summary(stats, top)
    _render_threats(threats)

    # ── 5. Telegram alert for HIGH-threat IPs ─────────────────────────────
    high_threats = [t for t in threats if t.threat_level == ThreatLevel.HIGH]

    if high_threats and not no_telegram:
        console.print("\n[bold red]🚨 HIGH-threat IPs detected — sending Telegram alert…[/bold red]")
        message = _build_telegram_message(stats, high_threats, log)
        ok = send_message(message)
        if ok:
            console.print("[green]✔ Telegram alert sent.[/green]")
        else:
            console.print(
                "[yellow]⚠ Telegram notification failed "
                "(check TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID in .env).[/yellow]"
            )
    elif high_threats and no_telegram:
        console.print(
            f"\n[yellow]⚠ {len(high_threats)} HIGH-threat IP(s) found "
            "but --no-telegram was set.[/yellow]"
        )
    else:
        console.print("\n[green]✔ No HIGH-threat IPs detected.[/green]")

    console.rule()


# ─────────────────────────────────────────────────────────────────────────────
# Rich rendering helpers
# ─────────────────────────────────────────────────────────────────────────────

def _render_summary(stats, top: int) -> None:
    """Print the Nginx Log Summary panel."""

    console.print()

    # ── Overview grid ─────────────────────────────────────────────────────
    overview = Table.grid(padding=(0, 4))
    overview.add_column(style="bold cyan",  no_wrap=True)
    overview.add_column(style="bold white", no_wrap=True)
    overview.add_column(style="bold cyan",  no_wrap=True)
    overview.add_column(style="bold white", no_wrap=True)

    ts_from = stats.first_request.strftime("%Y-%m-%d %H:%M") if stats.first_request else "—"
    ts_to   = stats.last_request.strftime("%Y-%m-%d %H:%M")  if stats.last_request  else "—"

    overview.add_row("Total Requests",  f"{stats.total_requests:,}",
                     "Unique IPs",      f"{stats.unique_ips:,}")
    overview.add_row("Unique Paths",    f"{stats.unique_paths:,}",
                     "Bandwidth",       stats.bandwidth_human())
    overview.add_row("Malformed",       f"{stats.malformed_count:,}",
                     "Period",          f"{ts_from}  →  {ts_to}")

    console.print(Panel(overview, title="[bold]📊 Nginx Log Summary[/bold]",
                         border_style="cyan", expand=False))

    # ── Status codes ──────────────────────────────────────────────────────
    status_tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
    status_tbl.add_column("Group",  style="bold", width=7)
    status_tbl.add_column("Count",  justify="right", width=10)
    status_tbl.add_column("Bar",    no_wrap=True)

    _STATUS_STYLES = {"2xx": "green", "3xx": "blue", "4xx": "yellow", "5xx": "red", "other": "dim"}
    total = stats.total_requests or 1

    for label in ("2xx", "3xx", "4xx", "5xx", "other"):
        count = stats.status_counts[label]
        if not count:
            continue
        pct  = count / total * 100
        bar  = "█" * max(1, int(pct / 2))
        style = _STATUS_STYLES.get(label, "white")
        status_tbl.add_row(
            Text(label, style=style),
            Text(f"{count:,}", style=style),
            Text(f"{bar}  {pct:.1f}%", style=style),
        )

    console.print(Panel(status_tbl, title="[bold]📈 Status Code Distribution[/bold]",
                         border_style="magenta", expand=False))

    # ── HTTP Methods ──────────────────────────────────────────────────────
    method_tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold blue")
    method_tbl.add_column("Method",  style="bold cyan", width=10)
    method_tbl.add_column("Count",   justify="right",   width=10)

    for method, count in stats.method_counts.most_common():
        method_tbl.add_row(method, f"{count:,}")

    # ── Top IPs ───────────────────────────────────────────────────────────
    ip_tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold blue")
    ip_tbl.add_column("#",        justify="right", width=4,  style="dim")
    ip_tbl.add_column("IP Address", style="bold cyan", width=20)
    ip_tbl.add_column("Requests",   justify="right",   width=10)

    for rank, (ip, count) in enumerate(stats.top_ips[:top], 1):
        ip_tbl.add_row(str(rank), ip, f"{count:,}")

    # ── Top Paths ─────────────────────────────────────────────────────────
    path_tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold blue")
    path_tbl.add_column("#",       justify="right", width=4, style="dim")
    path_tbl.add_column("Path",    style="cyan")
    path_tbl.add_column("Requests", justify="right", width=10)

    for rank, (path, count) in enumerate(stats.top_paths[:top], 1):
        path_tbl.add_row(str(rank), path, f"{count:,}")

    # Render the three tables side-by-side in a grid
    grid = Table.grid(padding=(0, 2))
    grid.add_column()
    grid.add_column()
    grid.add_column()
    grid.add_row(
        Panel(method_tbl, title="[bold]🔧 HTTP Methods[/bold]",   border_style="blue", expand=False),
        Panel(ip_tbl,     title=f"[bold]🌐 Top {top} IPs[/bold]", border_style="blue", expand=False),
        Panel(path_tbl,   title=f"[bold]🗂 Top {top} Paths[/bold]", border_style="blue", expand=False),
    )
    console.print(grid)


def _render_threats(threats: list[ThreatResult]) -> None:
    """Print the threat scoring table.

    Column layout rationale
    -----------------------
    Fixed-width columns (width=N, no_wrap=True):
        Level   – badge text is always the same length ("🔴 HIGH  " etc.)
        IP      – IPv4 fits in 18 chars; IPv6 needs up to 39 → min_width=20
        Reqs    – small integer, never wraps
        4xx     – small integer, never wraps
        5xx     – small integer, never wraps
        Country – ISO-3166 2-letter code or empty, never wraps

    Fluid column (ratio=1, no_wrap=False):
        Reasons – takes ALL remaining horizontal space and word-wraps
                  long reason strings (AbuseIPDB ISP names, path probes…)
                  so they never overflow into adjacent columns.

    Table-level settings:
        expand=True    – always fill the full console width
        min_width=100  – prevents collapse to an unreadable width when the
                         terminal is narrower than the fixed columns need
    """

    _BADGE = {
        ThreatLevel.HIGH:   "[bold red]🔴 HIGH  [/bold red]",
        ThreatLevel.MEDIUM: "[bold yellow]🟡 MEDIUM[/bold yellow]",
        ThreatLevel.LOW:    "[dim green]🟢 LOW   [/dim green]",
    }
    _ROW_STYLE = {
        ThreatLevel.HIGH:   "on dark_red",
        ThreatLevel.MEDIUM: "",
        ThreatLevel.LOW:    "dim",
    }

    # ── Fixed-width columns first; fluid Reasons column last ─────────────
    # rich allocates fixed/min widths first, then distributes the leftover
    # space proportionally among ratio columns.  With ratio=1 on Reasons
    # alone, it gets 100 % of that leftover — exactly what we want.
    tbl = Table(
        box        = box.ROUNDED,
        show_header= True,
        header_style = "bold white on dark_blue",
        row_styles   = ["", "on grey11"],   # zebra-stripe rows
        expand       = True,                # fill full terminal width
        min_width    = 100,                 # never collapse below this
        show_lines   = True,                # horizontal rule between rows
                                            # so multi-line Reasons are easy to read
    )

    # ── Columns with fixed / minimum widths (no_wrap=True) ───────────────
    tbl.add_column("Level",
                   width=12, no_wrap=True)

    tbl.add_column("IP",
                   style="bold cyan",
                   min_width=20, no_wrap=True)  # min_width handles IPv6

    tbl.add_column("Reqs",
                   justify="right",
                   width=5, no_wrap=True)

    tbl.add_column("4xx",
                   justify="right",
                   width=5, no_wrap=True,
                   style="yellow")

    tbl.add_column("5xx",
                   justify="right",
                   width=5, no_wrap=True,
                   style="red")

    tbl.add_column("CC",                    # country code from AbuseIPDB
                   justify="center",
                   width=4, no_wrap=True,
                   style="dim cyan",
                   header_style="bold dim cyan")

    # ── Fluid column: takes all remaining space and word-wraps ────────────
    # no_wrap=False  → rich wraps long lines at word boundaries
    # ratio=1        → gets 100 % of unused horizontal space
    # overflow="fold"→ hard-wraps the rare single token longer than the cell
    tbl.add_column("Reasons",
                   ratio=1,
                   no_wrap=False,
                   overflow="fold")

    # ── Rows ──────────────────────────────────────────────────────────────
    for t in threats:
        reasons_str = "\n".join(f"• {r}" for r in t.reasons)
        country     = t.country_code if hasattr(t, "country_code") else ""

        tbl.add_row(
            _BADGE[t.threat_level],
            t.ip,
            str(t.total_requests),
            str(t.error_4xx_count),
            str(t.error_5xx_count),
            country,
            reasons_str,
            style=_ROW_STYLE[t.threat_level],
        )

    high   = sum(1 for t in threats if t.threat_level == ThreatLevel.HIGH)
    medium = sum(1 for t in threats if t.threat_level == ThreatLevel.MEDIUM)

    console.print(Panel(
        tbl,
        title=(
            f"[bold]🛡 Threat Report  "
            f"[red]🔴 {high} HIGH[/red]  "
            f"[yellow]🟡 {medium} MEDIUM[/yellow]  "
            f"[dim]🟢 {len(threats) - high - medium} LOW[/dim][/bold]"
        ),
        border_style = "red"    if high   else
                       "yellow" if medium else "green",
        expand       = True,
        padding      = (0, 1),  # tighter horizontal padding inside Panel
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Telegram message builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_telegram_message(
    stats,
    high_threats: list[ThreatResult],
    log_path: str,
) -> str:
    """
    Compose an HTML-formatted Telegram alert message.

    Structure:
        🚨 header + log file name
        📊 Overview (total req, 4xx, 5xx, malformed)
        🔴 Per-IP detail block for each HIGH-threat IP
    """
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────
    lines += [
        "🚨 <b>Nginx Security Alert</b>",
        f"📄 Log: <code>{log_path}</code>",
        "",
    ]

    # ── Overview ──────────────────────────────────────────────────────────
    lines += [
        "📊 <b>Overview</b>",
        f"  • Total requests : <b>{stats.total_requests:,}</b>",
        f"  • 4xx errors     : <b>{stats.status_counts['4xx']:,}</b>",
        f"  • 5xx errors     : <b>{stats.status_counts['5xx']:,}</b>",
        f"  • Malformed      : <b>{stats.malformed_count:,}</b>",
        f"  • Bandwidth      : <b>{stats.bandwidth_human()}</b>",
        "",
        f"🔴 <b>{len(high_threats)} HIGH-threat IP(s) detected</b>",
        "━━━━━━━━━━━━━━━━━━━━",
    ]

    # ── Per-IP detail ─────────────────────────────────────────────────────
    for t in high_threats:
        # Header row for this IP
        bl_tag = "  🏴 <i>blacklisted</i>" if t.in_blacklist else ""
        lines.append(
            f"\n🔴 <code>{t.ip}</code>{bl_tag}"
        )
        lines.append(
            f"   Requests: <b>{t.total_requests}</b>  "
            f"4xx: <b>{t.error_4xx_count}</b>  "
            f"5xx: <b>{t.error_5xx_count}</b>  "
            f"malformed: <b>{t.malformed_count}</b>"
        )

        # Reasons
        for reason in t.reasons:
            lines.append(f"   ▸ {reason}")

        # Sensitive path samples (up to 3)
        if t.sensitive_path_hits:
            lines.append("   🗂 Sensitive paths probed:")
            for path, label in t.sensitive_path_hits[:3]:
                lines.append(f"     – <code>{path}</code>  <i>({label})</i>")

        # Malformed payload samples (up to 3)
        if t.malformed_samples:
            lines.append("   📦 Raw payloads:")
            for sample in t.malformed_samples[:3]:
                safe = sample.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                lines.append(f"     – <code>{safe}</code>")

    lines += ["", "━━━━━━━━━━━━━━━━━━━━",
              "🤖 <i>nginx-log-analyzer</i>"]

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()