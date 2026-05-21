#!/usr/bin/env python3
"""
WiFi Network Scanner
Author: Roshim Bhatta
GitHub: github.com/RocmDaGr8

Reads publicly broadcast 802.11 beacon frames using the macOS airport
utility — the same data shown in your Mac's WiFi menu bar.

Displays per-network:
  - SSID / BSSID
  - RSSI (signal strength in dBm + visual bar)
  - Channel
  - Security type with color-coded risk label

Legal note: Every access point continuously broadcasts these details
as public beacon frames. Reading them requires no credentials and is
equivalent to using your computer's built-in WiFi menu.

Usage:
  python3 scanner.py             # one-shot scan
  python3 scanner.py -w 5        # auto-refresh every 5 seconds
  python3 scanner.py -n 15       # show top 15 networks only
  python3 scanner.py --no-legend # skip security legend
"""

import subprocess
import argparse
import time
import sys
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

# --- macOS airport binary path ---
AIRPORT = (
    "/System/Library/PrivateFrameworks/Apple80211.framework"
    "/Versions/Current/Resources/airport"
)

console = Console()


def run_scan():
    """
    Run airport -s and return a list of network dicts sorted by RSSI.
    Airport scans 2.4 GHz and 5 GHz channels and prints one line per
    access point it hears a beacon frame from.
    """
    try:
        result = subprocess.run(
            [AIRPORT, "-s"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except FileNotFoundError:
        console.print("[bold red]Error:[/] airport utility not found.")
        console.print(f"  Expected: {AIRPORT}")
        console.print("  This tool is macOS-only.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        console.print("[bold yellow]Warning:[/] Scan timed out. Is WiFi enabled?")
        return []

    lines = result.stdout.strip().split("\n")
    if len(lines) < 2:
        return []

    networks = []
    for line in lines[1:]:
        if not line.strip():
            continue
        net = _parse_line(line)
        if net:
            networks.append(net)

    networks.sort(key=lambda x: x["rssi"], reverse=True)
    return networks


def _parse_line(line):
    """
    Parse one output line from airport -s.
    Locates BSSID (XX:XX:XX:XX:XX:XX) as anchor and works outward.
    Columns: [SSID padded]  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
    """
    parts = line.split()
    if len(parts) < 5:
        return None

    bssid_idx = None
    for i, part in enumerate(parts):
        if len(part) == 17 and part.count(":") == 5:
            bssid_idx = i
            break

    if bssid_idx is None:
        return None

    try:
        ssid     = " ".join(parts[:bssid_idx]) or "<hidden>"
        bssid    = parts[bssid_idx]
        rssi     = int(parts[bssid_idx + 1])
        channel  = parts[bssid_idx + 2]
        security_parts = parts[bssid_idx + 5:]
        security = " ".join(security_parts) if security_parts else "NONE"
        return {"ssid": ssid, "bssid": bssid, "rssi": rssi,
                "channel": channel, "security": security}
    except (IndexError, ValueError):
        return None


def rssi_bar(rssi):
    """Convert dBm RSSI to a visual signal bar."""
    if rssi >= -50:
        return "Excellent"
    elif rssi >= -60:
        return "Good     "
    elif rssi >= -70:
        return "Fair     "
    elif rssi >= -80:
        return "Weak     "
    else:
        return "Poor     "


def security_style(security):
    """Return (rich_color, label) based on security protocol."""
    s = security.upper()
    if "WPA3" in s:
        return "green",  "WPA3 [secure]"
    elif "WPA2" in s:
        return "yellow", "WPA2 [ok]    "
    elif "WPA" in s:
        return "red",    "WPA  [weak]  "
    elif "WEP" in s:
        return "red",    "WEP  [broken]"
    else:
        return "red",    "OPEN [none]  "


def build_table(networks, limit=None):
    """Build and return a rich Table from the list of scanned networks."""
    ts    = datetime.now().strftime("%H:%M:%S")
    shown = networks[:limit] if limit else networks

    table = Table(
        title=f"  WiFi Networks — {len(networks)} found  [{ts}]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        title_style="bold white",
        padding=(0, 1),
    )
    table.add_column("#",        style="dim",        width=3,  justify="right")
    table.add_column("SSID",     style="bold white", min_width=18)
    table.add_column("BSSID",    style="dim white",  width=17)
    table.add_column("Signal",   style="cyan",       width=10)
    table.add_column("dBm",      style="cyan",       width=5,  justify="right")
    table.add_column("Ch",       style="white",      width=4,  justify="center")
    table.add_column("Security",                     width=16)

    for i, net in enumerate(shown, 1):
        color, label = security_style(net["security"])
        table.add_row(
            str(i),
            net["ssid"],
            net["bssid"],
            rssi_bar(net["rssi"]),
            str(net["rssi"]),
            net["channel"],
            Text(label, style=color),
        )
    return table


def print_legend():
    """Print the security protocol colour legend."""
    console.print("  [green]WPA3 [secure][/]  Modern standard — most secure")
    console.print("  [yellow]WPA2 [ok]    [/]  Widely deployed — acceptable")
    console.print("  [red]WPA  [weak]  [/]  Deprecated — avoid if possible")
    console.print("  [red]WEP  [broken][/]  Broken encryption — trivially crackable")
    console.print("  [red]OPEN [none]  [/]  No encryption — all traffic visible")
    console.print()


def main():
    parser = argparse.ArgumentParser(
        description="WiFi network scanner with security risk assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py                  # one-shot scan
  python3 scanner.py -w 10            # refresh every 10 seconds
  python3 scanner.py -n 10 -w 5       # top 10, refresh every 5 s
  python3 scanner.py --no-legend      # skip legend
        """,
    )
    parser.add_argument("-w", "--watch", type=int, default=0,
                        help="Auto-refresh interval in seconds (0 = one shot)")
    parser.add_argument("-n", "--limit", type=int, default=None,
                        help="Show only the top N strongest networks")
    parser.add_argument("--no-legend", action="store_true",
                        help="Skip the security protocol colour legend")
    args = parser.parse_args()

    console.print()
    console.print("  [bold cyan]wifi-scanner[/]  |  github.com/RocmDaGr8")
    console.print("  [dim]─────────────────────────────────────────[/]")
    console.print("  [dim]Reads publicly broadcast beacon frames[/]")
    if args.watch:
        console.print(f"  [dim]Auto-refresh every {args.watch}s — Ctrl+C to stop[/]")
    console.print()

    first = True
    try:
        while True:
            networks = run_scan()

            if not networks:
                console.print("[yellow]No networks found. Is WiFi turned on?[/]")
            else:
                if not first and args.watch:
                    console.clear()
                    console.print()
                    console.print("  [bold cyan]wifi-scanner[/]  |  github.com/RocmDaGr8")
                    console.print("  [dim]─────────────────────────────────────────[/]")
                    console.print()

                table = build_table(networks, limit=args.limit)
                console.print(table)
                if not args.no_legend:
                    console.print()
                    print_legend()

            first = False
            if not args.watch:
                break

            console.print(f"  [dim]Next scan in {args.watch}s … (Ctrl+C to stop)[/]")
            time.sleep(args.watch)

    except KeyboardInterrupt:
        console.print("\n  [dim]Stopped.[/]")


if __name__ == "__main__":
    main()
