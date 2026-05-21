#!/usr/bin/env python3
"""
WiFi Network Scanner
Author: Roshim Bhatta
GitHub: github.com/RocmDaGr8

Reads publicly broadcast 802.11 beacon frames on macOS using the CoreWLAN
framework (via PyObjC) — the same data your Mac's WiFi menu reads.

Displays per-network:
  - SSID (network name)
  - BSSID (MAC address — requires Location permission, shown as N/A otherwise)
  - RSSI signal strength in dBm with visual bar
  - Channel number
  - Security type with colour-coded risk label

Legal note: SSIDs, channels, RSSI, and security type are continuously
broadcast by every access point as public 802.11 beacon frames. Reading
them requires no association, no credentials, and no decryption.

Requirements:
  pip3 install rich pyobjc-framework-CoreWLAN

Usage:
  python3 scanner.py             # one-shot scan
  python3 scanner.py -w 5        # auto-refresh every 5 seconds
  python3 scanner.py -n 15       # show top 15 networks only
  python3 scanner.py --no-legend # skip security legend
"""

import argparse
import time
import sys
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

# --- CoreWLAN security constants (CWSecurity enum) ---
# Maps integer security type to human-readable label
_SECURITY_NAMES = {
    0:  "OPEN",
    1:  "WEP",
    2:  "WPA Personal",
    3:  "WPA Personal Mixed",
    4:  "WPA2 Personal",
    5:  "WPA2 Personal",
    6:  "Dynamic WEP",
    7:  "WPA Enterprise",
    8:  "WPA Enterprise Mixed",
    9:  "WPA2 Enterprise",
    10: "WPA2 Enterprise",
    11: "WPA3 Personal",
    12: "WPA3 Enterprise",
    13: "WPA3 Transition",
    14: "OWE",
    15: "OWE Transition",
}

console = Console()


def run_scan():
    """
    Scan for nearby WiFi networks using the CoreWLAN framework.

    CoreWLAN is Apple's native WiFi framework. It passively collects beacon
    frames broadcast by nearby access points — no credentials or association
    required. Returns a deduplicated list sorted by RSSI (strongest first).
    """
    try:
        import CoreWLAN
    except ImportError:
        console.print("[bold red]Error:[/] CoreWLAN module not found.")
        console.print("  Install with: [cyan]pip3 install pyobjc-framework-CoreWLAN[/]")
        sys.exit(1)

    iface = CoreWLAN.CWWiFiClient.sharedWiFiClient().interface()
    if iface is None:
        console.print("[bold yellow]Warning:[/] No WiFi interface found.")
        return []

    nets, error = iface.scanForNetworksWithName_error_(None, None)
    if error:
        console.print(f"[bold yellow]Scan warning:[/] {error}")
    if not nets:
        return []

    raw = []
    for n in nets:
        ch       = n.wlanChannel()
        sec_int  = int(n.strongestSupportedSecurity())
        sec_str  = _SECURITY_NAMES.get(sec_int, f"Unknown ({sec_int})")
        raw.append({
            "ssid":     n.ssid() or "<hidden>",
            "bssid":    n.bssid() or "---",
            "rssi":     int(n.rssiValue()),
            "channel":  str(ch.channelNumber()) if ch else "?",
            "security": sec_str,
        })

    # Sort by RSSI, deduplicate on SSID (keep strongest)
    raw.sort(key=lambda x: x["rssi"], reverse=True)
    seen = {}
    for net in raw:
        if net["ssid"] not in seen:
            seen[net["ssid"]] = net
    return list(seen.values())


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
    """Return (rich_colour, short_label) based on security string."""
    s = security.upper()
    if "WPA3" in s:
        return "green",  "WPA3"
    elif "WPA2" in s:
        return "yellow", "WPA2"
    elif "OWE" in s:
        return "yellow", "OWE"
    elif "WPA" in s:
        return "red",    "WPA"
    elif "WEP" in s:
        return "red",    "WEP"
    elif s in ("OPEN", "NONE"):
        return "red",    "OPEN"
    else:
        return "dim",    security[:8]


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
    table.add_column("#",       style="dim",        width=3,  justify="right")
    table.add_column("SSID",    style="bold white", min_width=20)
    table.add_column("BSSID",   style="dim white",  width=17)
    table.add_column("Signal",  style="cyan",       width=10)
    table.add_column("dBm",     style="cyan",       width=5,  justify="right")
    table.add_column("Ch",      style="white",      width=4,  justify="center")
    table.add_column("Security",                    width=12)

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
    console.print("  [green]WPA3[/]  Modern standard — SAE handshake, most secure")
    console.print("  [yellow]WPA2[/]  Widely deployed — acceptable with strong passphrase")
    console.print("  [yellow]OWE [/]  Opportunistic encryption on open networks")
    console.print("  [red]WPA [/]  Deprecated TKIP — practical attacks exist")
    console.print("  [red]WEP [/]  Broken encryption — trivially crackable")
    console.print("  [red]OPEN[/]  No encryption — all traffic visible")
    console.print()
    console.print("  [dim]BSSID shown as --- if macOS Location permission not granted[/]")
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
                        help="Auto-refresh every N seconds (0 = one shot)")
    parser.add_argument("-n", "--limit", type=int, default=None,
                        help="Show top N networks by signal strength")
    parser.add_argument("--no-legend", action="store_true",
                        help="Skip the security protocol legend")
    args = parser.parse_args()

    console.print()
    console.print("  [bold cyan]wifi-scanner[/]  |  github.com/RocmDaGr8")
    console.print("  [dim]─────────────────────────────────────────[/]")
    console.print("  [dim]Reads publicly broadcast beacon frames via CoreWLAN[/]")
    if args.watch:
        console.print(f"  [dim]Auto-refresh every {args.watch}s — Ctrl+C to stop[/]")
    console.print()

    first = True
    try:
        while True:
            networks = run_scan()
            if not networks:
                console.print("[yellow]No networks found. Is WiFi on?[/]")
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
