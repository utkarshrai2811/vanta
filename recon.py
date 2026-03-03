#!/usr/bin/env python3
"""
Phase 1: Network Recon and Topology Mapping
Autonomous Red Team Agent
"""

import json
import sys
import argparse
import ipaddress
from datetime import datetime

import nmap
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.text import Text

console = Console()

RISKY_PORTS = {
    21: ("FTP", "red"), 22: ("SSH", "yellow"), 23: ("Telnet", "red"),
    25: ("SMTP", "yellow"), 53: ("DNS", "cyan"), 80: ("HTTP", "green"),
    110: ("POP3", "yellow"), 135: ("MSRPC", "red"), 139: ("NetBIOS", "red"),
    143: ("IMAP", "yellow"), 443: ("HTTPS", "green"), 445: ("SMB", "red"),
    3306: ("MySQL", "red"), 3389: ("RDP", "red"), 5432: ("PostgreSQL", "red"),
    5900: ("VNC", "red"), 6379: ("Redis", "red"), 8080: ("HTTP-Alt", "yellow"),
    8443: ("HTTPS-Alt", "yellow"), 27017: ("MongoDB", "red"),
}


def get_local_subnet():
    import subprocess
    try:
        result = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) > 3 and not parts[1].startswith("lo"):
                cidr = parts[3]
                network = ipaddress.IPv4Interface(cidr).network
                return str(network)
    except Exception:
        pass
    return "192.168.1.0/24"


def run_scan(target, scan_type):
    nm = nmap.PortScanner()
    scan_args = {
        "quick":    "-T4 -F --open -O --osscan-guess",
        "standard": "-T4 -sV -O --osscan-guess -p 1-1024 --open",
        "deep":     "-T3 -sV -O --osscan-guess -p- --open --script=banner",
    }
    args = scan_args.get(scan_type, scan_args["standard"])
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), BarColumn(), console=console, transient=True) as progress:
        progress.add_task(f"Scanning {target} [{scan_type} mode]...", total=None)
        nm.scan(hosts=target, arguments=args)
    return nm


def parse_scan(nm):
    scan_data = {
        "meta": {
            "timestamp": datetime.now().isoformat(),
            "scan_stats": nm.scanstats(),
            "command": nm.command_line(),
        },
        "hosts": {}
    }
    for host in nm.all_hosts():
        host_info = nm[host]
        os_matches = []
        if "osmatch" in host_info:
            for match in host_info["osmatch"][:3]:
                os_matches.append({
                    "name": match.get("name", "Unknown"),
                    "accuracy": match.get("accuracy", "0"),
                    "osfamily": match.get("osclass", [{}])[0].get("osfamily", "Unknown") if match.get("osclass") else "Unknown",
                })
        ports = {}
        for proto in host_info.all_protocols():
            for port in host_info[proto].keys():
                p = host_info[proto][port]
                ports[str(port)] = {
                    "protocol": proto,
                    "state": p.get("state", "unknown"),
                    "service": p.get("name", "unknown"),
                    "version": p.get("version", ""),
                    "product": p.get("product", ""),
                    "extrainfo": p.get("extrainfo", ""),
                    "risk": RISKY_PORTS.get(port, ("unknown", "white"))[1],
                }
        scan_data["hosts"][host] = {
            "ip": host,
            "hostname": host_info.hostname() or host,
            "state": host_info.state(),
            "os_matches": os_matches,
            "os_best_guess": os_matches[0]["name"] if os_matches else "Unknown",
            "open_ports": ports,
            "port_count": len(ports),
        }
    return scan_data


def build_topology(scan_data, output_path="topology.png"):
    G = nx.Graph()
    G.add_node("GATEWAY", node_type="gateway")
    for ip, host in scan_data["hosts"].items():
        has_critical = any(p["risk"] == "red" for p in host["open_ports"].values())
        has_warning  = any(p["risk"] == "yellow" for p in host["open_ports"].values())
        color = "#e74c3c" if has_critical else ("#f39c12" if has_warning else "#2ecc71")
        short_os = host["os_best_guess"].split(" ")[0] if host["os_best_guess"] != "Unknown" else "?"
        G.add_node(ip, node_type="host", color=color, label=f"{ip}\n{short_os}\n{host['port_count']} ports")
        G.add_edge("GATEWAY", ip)

    pos = nx.spring_layout(G, k=2.5, seed=42)
    fig, ax = plt.subplots(figsize=(16, 10))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#4a4a6a", width=1.5, alpha=0.7, style="dashed")
    gw = [n for n in G.nodes if G.nodes[n].get("node_type") == "gateway"]
    nx.draw_networkx_nodes(G, pos, nodelist=gw, ax=ax, node_color="#3498db", node_size=1800, node_shape="s")
    hn = [n for n in G.nodes if G.nodes[n].get("node_type") == "host"]
    hc = [G.nodes[n].get("color", "#2ecc71") for n in hn]
    nx.draw_networkx_nodes(G, pos, nodelist=hn, ax=ax, node_color=hc, node_size=1200, alpha=0.9)

    labels = {"GATEWAY": "GATEWAY\n[Router]"}
    for ip in scan_data["hosts"]:
        labels[ip] = G.nodes[ip].get("label", ip)
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=7, font_color="white", font_weight="bold")

    legend_elements = [
        mpatches.Patch(facecolor="#e74c3c", label="High Risk"),
        mpatches.Patch(facecolor="#f39c12", label="Medium Risk"),
        mpatches.Patch(facecolor="#2ecc71", label="Low Risk"),
        mpatches.Patch(facecolor="#3498db", label="Gateway"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", facecolor="#1a1a2e", edgecolor="#4a4a6a", labelcolor="white", fontsize=9)
    ax.set_title(f"Network Topology  |  {len(scan_data['hosts'])} hosts  |  {scan_data['meta']['timestamp'][:19]}", color="white", fontsize=13, fontweight="bold", pad=15)
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return output_path


def print_summary(scan_data):
    console.print()
    console.print(Panel("[bold cyan]Phase 1: Recon Complete[/bold cyan]", subtitle=f"[dim]{scan_data['meta']['timestamp'][:19]}[/dim]", border_style="cyan"))
    table = Table(title="Discovered Hosts", show_header=True, header_style="bold magenta", border_style="dim", show_lines=True)
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="white")
    table.add_column("OS Guess", style="yellow")
    table.add_column("Open Ports", justify="center", style="green")
    table.add_column("Risk Ports", style="red")
    for ip, host in scan_data["hosts"].items():
        risky = [
            f"[red]{p}[/red]" if host["open_ports"][p]["risk"] == "red" else f"[yellow]{p}[/yellow]"
            for p in host["open_ports"] if host["open_ports"][p]["risk"] in ("red", "yellow")
        ]
        table.add_row(
            ip,
            host["hostname"] if host["hostname"] != ip else "[dim]n/a[/dim]",
            host["os_best_guess"][:40] if host["os_best_guess"] != "Unknown" else "[dim]Unknown[/dim]",
            str(host["port_count"]),
            ", ".join(risky[:6]) or "[green]none[/green]",
        )
    console.print(table)
    all_svcs = {}
    for host in scan_data["hosts"].values():
        for pdata in host["open_ports"].values():
            svc = pdata["service"]
            all_svcs[svc] = all_svcs.get(svc, 0) + 1
    if all_svcs:
        svc_table = Table(title="Service Summary", border_style="dim")
        svc_table.add_column("Service", style="cyan")
        svc_table.add_column("Count", justify="right")
        for svc, count in sorted(all_svcs.items(), key=lambda x: -x[1])[:10]:
            svc_table.add_row(svc, str(count))
        console.print(svc_table)


def main():
    parser = argparse.ArgumentParser(description="RedTeam Agent Phase 1: Network Recon")
    parser.add_argument("--target", "-t", default=None)
    parser.add_argument("--mode", "-m", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--output", "-o", default="recon_state.json")
    parser.add_argument("--topology", "-tp", default="topology.png")
    parser.add_argument("--no-map", action="store_true")
    args = parser.parse_args()

    console.print(Panel(Text("Autonomous Red Team Agent\nPhase 1: Network Recon & Topology Mapping", justify="center", style="bold cyan"), border_style="cyan"))

    target = args.target or get_local_subnet()
    console.print(f"\n[bold]Target:[/bold] [cyan]{target}[/cyan]")
    console.print(f"[bold]Mode:[/bold]   [yellow]{args.mode}[/yellow]")
    console.print(f"[bold]Output:[/bold] [dim]{args.output}[/dim]\n")

    nm = run_scan(target, args.mode)
    scan_data = parse_scan(nm)

    if not scan_data["hosts"]:
        console.print("[bold red]No hosts discovered. Try a different target or scan mode.[/bold red]")
        sys.exit(1)

    console.print(f"[bold green]Discovered {len(scan_data['hosts'])} host(s)[/bold green]")

    with open(args.output, "w") as f:
        json.dump(scan_data, f, indent=2)
    console.print(f"[dim]Saved state to[/dim] [bold]{args.output}[/bold]")

    print_summary(scan_data)

    if not args.no_map:
        console.print(f"\n[bold cyan]Generating topology map...[/bold cyan]")
        build_topology(scan_data, args.topology)
        console.print(f"[bold green]Topology saved to[/bold green] [bold]{args.topology}[/bold]")

    console.print(f"\n[bold green]Phase 1 complete.[/bold green] Pass [cyan]{args.output}[/cyan] to Phase 2.\n")


if __name__ == "__main__":
    main()
