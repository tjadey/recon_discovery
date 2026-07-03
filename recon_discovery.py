#!/usr/bin/env python3
"""
recon_discovery.py - Non-disruptive internal host & service discovery.

AUTHORIZED PENETRATION TESTING USE ONLY.
Run only against targets covered by a signed scope / rules of engagement.

Design goals (safety-first, "do no harm"):
  * Two staged phases: host discovery -> service discovery on LIVE hosts only.
  * Conservative timing and a hard packet-rate cap so fragile / legacy / OT
    hosts are not overwhelmed.
  * Version detection (-sV) is OFF by default because service probes can crash
    brittle stacks (printers, SCADA, old appliances). It is opt-in and warns.
  * No default NSE scripts (nmap --script) are ever run.
  * Honors an exclude file for out-of-scope or known-fragile hosts.
  * A --fragile mode adds a per-probe scan-delay and lowers the rate further.
  * Everything is logged (exact commands, timestamps, results) as JSON + CSV +
    a human-readable log, suitable for a report appendix / ROE evidence trail.

Engine: wraps nmap when present (preferred). Falls back to a rate-limited
pure-python TCP connect scan if nmap is unavailable.
"""

import argparse
import csv
import datetime
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Safe defaults. Tune these to the engagement, but keep them conservative.
# ---------------------------------------------------------------------------
SAFE_DEFAULTS = {
    "timing": "T2",          # polite; avoid T4/T5 on production networks
    "max_rate": 100,         # packets/sec ceiling (nmap --max-rate)
    "max_retries": 1,        # don't hammer non-responsive ports
    "host_timeout": "15m",   # give up on a host rather than stall forever
    "fragile_rate": 25,      # rate used in --fragile mode
    "fragile_scan_delay": "50ms",
}

# A curated "safe" TCP port set for internal AD/Windows environments.
# Focused on discovery value, avoids known-fragile probe targets by default.
DEFAULT_TCP_PORTS = (
    "21,22,23,25,53,80,88,110,135,139,143,389,443,445,464,465,514,"
    "587,593,636,993,995,1433,1521,2049,3268,3269,3306,3389,5432,"
    "5985,5986,8000,8080,8443,9389,10443"
)


def ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def slug() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


class Logger:
    """Tees to stdout and a run log so every action is captured for reporting."""

    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, "a", encoding="utf-8")

    def log(self, msg: str):
        line = f"[{ts()}] {msg}"
        print(line)
        self.fh.write(line + "\n")
        self.fh.flush()

    def close(self):
        self.fh.close()


# ---------------------------------------------------------------------------
# nmap-backed scanning (preferred engine)
# ---------------------------------------------------------------------------
def run_cmd(cmd, log: Logger):
    """Run a command, record it verbatim, return (rc, stdout, stderr)."""
    log.log("EXEC: " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)


def nmap_host_discovery(targets, exclude_file, log: Logger, outbase: str):
    """Stage 1: find live hosts. -sn = no port scan, just discovery."""
    xml = f"{outbase}_hosts.xml"
    cmd = ["nmap", "-sn", "-PR", "-PE", "-PS445,3389,88", "-PA80",
           "-n", "--stats-every", "30s", "-oX", xml]
    if exclude_file:
        cmd += ["--excludefile", exclude_file]
    cmd += targets
    rc, out, err = run_cmd(cmd, log)
    if rc != 0:
        log.log(f"WARN: host discovery returned rc={rc}: {err.strip()}")
    live = _parse_live_hosts_xml(xml)
    log.log(f"Host discovery complete: {len(live)} live host(s).")
    return live


def nmap_service_discovery(hosts, ports, args, log: Logger, outbase: str):
    """Stage 2: scan services on LIVE hosts only, with rate/timing caps."""
    if not hosts:
        log.log("No live hosts to service-scan. Skipping stage 2.")
        return {}

    live_file = f"{outbase}_live.txt"
    with open(live_file, "w", encoding="utf-8") as f:
        f.write("\n".join(hosts) + "\n")

    rate = SAFE_DEFAULTS["fragile_rate"] if args.fragile else args.max_rate
    xml = f"{outbase}_services.xml"

    # -sS (SYN) is lighter than a full connect; falls back to -sT if not root.
    scan_type = "-sS" if os.geteuid() == 0 else "-sT"
    if scan_type == "-sT":
        log.log("Not root: using TCP connect scan (-sT) instead of SYN (-sS).")

    cmd = ["nmap", scan_type, "-Pn", "-n",
           f"-{args.timing}",
           "--max-rate", str(rate),
           "--max-retries", str(args.max_retries),
           "--host-timeout", args.host_timeout,
           "-p", ports,
           "--stats-every", "30s",
           "-iL", live_file,
           "-oX", xml, "-oN", f"{outbase}_services.txt"]

    if args.fragile:
        cmd += ["--scan-delay", SAFE_DEFAULTS["fragile_scan_delay"]]

    if args.version:
        log.log("WARNING: version detection (-sV) enabled. Service probes can "
                "disrupt fragile/legacy/OT services. Intensity capped at 2.")
        cmd += ["-sV", "--version-intensity", "2"]

    if args.exclude_file:
        cmd += ["--excludefile", args.exclude_file]

    rc, out, err = run_cmd(cmd, log)
    if rc != 0:
        log.log(f"WARN: service discovery returned rc={rc}: {err.strip()}")
    return _parse_services_xml(xml)


def _parse_live_hosts_xml(path):
    import xml.etree.ElementTree as ET
    hosts = []
    if not os.path.exists(path):
        return hosts
    try:
        root = ET.parse(path).getroot()
        for h in root.findall("host"):
            st = h.find("status")
            if st is not None and st.get("state") == "up":
                addr = h.find("address")
                if addr is not None:
                    hosts.append(addr.get("addr"))
    except ET.ParseError:
        pass
    return hosts


def _parse_services_xml(path):
    import xml.etree.ElementTree as ET
    results = {}
    if not os.path.exists(path):
        return results
    try:
        root = ET.parse(path).getroot()
        for h in root.findall("host"):
            addr_el = h.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            open_ports = []
            ports_el = h.find("ports")
            if ports_el is not None:
                for p in ports_el.findall("port"):
                    state = p.find("state")
                    if state is not None and state.get("state") == "open":
                        svc = p.find("service")
                        open_ports.append({
                            "port": int(p.get("portid")),
                            "proto": p.get("protocol"),
                            "service": (svc.get("name") if svc is not None else ""),
                            "product": (svc.get("product", "") if svc is not None else ""),
                            "version": (svc.get("version", "") if svc is not None else ""),
                        })
            if open_ports:
                results[ip] = open_ports
    except ET.ParseError:
        pass
    return results


# ---------------------------------------------------------------------------
# Pure-python fallback (rate-limited TCP connect scan) - used only if no nmap
# ---------------------------------------------------------------------------
def python_fallback(targets, ports, args, log: Logger):
    log.log("nmap not found. Using rate-limited pure-python connect scan.")
    log.log("NOTE: fallback has no host-discovery stage; it probes each target "
            "directly. Keep target lists tight.")

    ip_list = _expand_targets(targets, args.exclude_file, log)
    port_list = _expand_ports(ports)
    rate = SAFE_DEFAULTS["fragile_rate"] if args.fragile else args.max_rate
    delay = 1.0 / max(rate, 1)  # simple pacing between connections

    results = {}
    for ip in ip_list:
        open_ports = []
        for port in port_list:
            if _tcp_connect(ip, port, timeout=1.5):
                svc = _guess_service(port)
                open_ports.append({"port": port, "proto": "tcp",
                                   "service": svc, "product": "", "version": ""})
                log.log(f"OPEN {ip}:{port} ({svc})")
            time.sleep(delay)
        if open_ports:
            results[ip] = open_ports
    return ip_list, results


def _tcp_connect(ip, port, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def _expand_targets(targets, exclude_file, log):
    excluded = set()
    if exclude_file and os.path.exists(exclude_file):
        with open(exclude_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    excluded.add(line)
    ips = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            for ip in net.hosts():
                sip = str(ip)
                if sip not in excluded:
                    ips.append(sip)
        except ValueError:
            if t not in excluded:
                ips.append(t)
    return ips


def _expand_ports(ports):
    out = []
    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


_SVC_MAP = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 88: "kerberos", 110: "pop3", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
            445: "microsoft-ds", 464: "kpasswd", 636: "ldaps",
            1433: "ms-sql", 3268: "globalcat-ldap", 3269: "globalcat-ldaps",
            3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
            5985: "winrm-http", 5986: "winrm-https", 9389: "adws"}


def _guess_service(port):
    return _SVC_MAP.get(port, "unknown")


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------
def write_outputs(live_hosts, services, outbase, args, log):
    manifest = {
        "scan_metadata": {
            "timestamp": ts(),
            "targets": args.targets,
            "exclude_file": args.exclude_file,
            "ports": args.ports,
            "timing": args.timing,
            "max_rate_pps": (SAFE_DEFAULTS["fragile_rate"]
                             if args.fragile else args.max_rate),
            "fragile_mode": args.fragile,
            "version_detection": args.version,
            "engine": "nmap" if shutil.which("nmap") else "python-fallback",
        },
        "live_hosts": live_hosts,
        "services": services,
    }
    with open(f"{outbase}.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    with open(f"{outbase}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "proto", "service", "product", "version"])
        for ip, ports in services.items():
            for p in ports:
                w.writerow([ip, p["port"], p["proto"], p["service"],
                            p.get("product", ""), p.get("version", "")])

    log.log(f"Results written: {outbase}.json / {outbase}.csv")
    log.log(f"Summary: {len(live_hosts)} live host(s), "
            f"{sum(len(v) for v in services.values())} open service(s).")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Non-disruptive internal host & service discovery "
                    "(authorized pentest use only).")
    ap.add_argument("targets", nargs="+",
                    help="CIDR(s)/IP(s), e.g. 10.10.10.0/24 10.10.20.5")
    ap.add_argument("-e", "--exclude-file",
                    help="File of out-of-scope / fragile hosts to skip.")
    ap.add_argument("-p", "--ports", default=DEFAULT_TCP_PORTS,
                    help="TCP ports (default: curated AD/Windows set).")
    ap.add_argument("-t", "--timing", default=SAFE_DEFAULTS["timing"],
                    choices=["T0", "T1", "T2", "T3"],
                    help="nmap timing template (T4/T5 intentionally disallowed).")
    ap.add_argument("--max-rate", type=int, default=SAFE_DEFAULTS["max_rate"],
                    help="Packets/sec ceiling.")
    ap.add_argument("--max-retries", type=int,
                    default=SAFE_DEFAULTS["max_retries"])
    ap.add_argument("--host-timeout", default=SAFE_DEFAULTS["host_timeout"])
    ap.add_argument("--fragile", action="store_true",
                    help="Extra-gentle mode for OT/legacy: adds scan-delay, "
                         "lowers rate.")
    ap.add_argument("--version", action="store_true",
                    help="Enable capped -sV version detection (can disrupt "
                         "fragile services; off by default).")
    ap.add_argument("-o", "--outdir", default="recon_output")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    outbase = os.path.join(args.outdir, f"recon_{slug()}")
    log = Logger(outbase + ".log")

    log.log("=== Non-disruptive recon started ===")
    log.log(f"Targets: {args.targets} | Ports: {args.ports}")
    log.log(f"Timing: {args.timing} | Max-rate: "
            f"{SAFE_DEFAULTS['fragile_rate'] if args.fragile else args.max_rate} pps"
            f" | Fragile: {args.fragile} | Version-detect: {args.version}")
    if args.exclude_file:
        log.log(f"Exclude file: {args.exclude_file}")

    try:
        if shutil.which("nmap"):
            live = nmap_host_discovery(args.targets, args.exclude_file, log, outbase)
            services = nmap_service_discovery(live, args.ports, args, log, outbase)
        else:
            live, services = python_fallback(args.targets, args.ports, args, log)
        write_outputs(live, services, outbase, args, log)
    except KeyboardInterrupt:
        log.log("Interrupted by user. Partial results may be in output dir.")
    finally:
        log.log("=== Recon finished ===")
        log.close()


if __name__ == "__main__":
    main()
