#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

SOURCES = ["crtsh", "subfinder"]

def normalize_host(host, domain):
    host = host.strip().lower()
    if not host:
        return None
    if host.startswith("*."):
        host = host[2:]
    host = host.rstrip(".")
    domain = domain.strip().lower().rstrip(".")
    if host == domain or host.endswith("." + domain):
        return host
    return None

def normalize_hosts(hosts, domain):
    out = set()
    for host in hosts:
        h = normalize_host(host, domain)
        if h:
            out.add(h)
    return sorted(out)

def ensure_workspace(workspace, domain):
    paths = {
        "raw": workspace / "raw",
        "normalized": workspace / "normalized",
        "delta": workspace / "delta",
        "inventory": workspace / "inventory",
        "notes": workspace / "notes",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)

    inv = paths["inventory"] / "all-hosts.txt"
    state = paths["inventory"] / "state.json"

    if not inv.exists():
        inv.write_text("", encoding="utf-8")

    if not state.exists():
        state.write_text(json.dumps({"domain": domain, "sources_applied": []}, indent=2) + "\n", encoding="utf-8")
    else:
        current = json.loads(state.read_text(encoding="utf-8"))
        if current.get("domain") and current["domain"] != domain:
            raise SystemExit(f"[!] Workspace belongs to {current['domain']}, not {domain}")

    paths["inventory_file"] = inv
    paths["state_file"] = state
    return paths

def read_lines(path):
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]

def write_lines(path, lines):
    data = sorted(set(lines))
    path.write_text(("\n".join(data) + "\n") if data else "", encoding="utf-8")

def apply_source(source, hosts, paths):
    write_lines(paths["normalized"] / f"{source}.txt", hosts)

    before = set(read_lines(paths["inventory_file"]))
    new_hosts = sorted(set(hosts) - before)
    write_lines(paths["delta"] / f"{source}-new.txt", new_hosts)

    after = before | set(hosts)
    write_lines(paths["inventory_file"], after)

    state = json.loads(paths["state_file"].read_text(encoding="utf-8"))
    applied = state.setdefault("sources_applied", [])
    if source not in applied:
        applied.append(source)
    paths["state_file"].write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    return len(new_hosts), len(after)

def fetch_crtsh(domain, paths, timeout):
    q = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "bb-recon/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()

    (paths["raw"] / "crtsh.json").write_bytes(raw)
    data = json.loads(raw.decode("utf-8"))

    hosts = []
    for entry in data:
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if isinstance(value, str):
                hosts.extend(value.splitlines())

    return normalize_hosts(hosts, domain)

def run_subfinder(domain, paths, timeout):
    if not shutil.which("subfinder"):
        raise RuntimeError("subfinder not found in PATH")

    cmd = ["subfinder", "-d", domain, "-silent", "-all"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    (paths["raw"] / "subfinder.txt").write_text(result.stdout, encoding="utf-8")
    (paths["raw"] / "subfinder.stderr.txt").write_text(result.stderr, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(f"subfinder exited with code {result.returncode}")

    return normalize_hosts(result.stdout.splitlines(), domain)

def status(paths):
    state = json.loads(paths["state_file"].read_text(encoding="utf-8"))
    print(f"\nTarget: {state.get('domain', '?')}")
    print("-" * 52)
    for source in SOURCES:
        n = paths["normalized"] / f"{source}.txt"
        d = paths["delta"] / f"{source}-new.txt"
        if n.exists():
            print(f"{source:<12} normalized={len(read_lines(n)):<6} new={len(read_lines(d))}")
        else:
            print(f"{source:<12} not run")
    print("-" * 52)
    print(f"{'inventory':<12} total={len(read_lines(paths['inventory_file']))}\n")

def main():
    parser = argparse.ArgumentParser(description="Passive bug bounty recon: RAW -> NORMALIZED -> DELTA -> INVENTORY")
    parser.add_argument("domain")
    parser.add_argument("-w", "--workspace", type=Path)
    parser.add_argument("--timeout", type=int, default=300)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init")
    runp = sub.add_parser("run")
    runp.add_argument("--sources", nargs="+", choices=SOURCES, default=SOURCES)
    sub.add_parser("status")
    newp = sub.add_parser("new")
    newp.add_argument("source", choices=SOURCES)

    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    workspace = args.workspace.expanduser() if args.workspace else (Path.home() / "recon" / domain)
    paths = ensure_workspace(workspace, domain)

    if args.command == "init":
        print(f"[+] Workspace ready: {workspace}")
        status(paths)
        return

    if args.command == "status":
        status(paths)
        return

    if args.command == "new":
        for line in read_lines(paths["delta"] / f"{args.source}-new.txt"):
            print(line)
        return

    runners = {
        "crtsh": fetch_crtsh,
        "subfinder": run_subfinder,
    }

    for source in args.sources:
        try:
            print(f"[*] Running {source}...")
            hosts = runners[source](domain, paths, args.timeout)
            new_count, total = apply_source(source, hosts, paths)
            print(f"[+] {source}: normalized={len(hosts)} new={new_count} inventory={total}")
        except Exception as e:
            print(f"[!] {source}: {e}", file=sys.stderr)

    status(paths)

if __name__ == "__main__":
    main()
