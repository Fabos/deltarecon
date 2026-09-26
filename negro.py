#!/usr/bin/env python3
"""
Negro Recon v0.2
"Olfatea donde otros no miran."

Passive-first Bug Bounty asset discovery orchestrator.

Automated sources in this version:
  1. crt.sh
  2. Subfinder

Planned sources are intentionally NOT automated yet. The rule is:
learn manually -> understand the value -> automate.

Pipeline:
  RAW -> NORMALIZED -> DELTA -> INVENTORY -> PROVENANCE
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

VERSION = "0.2.0"
SOURCE_ORDER = ["crtsh", "subfinder"]

SOURCE_INFO = {
    "crtsh": ("AUTOMATIZADA", "Certificate Transparency", "Subdominios observados en certificados TLS públicos."),
    "subfinder": ("AUTOMATIZADA", "Subfinder passive", "Agrega múltiples fuentes pasivas de descubrimiento."),
    "amass": ("APRENDER MANUALMENTE", "Amass passive", "OSINT/DNS pasivo y correlación de fuentes."),
    "gau": ("APRENDER MANUALMENTE", "GAU", "URLs históricas; pivote para hosts y endpoints olvidados."),
    "wayback": ("APRENDER MANUALMENTE", "Wayback / CDX", "Arqueología histórica de hosts, rutas y parámetros."),
    "urlscan": ("APRENDER MANUALMENTE", "URLScan", "Hosts vistos en navegaciones públicas, JS y recursos externos."),
    "passive_dns": ("APRENDER MANUALMENTE", "Passive DNS", "Relaciones DNS históricas que pueden no aparecer en CT."),
    "tls_san": ("APRENDER MANUALMENTE", "TLS SAN discovery", "Descubrir hosts hermanos desde certificados de activos conocidos."),
    "github": ("APRENDER MANUALMENTE", "GitHub / code search", "Dominios, APIs, buckets y nombres internos desde código público."),
}

CONFIG_PATH = Path.home() / ".config" / "negro" / "config.json"


def banner() -> None:
    print(r"""
 _   _                      
| \ | | ___  __ _ _ __ ___ 
|  \| |/ _ \/ _` | '__/ _ \
| |\  |  __/ (_| | | | (_) |
|_| \_|\___|\__, |_|  \___/ 
            |___/            
""")
    print(f"Negro Recon v{VERSION} — olfatea donde otros no miran.\n")


def normalize_host(host: str, domain: str) -> str | None:
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


def normalize_hosts(hosts: Iterable[str], domain: str) -> list[str]:
    clean = set()
    for host in hosts:
        value = normalize_host(host, domain)
        if value:
            clean.add(value)
    return sorted(clean)


def write_lines(path: Path, lines: Iterable[str]) -> None:
    values = sorted(set(lines))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(("\n".join(values) + "\n") if values else "", encoding="utf-8")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def workspace_paths(workspace: Path) -> dict[str, Path]:
    return {
        "root": workspace,
        "raw": workspace / "raw",
        "normalized": workspace / "normalized",
        "delta": workspace / "delta",
        "inventory": workspace / "inventory",
        "notes": workspace / "notes",
        "inventory_file": workspace / "inventory" / "all-hosts.txt",
        "provenance_file": workspace / "inventory" / "provenance.json",
        "state_file": workspace / "inventory" / "state.json",
    }


def ensure_workspace(workspace: Path, domain: str) -> dict[str, Path]:
    paths = workspace_paths(workspace)
    for key in ("raw", "normalized", "delta", "inventory", "notes"):
        paths[key].mkdir(parents=True, exist_ok=True)

    if not paths["state_file"].exists():
        paths["state_file"].write_text(
            json.dumps({"domain": domain, "version": VERSION}, indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        state = json.loads(paths["state_file"].read_text(encoding="utf-8"))
        existing_domain = state.get("domain")
        if existing_domain and existing_domain != domain:
            raise SystemExit(f"[!] Este workspace pertenece a {existing_domain}, no a {domain}")

    if not paths["inventory_file"].exists():
        paths["inventory_file"].write_text("", encoding="utf-8")
    if not paths["provenance_file"].exists():
        paths["provenance_file"].write_text("{}\n", encoding="utf-8")
    return paths


def rebuild_inventory(paths: dict[str, Path]) -> tuple[int, dict[str, int]]:
    """Rebuild del inventario usando un orden fijo de fuentes.

    Así un rerun de crt.sh no borra ni distorsiona el delta histórico lógico.
    """
    source_sets = {
        source: set(read_lines(paths["normalized"] / f"{source}.txt"))
        for source in SOURCE_ORDER
    }

    seen: set[str] = set()
    first_seen_counts: dict[str, int] = {}

    for source in SOURCE_ORDER:
        current = source_sets[source]
        new_hosts = sorted(current - seen)
        write_lines(paths["delta"] / f"{source}-new.txt", new_hosts)
        first_seen_counts[source] = len(new_hosts)
        seen |= current

    provenance = {}
    for host in sorted(seen):
        sources = [source for source in SOURCE_ORDER if host in source_sets[source]]
        provenance[host] = {
            "first_source": sources[0] if sources else None,
            "sources": sources,
        }

    write_lines(paths["inventory_file"], seen)
    paths["provenance_file"].write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return len(seen), first_seen_counts


def fetch_crtsh(domain: str, paths: dict[str, Path], timeout: int) -> list[str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": f"Negro-Recon/{VERSION}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()

    (paths["raw"] / "crtsh.json").write_bytes(raw)
    data = json.loads(raw.decode("utf-8"))
    hosts: list[str] = []
    for entry in data:
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if isinstance(value, str):
                hosts.extend(value.splitlines())
    return normalize_hosts(hosts, domain)


def run_subfinder(domain: str, paths: dict[str, Path], timeout: int) -> list[str]:
    if not shutil.which("subfinder"):
        raise RuntimeError("Subfinder no está instalado o no está disponible en PATH.")

    command = ["subfinder", "-d", domain, "-silent", "-all"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)

    (paths["raw"] / "subfinder.txt").write_text(result.stdout, encoding="utf-8")
    (paths["raw"] / "subfinder.stderr.txt").write_text(result.stderr, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(
            f"Subfinder terminó con código {result.returncode}. Revisa raw/subfinder.stderr.txt"
        )
    return normalize_hosts(result.stdout.splitlines(), domain)


def collect_source(source: str, domain: str, paths: dict[str, Path], timeout: int) -> None:
    if source == "crtsh":
        print("[*] Consultando crt.sh...")
        hosts = fetch_crtsh(domain, paths, timeout)
    elif source == "subfinder":
        print("[*] Ejecutando Subfinder passive...")
        hosts = run_subfinder(domain, paths, timeout)
    else:
        raise RuntimeError(f"Fuente no automatizada todavía: {source}")

    write_lines(paths["normalized"] / f"{source}.txt", hosts)
    total, counts = rebuild_inventory(paths)
    print(f"[+] {source}: {len(hosts)} hosts normalizados")
    print(f"[+] Delta {source}: {counts.get(source, 0)}")
    print(f"[+] Inventario total: {total}")


def print_status(domain: str, paths: dict[str, Path]) -> None:
    print(f"\nTarget:    {domain}")
    print(f"Workspace: {paths['root']}")
    print("-" * 64)
    for source in SOURCE_ORDER:
        normalized = paths["normalized"] / f"{source}.txt"
        delta = paths["delta"] / f"{source}-new.txt"
        if normalized.exists():
            print(
                f"{source:<12} encontrados={len(read_lines(normalized)):<6} "
                f"nuevos={len(read_lines(delta))}"
            )
        else:
            print(f"{source:<12} pendiente")
    print("-" * 64)
    print(f"{'inventory':<12} total={len(read_lines(paths['inventory_file']))}\n")


def show_new(paths: dict[str, Path], source: str) -> None:
    path = paths["delta"] / f"{source}-new.txt"
    values = read_lines(path)
    print(f"\n{source}: {len(values)} hosts nuevos\n")
    for value in values:
        print(value)


def show_inventory(paths: dict[str, Path], limit: int | None = None) -> None:
    values = read_lines(paths["inventory_file"])
    print(f"\nInventario: {len(values)} hosts\n")
    if limit is not None:
        values = values[:limit]
    for value in values:
        print(value)


def search_inventory(paths: dict[str, Path], pattern: str) -> None:
    pattern = pattern.lower()
    matches = [host for host in read_lines(paths["inventory_file"]) if pattern in host.lower()]
    print(f"\nCoincidencias: {len(matches)}\n")
    for host in matches:
        print(host)


def show_sources() -> None:
    print("\nFuentes / técnicas de enumeración\n")
    for name, (status, label, purpose) in SOURCE_INFO.items():
        print(f"[{status:<20}] {name:<12} — {label}")
        print(f"  {purpose}")
    print()


def config_load() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def config_save(domain: str, workspace: Path) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        json.dumps({"domain": domain, "workspace": str(workspace)}, indent=2) + "\n",
        encoding="utf-8",
    )


def default_workspace(domain: str) -> Path:
    return Path.home() / "recon" / domain


def choose_target(force_new: bool = False) -> tuple[str, Path]:
    current = {} if force_new else config_load()
    if current.get("domain") and current.get("workspace"):
        answer = input(
            f"Usar target anterior {current['domain']} ({current['workspace']})? [Y/n]: "
        ).strip().lower()
        if answer in ("", "y", "yes", "s", "si", "sí"):
            return current["domain"], Path(current["workspace"]).expanduser()

    domain = input("Dominio objetivo (ej. mercadolibre.com): ").strip().lower().rstrip(".")
    default = default_workspace(domain)
    workspace_raw = input(f"Workspace [{default}]: ").strip()
    workspace = Path(workspace_raw).expanduser() if workspace_raw else default
    config_save(domain, workspace)
    return domain, workspace


def interactive_menu() -> None:
    banner()
    domain, workspace = choose_target()
    paths = ensure_workspace(workspace, domain)

    while True:
        print(f"\nTarget actual: {domain}")
        print(f"Workspace:     {workspace}\n")
        print("[1] Dashboard / estado")
        print("[2] Ejecutar crt.sh")
        print("[3] Ejecutar Subfinder")
        print("[4] Ejecutar todas las fuentes automatizadas")
        print("[5] Ver hosts nuevos por fuente")
        print("[6] Ver inventario")
        print("[7] Buscar en inventario")
        print("[8] Ver fuentes y roadmap")
        print("[9] Cambiar target")
        print("[0] Salir")

        choice = input("\nOpción > ").strip()
        try:
            if choice == "1":
                print_status(domain, paths)
            elif choice == "2":
                collect_source("crtsh", domain, paths, 300)
            elif choice == "3":
                collect_source("subfinder", domain, paths, 300)
            elif choice == "4":
                for source in SOURCE_ORDER:
                    collect_source(source, domain, paths, 300)
            elif choice == "5":
                source = input(f"Fuente ({', '.join(SOURCE_ORDER)}): ").strip().lower()
                if source in SOURCE_ORDER:
                    show_new(paths, source)
                else:
                    print("[!] Fuente inválida.")
            elif choice == "6":
                raw_limit = input("Máximo a mostrar [50, 0 = todos]: ").strip()
                limit = 50 if raw_limit == "" else int(raw_limit)
                show_inventory(paths, None if limit == 0 else limit)
            elif choice == "7":
                search_inventory(paths, input("Texto a buscar: ").strip())
            elif choice == "8":
                show_sources()
            elif choice == "9":
                domain, workspace = choose_target(force_new=True)
                paths = ensure_workspace(workspace, domain)
            elif choice == "0":
                print("Hasta luego. Negro queda olfateando.")
                return
            else:
                print("[!] Opción inválida.")
        except KeyboardInterrupt:
            print("\n[!] Operación cancelada.")
        except Exception as exc:
            print(f"[!] Error: {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Negro Recon — Passive Bug Bounty reconnaissance organizer"
    )
    parser.add_argument("domain", nargs="?", help="Dominio objetivo. Sin argumentos abre menú.")
    parser.add_argument("-w", "--workspace", type=Path)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--version", action="version", version=f"Negro Recon {VERSION}")

    subs = parser.add_subparsers(dest="command")
    subs.add_parser("init")

    runp = subs.add_parser("run")
    runp.add_argument("--sources", nargs="+", choices=SOURCE_ORDER, default=SOURCE_ORDER)

    subs.add_parser("status")

    newp = subs.add_parser("new")
    newp.add_argument("source", choices=SOURCE_ORDER)

    invp = subs.add_parser("inventory")
    invp.add_argument("--limit", type=int, default=50)

    searchp = subs.add_parser("search")
    searchp.add_argument("pattern")

    subs.add_parser("sources")
    return parser


def cli_main(args: argparse.Namespace) -> None:
    domain = args.domain.strip().lower().rstrip(".")
    workspace = args.workspace.expanduser() if args.workspace else default_workspace(domain)
    config_save(domain, workspace)
    paths = ensure_workspace(workspace, domain)

    if args.command == "init":
        print(f"[+] Workspace listo: {workspace}")
        print_status(domain, paths)
    elif args.command == "status" or args.command is None:
        print_status(domain, paths)
    elif args.command == "new":
        show_new(paths, args.source)
    elif args.command == "inventory":
        show_inventory(paths, None if args.limit == 0 else args.limit)
    elif args.command == "search":
        search_inventory(paths, args.pattern)
    elif args.command == "sources":
        show_sources()
    elif args.command == "run":
        for source in args.sources:
            try:
                collect_source(source, domain, paths, args.timeout)
            except Exception as exc:
                print(f"[!] {source}: {exc}", file=sys.stderr)
        print_status(domain, paths)


def main() -> None:
    if len(sys.argv) == 1:
        interactive_menu()
        return
    parser = build_parser()
    args = parser.parse_args()
    if args.domain is None:
        interactive_menu()
        return
    cli_main(args)


if __name__ == "__main__":
    main()
