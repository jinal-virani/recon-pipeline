#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon-pipeline — Automated subdomain reconnaissance pipeline.

Pipeline:
    Domain -> subfinder -> dnsx -> httpx-toolkit -> katana -> mantra

AUTHORIZED USE ONLY: run this tool ONLY against domains you own or are
explicitly authorized to assess (CTFs, labs, authorized bug-bounty scopes).

Usage:
    python3 recon.py example.com
    python3 recon.py --domain example.com --output results
"""

from __future__ import annotations

import argparse
import logging
import re
import shutil
import signal
import subprocess
import sys
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import yaml  # listed in requirements.txt; config degrades to defaults if absent
except ImportError:  # pragma: no cover
    yaml = None

APP_NAME = "recon-pipeline"
VERSION = "1.0.0"

# Logical tool name -> candidate binary names (first found on PATH wins).
TOOLS: Dict[str, List[str]] = {
    "subfinder": ["subfinder"],
    "httpx": ["httpx-toolkit", "httpx"],  # Kali package name first, PD upstream second
    "dnsx": ["dnsx"],
    "katana": ["katana"],
    # "mantra": ["mantra"],
}

# Go module paths used by --update.
GO_MODULES: Dict[str, str] = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    # "mantra": "github.com/Brosck/mantra",
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "httpx": {
        "threads": 25,
        "timeout": 10,
        "status_code": True,
        "title": True,
        "tech_detect": True,
        "web_server": True,
        "content_length": True,
        "location": False,
    },
    "dnsx": {"threads": 25, "timeout": 10},
    "katana": {"depth": 2, "concurrency": 5, "timeout": 30},
    # "mantra": {"enabled": True},
    "output": {"directory": "output"},
    "logging": {"level": "INFO"},
}

# Strict hostname validation: no scheme, no path, no port, no shell chars.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

SHELL_METACHARS = set(" /\\;|&`$<>(){}[]!\"'*?\n\r\t")

FILE_LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
CONSOLE_PREFIX = {
    logging.DEBUG: "[DEBUG]",
    logging.INFO: "[+]",
    logging.WARNING: "[WARNING]",
    logging.ERROR: "[ERROR]",
    logging.CRITICAL: "[CRITICAL]",
}


class ReconError(Exception):
    """Base class for pipeline errors."""


class InvalidDomainError(ReconError):
    """Raised when the supplied domain is not a valid hostname."""


class ToolNotFoundError(ReconError):
    """Raised when a required external tool is missing."""


class ToolTimeoutError(ReconError):
    """Raised when an external tool exceeds its time budget."""


@dataclass
class StageResult:
    """Outcome of a single pipeline stage."""

    name: str
    status: str = "PENDING"  # SUCCESS | FAILED | SKIPPED
    count: int = 0
    output_file: Optional[Path] = None
    message: str = ""


class ConsoleFormatter(logging.Formatter):
    """Prefixes console records with [+]/[-]/[WARNING]/[ERROR]."""

    def format(self, record: logging.LogRecord) -> str:
        prefix = CONSOLE_PREFIX.get(record.levelno, "[*]")
        return f"{prefix} {super().format(record)}"


def setup_logging(log_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure file + console logging and return the app logger."""
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_dir / "scan.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter(FILE_LOG_FORMAT))
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(ConsoleFormatter("%(message)s"))
    logger.addHandler(ch)
    return logger


# ---------------------------------------------------------------------------
# Domain / filesystem helpers
# ---------------------------------------------------------------------------

def validate_domain(domain: str) -> bool:
    """Return True if ``domain`` is a syntactically valid bare hostname.

    Rejects schemes, paths, ports and any shell metacharacters so the value
    can never be interpreted as shell syntax downstream.
    """
    if not isinstance(domain, str) or not domain or len(domain) > 253:
        return False
    if any(ch in SHELL_METACHARS for ch in domain):
        return False
    return bool(DOMAIN_RE.match(domain))


def sanitize_dirname(domain: str) -> str:
    """Return a filesystem-safe directory name derived from ``domain``."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)
    return safe.strip("._-") or "target"


def make_scan_dir(base: Path, domain: str) -> Path:
    """Create a unique timestamped scan directory; never overwrites old scans."""
    safe = sanitize_dirname(domain)
    root = base / safe
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    scan_dir = root / stamp
    counter = 1
    while scan_dir.exists():  # same-second collision safety
        scan_dir = root / f"{stamp}_{counter}"
        counter += 1
    scan_dir.mkdir(parents=True)
    return scan_dir


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(config_path: Path) -> Dict[str, Any]:
    """Load config.yaml and deep-merge it over DEFAULT_CONFIG."""
    cfg = deepcopy(DEFAULT_CONFIG)
    if yaml is None or not config_path.exists():
        return cfg
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            return cfg
        for section, values in loaded.items():
            if isinstance(values, dict) and isinstance(cfg.get(section), dict):
                cfg[section].update(values)
            else:
                cfg[section] = values
    except Exception as exc:  # config must never crash the tool
        print(f"[WARNING] Could not load {config_path}: {exc}; using defaults.")
    return cfg


# ---------------------------------------------------------------------------
# Dependencies & safe subprocess execution
# ---------------------------------------------------------------------------

def find_tool(logical: str) -> Optional[str]:
    """Return the absolute path of the first available binary for ``logical``."""
    for candidate in TOOLS.get(logical, [logical]):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def check_dependencies() -> Dict[str, Optional[str]]:
    """Probe every required tool; return name -> binary path (None if missing)."""
    return {name: find_tool(name) for name in TOOLS}


def run_command(
    cmd: Sequence[str],
    *,
    timeout: int = 120,
    input_data: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> subprocess.CompletedProcess:
    """Execute ``cmd`` as an argument list. Never uses a shell."""
    if logger:
        logger.debug("exec: %s", " ".join(str(c) for c in cmd))
    try:
        return subprocess.run(
            [str(c) for c in cmd],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"binary not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeoutError(f"{cmd[0]} exceeded {timeout}s timeout") from exc


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def read_lines(path: Path) -> List[str]:
    """Read non-empty, stripped lines from a text file (missing file -> [])."""
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return []


def write_lines(path: Path, lines: Sequence[str]) -> None:
    """Write de-duplicated, non-empty lines to a text file."""
    seen: set = set()
    unique: List[str] = []
    for line in lines:
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            unique.append(line)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")


# ---------------------------------------------------------------------------
# Command builders (kept pure/testable)
# ---------------------------------------------------------------------------

def build_subfinder_cmd(binary: str, domain: str, output_file: Path) -> List[str]:
    return [binary, "-d", domain, "-o", str(output_file), "-silent"]


def build_dnsx_cmd(
    binary: str, input_file: Path, output_file: Path, cfg: Dict[str, Any]
) -> List[str]:
    # dnsx has no -timeout flag (verified against PD docs); threads only.
    return [
        binary,
        "-l", str(input_file),
        "-o", str(output_file),
        "-silent",
        "-t", str(cfg.get("threads", 25)),
    ]


def build_httpx_cmd(
    binary: str, input_file: Path, output_file: Path, cfg: Dict[str, Any]
) -> List[str]:
    cmd = [binary, "-l", str(input_file), "-o", str(output_file), "-silent"]
    if cfg.get("status_code"):
        cmd.append("-status-code")
    if cfg.get("title"):
        cmd.append("-title")
    if cfg.get("tech_detect"):
        cmd.append("-tech-detect")
    if cfg.get("web_server"):
        cmd.append("-web-server")
    if cfg.get("content_length"):
        cmd.append("-content-length")
    if cfg.get("location"):
        cmd.append("-location")
    cmd += ["-threads", str(cfg.get("threads", 25)), "-timeout", str(cfg.get("timeout", 10))]
    return cmd


def build_katana_cmd(
    binary: str, input_file: Path, output_file: Path, cfg: Dict[str, Any]
) -> List[str]:
    # katana has no -timeout flag (verified against PD docs);
    # use -depth and -concurrency only.
    return [
        binary,
        "-list", str(input_file),
        "-o", str(output_file),
        "-silent",
        "-depth", str(cfg.get("depth", 2)),
        "-c", str(cfg.get("concurrency", 5)),
    ]


# ---------------------------------------------------------------------------
# Result parsers
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"^https?://[^\s\[\]]+", re.IGNORECASE)
JS_URL_RE = re.compile(r"\.js(?:\?|$)", re.IGNORECASE)


def parse_httpx_output(path: Path) -> Tuple[List[str], List[str]]:
    """Return (detailed lines, clean live URLs) from an httpx result file."""
    detailed: List[str] = []
    live: List[str] = []
    for line in read_lines(path):
        detailed.append(line)
        m = URL_RE.match(line)
        if m:
            url = m.group(0).rstrip(".,;)]}>")
            live.append(url)
    return detailed, live


def extract_js_urls(urls: Sequence[str]) -> List[str]:
    """Keep only JavaScript asset URLs (``.js`` with optional query string)."""
    return [u for u in urls if JS_URL_RE.search(u)]


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def stage_subfinder(
    domain: str, binary: str, scan_dir: Path, logger: logging.Logger
) -> StageResult:
    st = StageResult(name="subfinder")
    output_file = scan_dir / "subdomains.txt"
    cmd = build_subfinder_cmd(binary, domain, output_file)
    logger.info("Running subdomain enumeration (subfinder)...")
    try:
        result = run_command(cmd, timeout=300, logger=logger)
    except ReconError as exc:
        st.status, st.message = "FAILED", str(exc)
        return st
    if result.returncode != 0:
        st.status = "FAILED"
        st.message = f"exit={result.returncode}: {result.stderr.strip()[:300]}"
        return st
    subs = read_lines(output_file)
    write_lines(output_file, subs)  # normalize/dedupe
    st.status, st.count, st.output_file = "SUCCESS", len(subs), output_file
    if st.count == 0:
        st.message = "no subdomains found"
        logger.warning("No subdomains found for %s.", domain)
    else:
        logger.info("Subdomains found: %d", st.count)
    return st


def stage_dnsx(
    binary: str, scan_dir: Path, logger: logging.Logger, cfg: Dict[str, Any]
) -> StageResult:
    st = StageResult(name="dnsx")
    output_file = scan_dir / "dnsx.txt"
    cmd = build_dnsx_cmd(binary, scan_dir / "subdomains.txt", output_file, cfg)
    logger.info("Running DNS resolution (dnsx)...")
    try:
        result = run_command(cmd, timeout=300, logger=logger)
    except ReconError as exc:
        st.status, st.message = "FAILED", str(exc)
        return st
    if result.returncode != 0:
        st.status = "FAILED"
        st.message = f"exit={result.returncode}: {result.stderr.strip()[:300]}"
        return st
    resolved = read_lines(output_file)
    write_lines(output_file, resolved)
    write_lines(scan_dir / "resolved.txt", resolved)
    st.status, st.count, st.output_file = "SUCCESS", len(resolved), output_file
    if st.count == 0:
        st.message = "no domains resolved"
        logger.warning("dnsx resolved no domains.")
    else:
        logger.info("DNS resolved: %d", st.count)
    return st


def stage_httpx(
    binary: str, scan_dir: Path, logger: logging.Logger, cfg: Dict[str, Any]
) -> StageResult:
    st = StageResult(name="httpx")
    output_file = scan_dir / "httpx.txt"
    cmd = build_httpx_cmd(binary, scan_dir / "subdomains.txt", output_file, cfg)
    logger.info("Probing HTTP/HTTPS services (httpx)...")
    try:
        result = run_command(cmd, timeout=600, logger=logger)
    except ReconError as exc:
        st.status, st.message = "FAILED", str(exc)
        return st
    if result.returncode != 0:
        st.status = "FAILED"
        st.message = f"exit={result.returncode}: {result.stderr.strip()[:300]}"
        return st
    detailed, live = parse_httpx_output(output_file)
    write_lines(output_file, detailed)
    write_lines(scan_dir / "live_urls.txt", live)
    st.status, st.count, st.output_file = "SUCCESS", len(detailed), output_file
    logger.info("HTTP services detected: %d", len(detailed))
    logger.info("Live URLs: %d", len(live))
    return st


def stage_katana(
    binary: str, scan_dir: Path, logger: logging.Logger, cfg: Dict[str, Any]
) -> StageResult:
    st = StageResult(name="katana")
    output_file = scan_dir / "katana.txt"
    cmd = build_katana_cmd(binary, scan_dir / "live_urls.txt", output_file, cfg)
    logger.info("Crawling live URLs (katana)...")
    try:
        result = run_command(cmd, timeout=900, logger=logger)
    except ReconError as exc:
        st.status, st.message = "FAILED", str(exc)
        return st
    if result.returncode != 0:
        st.status = "FAILED"
        st.message = f"exit={result.returncode}: {result.stderr.strip()[:300]}"
        return st
    urls = read_lines(output_file)
    write_lines(output_file, urls)
    st.status, st.count, st.output_file = "SUCCESS", len(urls), output_file
    logger.info("Katana URLs discovered: %d", len(urls))
    return st


# def stage_mantra(
#     binary: str, scan_dir: Path, logger: logging.Logger
# ) -> StageResult:
#     st = StageResult(name="mantra")
#     output_file = scan_dir / "mantra.txt"
#     js_urls = extract_js_urls(read_lines(scan_dir / "katana.txt"))
#     if not js_urls:
#         st.status, st.message = "SKIPPED", "no JavaScript URLs found in katana output"
#         logger.warning("mantra skipped: no JS URLs to scan.")
#         return st
#     logger.info("Scanning %d JS URL(s) for leaked secrets (mantra)...", len(js_urls))
#     try:
#         result = run_command(
#             [binary], timeout=300, input_data="\n".join(js_urls), logger=logger
#         )
#     except ReconError as exc:
#         st.status, st.message = "FAILED", str(exc)
#         return st
#     if result.returncode != 0:
#         st.status = "FAILED"
#         st.message = f"exit={result.returncode}: {result.stderr.strip()[:300]}"
#         return st
#     results = [ln for ln in result.stdout.splitlines() if ln.strip()]
#     write_lines(output_file, results)
#     st.status, st.count, st.output_file = "SUCCESS", len(results), output_file
#     logger.info("Mantra results: %d", len(results))
#     return st


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def generate_summary(
    domain: str,
    scan_dir: Path,
    stages: List[StageResult],
    counts: Dict[str, int],
    started: datetime,
    finished: datetime,
    interrupted: bool = False,
) -> Path:
    lines = [
        "========================================",
        " Reconnaissance Summary",
        "========================================",
        "",
        f"Target:          {domain}",
        f"Scan directory:  {scan_dir}",
        "",
        f"Subdomains:      {counts.get('subdomains', 0)}",
        f"DNS Resolved:    {counts.get('resolved', 0)}",
        f"HTTP Services:   {counts.get('http', 0)}",
        f"Live URLs:       {counts.get('live_urls', 0)}",
        f"Katana URLs:     {counts.get('katana', 0)}",
        # f"Mantra Results:  {counts.get('mantra', 0)}",
        "",
        "Stages:",
    ]
    for st in stages:
        suffix = f" ({st.message})" if st.message else ""
        lines.append(f"  {st.name:<10} {st.status}{suffix}")
    lines += [
        "",
        f"Scan started:    {started:%Y-%m-%d %H:%M:%S}",
        f"Scan completed:  {finished:%Y-%m-%d %H:%M:%S}",
    ]
    if interrupted:
        lines.append("Note:            Scan interrupted by user (Ctrl+C).")
    lines.append("========================================")
    summary = scan_dir / "summary.txt"
    summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def print_terminal_summary(
    domain: str, scan_dir: Path, counts: Dict[str, int], interrupted: bool
) -> None:
    print("\n" + "=" * 52)
    print(" Scan Complete")
    print("=" * 52)
    print(f" Target:        {domain}")
    print(f" Subdomains:    {counts['subdomains']}")
    print(f" DNS Resolved:  {counts['resolved']}")
    print(f" HTTP Services: {counts['http']}")
    print(f" Live URLs:     {counts['live_urls']}")
    print(f" Katana URLs:   {counts['katana']}")
    # print(f" Mantra:        {counts['mantra']}")
    if interrupted:
        print(" Note:          interrupted by user (Ctrl+C)")
    print("\n Results:")
    print(f" {scan_dir}/")


# ---------------------------------------------------------------------------
# Update helper
# ---------------------------------------------------------------------------

def run_update(logger: logging.Logger) -> int:
    """Reinstall all Go-based tools at the latest version."""
    go = shutil.which("go")
    if not go:
        print("[ERROR] go is not installed. Install it: sudo apt install golang-go")
        return 1
    print("[+] Updating Go-installed tools (this may take a while)...")
    ok = True
    for name, module in GO_MODULES.items():
        print(f"[*] Updating {name} ...")
        try:
            result = run_command([go, "install", "-v", f"{module}@latest"], timeout=600, logger=logger)
            if result.returncode == 0:
                print(f"[+] {name} updated.")
            else:
                print(f"[ERROR] {name} update failed: {result.stderr.strip()[:200]}")
                ok = False
        except ReconError as exc:
            print(f"[ERROR] {name}: {exc}")
            ok = False
    print(f"[INFO] Ensure $(go env GOPATH)/bin is in your PATH.")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> Tuple[argparse.Namespace, Optional[str]]:
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description=f"{APP_NAME} v{VERSION} — automated subdomain reconnaissance pipeline.",
        epilog="Authorized use only. See README.md.",
    )
    parser.add_argument("domain", nargs="?", help="root domain to enumerate (e.g. example.com)")
    parser.add_argument("--domain", dest="domain_flag", help="root domain (alternative to positional arg)")
    parser.add_argument("--output", default=None, help="base output directory (default: from config.yaml)")
    parser.add_argument("--timeout", type=int, default=None, help="override default tool timeout (seconds)")
    parser.add_argument("--threads", type=int, default=None, help="override default thread/concurrency count")
    parser.add_argument("--skip-dnsx", action="store_true", help="skip DNS resolution stage")
    parser.add_argument("--skip-katana", action="store_true", help="skip web crawling stage")
    # parser.add_argument("--skip-mantra", action="store_true", help="skip mantra secret-scanning stage")
    parser.add_argument("--update", action="store_true", help="update Go-installed tools and exit")
    parser.add_argument("--verbose", action="store_true", help="enable DEBUG logging")
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    args = parser.parse_args(argv)
    if args.domain_flag and args.domain:
        parser.error("provide the domain either positionally or via --domain, not both")
    return args, args.domain_flag or args.domain


def print_banner() -> None:
    print("=" * 52)
    print(f" {APP_NAME} v{VERSION} — Automated Recon Pipeline")
    print("=" * 52)


def run_pipeline(
    domain: str, args: argparse.Namespace, cfg: Dict[str, Any], logger: logging.Logger
) -> int:
    started = datetime.now()
    base = Path(args.output or cfg["output"]["directory"])
    scan_dir = make_scan_dir(base, domain)
    logger.info("Scan directory: %s", scan_dir)

    # -- dependencies -----------------------------------------------------
    logger.info("Checking dependencies...")
    deps = check_dependencies()
    missing = [name for name, path in deps.items() if path is None]
    for name in TOOLS:
        if deps[name]:
            logger.info("%s: OK (%s)", name, deps[name])
        else:
            logger.error("%s is not installed.", name)
    if missing:
        logger.error("Missing tools: %s", ", ".join(missing))
        logger.error("Run ./install.sh to install them, then re-run.")
        return 1

    stages: List[StageResult] = []
    interrupted = False
    st_httpx = StageResult("httpx", "SKIPPED", message="not reached")

    try:
        # -- subfinder ----------------------------------------------------
        st_sub = stage_subfinder(domain, deps["subfinder"], scan_dir, logger)
        stages.append(st_sub)
        subdomains = read_lines(scan_dir / "subdomains.txt")

        # -- dnsx ---------------------------------------------------------
        if args.skip_dnsx:
            stages.append(StageResult("dnsx", "SKIPPED", message="--skip-dnsx"))
            logger.warning("dnsx skipped (--skip-dnsx).")
        elif st_sub.status != "SUCCESS" or not subdomains:
            stages.append(StageResult("dnsx", "SKIPPED", message="no subdomains to resolve"))
            logger.warning("dnsx skipped: no subdomains available.")
        else:
            stages.append(stage_dnsx(deps["dnsx"], scan_dir, logger, cfg))

        # -- httpx --------------------------------------------------------
        if st_sub.status != "SUCCESS" or not subdomains:
            st_httpx = StageResult("httpx", "SKIPPED", message="no subdomains to probe")
            stages.append(st_httpx)
            logger.warning("httpx skipped: no subdomains available.")
        else:
            st_httpx = stage_httpx(deps["httpx"], scan_dir, logger, cfg)
            stages.append(st_httpx)

        # -- katana -------------------------------------------------------
        live_urls = read_lines(scan_dir / "live_urls.txt")
        if args.skip_katana:
            stages.append(StageResult("katana", "SKIPPED", message="--skip-katana"))
            logger.warning("katana skipped (--skip-katana).")
        elif not live_urls:
            stages.append(StageResult("katana", "SKIPPED", message="no live URLs to crawl"))
            logger.warning("katana skipped: no live URLs available.")
        elif st_httpx.status != "SUCCESS":
            stages.append(StageResult("katana", "SKIPPED", message="httpx stage failed"))
            logger.warning("katana skipped: httpx stage failed.")
        else:
            stages.append(stage_katana(deps["katana"], scan_dir, logger, cfg))

        # -- mantra -------------------------------------------------------
        # katana_urls = read_lines(scan_dir / "katana.txt")
        # if args.skip_mantra:
        #     stages.append(StageResult("mantra", "SKIPPED", message="--skip-mantra"))
        #     logger.warning("mantra skipped (--skip-mantra).")
        # elif not katana_urls:
        #     stages.append(StageResult("mantra", "SKIPPED", message="no katana URLs to scan"))
        #     logger.warning("mantra skipped: no katana output available.")
        # else:
        #     stages.append(stage_mantra(deps["mantra"], scan_dir, logger))
    except KeyboardInterrupt:
        interrupted = True
        logger.error("Interrupted by user (Ctrl+C). Preserving partial results...")
    except Exception as exc:  # noqa: BLE001 - last-resort guard
        logger.error("Unexpected pipeline error: %s", exc)
        stages.append(StageResult("pipeline", "FAILED", message=str(exc)))

    # Finalize any stage left PENDING.
    for st in stages:
        if st.status == "PENDING":
            st.status, st.message = "SKIPPED", "not reached"

    counts = {
        "subdomains": len(read_lines(scan_dir / "subdomains.txt")),
        "resolved": len(read_lines(scan_dir / "resolved.txt")),
        "http": len(read_lines(scan_dir / "httpx.txt")),
        "live_urls": len(read_lines(scan_dir / "live_urls.txt")),
        "katana": len(read_lines(scan_dir / "katana.txt")),
        # "mantra": len(read_lines(scan_dir / "mantra.txt")),
    }

    finished = datetime.now()
    summary = generate_summary(domain, scan_dir, stages, counts, started, finished, interrupted)
    logger.info("Summary written to %s", summary)
    print_terminal_summary(domain, scan_dir, counts, interrupted)
    return 130 if interrupted else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args, domain = parse_args(argv)

    if args.update:
        print_banner()
        logger = setup_logging(Path("logs"), "INFO")
        return run_update(logger)

    if not domain:
        print("[ERROR] No domain supplied.")
        print("[INFO]  Usage: python3 recon.py example.com")
        return 2
    if not validate_domain(domain):
        print(f"[ERROR] Invalid domain: {domain!r}")
        print("[INFO]  Use a bare hostname (no scheme, path, or port): example.com")
        return 2

    print_banner()
    print(f"[+] Target: {domain}")
    print()

    cfg = load_config(Path(args.config))
    log_level = "DEBUG" if args.verbose else str(cfg["logging"].get("level", "INFO"))
    log_base = Path(args.output or cfg["output"]["directory"]) / sanitize_dirname(domain)
    logger = setup_logging(log_base, log_level)

    # Apply CLI overrides.
    if args.threads:
        for section in ("httpx", "dnsx"):
            cfg[section]["threads"] = args.threads
        cfg["katana"]["concurrency"] = args.threads
    if args.timeout:
        for section in ("httpx", "dnsx", "katana"):
            cfg[section]["timeout"] = args.timeout

    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        return run_pipeline(domain, args, cfg, logger)
    except KeyboardInterrupt:
        logger.error("Interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())