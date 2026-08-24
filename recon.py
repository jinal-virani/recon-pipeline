#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon-pipeline - authorized reconnaissance pipeline.

Pipeline:
    domain -> subfinder -> dnsx -> httpx-toolkit -> live_urls -> katana -> mantra

Usage:
    python3 recon.py example.com
    python3 recon.py --domain example.com --output results

AUTHORIZED USE ONLY:
Run this tool only against systems you own or are explicitly authorized
to assess, including CTFs, labs, and in-scope bug-bounty targets.
"""

from __future__ import annotations

import argparse
import logging
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


APP_NAME = "recon-pipeline"
VERSION = "2.0.0"

# Kali commonly exposes ProjectDiscovery httpx as httpx-toolkit.
TOOLS = {
    "subfinder": ["subfinder"],
    "dnsx": ["dnsx"],
    "httpx": ["httpx-toolkit", "httpx"],
    "katana": ["katana"],
    # "mantra": ["mantra"],
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

URL_RE = re.compile(r"https?://[^\s\[\]<>\"']+", re.I)
SHELL_CHARS = set(" /\\;|&`$<>(){}[]!\"'*?\n\r\t")

DEFAULTS: Dict[str, Any] = {
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
    "dnsx": {"threads": 25},
    "katana": {"depth": 2, "concurrency": 5},
    "timeouts": {
        "subfinder": 300,
        "dnsx": 300,
        "httpx": 600,
        "katana": 900,
        # "mantra": 600,
    },
    "output": {"directory": "output"},
}


@dataclass
class StageResult:
    name: str
    status: str = "PENDING"
    count: int = 0
    output_file: Optional[Path] = None
    message: str = ""


class ReconError(Exception):
    pass


class ToolTimeoutError(ReconError):
    pass


def validate_domain(domain: str) -> bool:
    if not isinstance(domain, str) or not domain or len(domain) > 253:
        return False
    if any(ch in SHELL_CHARS for ch in domain):
        return False
    return bool(DOMAIN_RE.fullmatch(domain.rstrip(".")))


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def sanitize_dirname(domain: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)
    return safe.strip("._-") or "target"


def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    try:
        return [
            line.strip()
            for line in path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def write_lines(path: Path, lines: Sequence[str]) -> None:
    seen = set()
    clean = []
    for line in lines:
        value = str(line).strip()
        if value and value not in seen:
            seen.add(value)
            clean.append(value)

    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(clean)
    path.write_text(content + ("\n" if content else ""), encoding="utf-8")


def make_scan_dir(base: Path, domain: str) -> Path:
    root = base / sanitize_dirname(domain)
    root.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    scan_dir = root / stamp
    counter = 1

    while scan_dir.exists():
        scan_dir = root / f"{stamp}_{counter}"
        counter += 1

    scan_dir.mkdir(parents=True)
    return scan_dir


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)

    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value

    return result


def load_config(path: Path) -> Dict[str, Any]:
    config = DEFAULTS

    if not path.exists():
        return config

    try:
        import yaml
    except ImportError:
        print("[WARNING] PyYAML is not installed; using built-in defaults.")
        return config

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            print("[WARNING] config.yaml must contain a YAML mapping; using defaults.")
            return config
        return deep_merge(config, loaded)
    except Exception as exc:
        print(f"[WARNING] Could not load {path}: {exc}")
        return config


def setup_logging(scan_dir: Path, verbose: bool) -> logging.Logger:
    logger = logging.getLogger(APP_NAME)
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler(scan_dir / "scan.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console)

    return logger


def find_tool(name: str) -> Optional[str]:
    for candidate in TOOLS.get(name, [name]):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def check_dependencies() -> Dict[str, Optional[str]]:
    return {name: find_tool(name) for name in TOOLS}


def run_command(
    command: Sequence[str],
    timeout: int,
    logger: logging.Logger,
    input_data: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    logger.debug("Command: %s", " ".join(map(str, command)))

    try:
        return subprocess.run(
            list(map(str, command)),
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeoutError(
            f"{command[0]} timed out after {timeout} seconds"
        ) from exc
    except FileNotFoundError as exc:
        raise ReconError(f"Tool not found: {command[0]}") from exc


def save_process_error(
    result: subprocess.CompletedProcess[str],
    stage: StageResult,
) -> StageResult:
    if result.returncode != 0:
        stderr = (result.stderr or "").strip().replace("\n", " ")
        stage.status = "FAILED"
        stage.message = f"exit={result.returncode}"
        if stderr:
            stage.message += f": {stderr[:300]}"
    return stage


def build_subfinder(binary: str, domain: str, output: Path) -> List[str]:
    return [binary, "-d", domain, "-silent", "-o", str(output)]


def build_dnsx(binary: str, input_file: Path, output: Path, cfg: Dict[str, Any]) -> List[str]:
    return [
        binary,
        "-l", str(input_file),
        "-silent",
        "-o", str(output),
        "-t", str(cfg.get("threads", 25)),
    ]


def build_httpx(binary: str, input_file: Path, output: Path, cfg: Dict[str, Any]) -> List[str]:
    command = [
        binary,
        "-l", str(input_file),
        "-silent",
        "-o", str(output),
        "-threads", str(cfg.get("threads", 25)),
        "-timeout", str(cfg.get("timeout", 10)),
    ]

    flags = {
        "status_code": "-status-code",
        "title": "-title",
        "tech_detect": "-tech-detect",
        "web_server": "-web-server",
        "content_length": "-content-length",
        "location": "-location",
    }

    for key, flag in flags.items():
        if cfg.get(key):
            command.append(flag)
            command += ["-mc", "200,301,302"]
    return command


def build_katana(binary: str, input_file: Path, output: Path, cfg: Dict[str, Any]) -> List[str]:
    return [
        binary,
        "-list", str(input_file),
        "-silent",
        "-o", str(output),
        "-depth", str(cfg.get("depth", 2)),
        "-c", str(cfg.get("concurrency", 5)),
    ]


def extract_urls(lines: Sequence[str]) -> List[str]:
    urls = []

    for line in lines:
        match = URL_RE.search(line)
        if match:
            urls.append(match.group(0).rstrip(".,;)]}"))

    return urls


def parse_httpx(path: Path) -> List[str]:
    """
    httpx -silent output starts with the URL and may contain metadata.
    Extract only the URL portion for downstream crawling.
    """
    return extract_urls(read_lines(path))


def run_stage(
    name: str,
    command: Sequence[str],
    output_file: Path,
    timeout: int,
    logger: logging.Logger,
) -> StageResult:
    result_stage = StageResult(name=name, output_file=output_file)

    try:
        result = run_command(command, timeout, logger)
    except ReconError as exc:
        result_stage.status = "FAILED"
        result_stage.message = str(exc)
        logger.error("%s failed: %s", name, exc)
        return result_stage

    if result.returncode != 0:
        save_process_error(result, result_stage)
        logger.error("%s failed: %s", name, result_stage.message)
        return result_stage

    values = read_lines(output_file)
    write_lines(output_file, values)

    result_stage.status = "SUCCESS"
    result_stage.count = len(values)

    if not values:
        result_stage.message = "command succeeded but returned no results"
        logger.warning("%s returned no results.", name)
    else:
        logger.info("%s returned %d result(s).", name, len(values))

    return result_stage


def stage_subfinder(
    domain: str,
    binary: str,
    scan_dir: Path,
    logger: logging.Logger,
    timeout: int,
) -> StageResult:
    output = scan_dir / "subdomains.txt"
    logger.info("1/5 Running subfinder...")

    stage = run_stage(
        "subfinder",
        build_subfinder(binary, domain, output),
        output,
        timeout,
        logger,
    )

    # Always normalize subfinder output.
    write_lines(output, read_lines(output))
    stage.count = len(read_lines(output))
    return stage


def stage_dnsx(
    binary: str,
    scan_dir: Path,
    logger: logging.Logger,
    cfg: Dict[str, Any],
    timeout: int,
) -> StageResult:
    output = scan_dir / "dnsx.txt"
    input_file = scan_dir / "subdomains.txt"

    logger.info("2/5 Running dnsx...")

    stage = run_stage(
        "dnsx",
        build_dnsx(binary, input_file, output, cfg),
        output,
        timeout,
        logger,
    )

    resolved = read_lines(output)
    write_lines(scan_dir / "resolved.txt", resolved)
    stage.count = len(resolved)
    return stage


def stage_httpx(
    binary: str,
    scan_dir: Path,
    logger: logging.Logger,
    cfg: Dict[str, Any],
    timeout: int,
) -> StageResult:
    output = scan_dir / "httpx.txt"
    logger.info("3/5 Running httpx-toolkit...")

    stage = run_stage(
        "httpx",
        build_httpx(binary, scan_dir / "subdomains.txt", output, cfg),
        output,
        timeout,
        logger,
    )

    # This is the critical gate for Katana:
    # only actual HTTP/HTTPS URLs go into live_urls.txt.
    live_urls = parse_httpx(output)
    write_lines(scan_dir / "live_urls.txt", live_urls)

    stage.count = len(read_lines(output))

    logger.info("Live HTTP/HTTPS URLs: %d", len(live_urls))

    if stage.status == "SUCCESS" and not live_urls:
        stage.message = "httpx completed but no live HTTP/HTTPS URLs were found"

    return stage


def stage_katana(
    binary: str,
    scan_dir: Path,
    logger: logging.Logger,
    cfg: Dict[str, Any],
    timeout: int,
) -> StageResult:
    output = scan_dir / "katana.txt"
    logger.info("4/5 Running katana against live URLs...")

    stage = run_stage(
        "katana",
        build_katana(binary, scan_dir / "live_urls.txt", output, cfg),
        output,
        timeout,
        logger,
    )

    stage.count = len(read_lines(output))
    return stage


# def stage_mantra(
#     binary: str,
#     scan_dir: Path,
#     logger: logging.Logger,
#     timeout: int,
# ) -> StageResult:
    # """
    # Mantra accepts URLs through stdin in the commonly documented usage:
    #     cat js_urls.txt | mantra

    # We feed only JavaScript URLs discovered by Katana.
    # """
    # output = scan_dir / "mantra.txt"
    # katana_lines = read_lines(scan_dir / "katana.txt")

    # js_urls = [
    #     url for url in extract_urls(katana_lines)
    #     if re.search(r"\.js(?:[?#].*)?$", url, re.I)
    # ]

    # write_lines(scan_dir / "js_urls.txt", js_urls)

    # if not js_urls:
    #     logger.warning("5/5 Mantra skipped: no JavaScript URLs found.")
    #     return StageResult(
    #         name="mantra",
    #         status="SKIPPED",
    #         message="no JavaScript URLs found in katana output",
    #         output_file=output,
    #     )

    # logger.info("5/5 Running mantra against %d JavaScript URL(s)...", len(js_urls))

    # try:
    #     result = run_command(
    #         [binary],
    #         timeout,
    #         logger,
    #         input_data="\n".join(js_urls) + "\n",
    #     )
    # except ReconError as exc:
    #     logger.error("mantra failed: %s", exc)
    #     return StageResult(
    #         name="mantra",
    #         status="FAILED",
    #         message=str(exc),
    #         output_file=output,
    #     )

    # if result.returncode != 0:
    #     stderr = (result.stderr or "").strip().replace("\n", " ")
    #     message = f"exit={result.returncode}"
    #     if stderr:
    #         message += f": {stderr[:300]}"

    #     logger.error("mantra failed: %s", message)
    #     return StageResult(
    #         name="mantra",
    #         status="FAILED",
    #         message=message,
    #         output_file=output,
    #     )

    results = [
        line.strip()
        for line in (result.stdout or "").splitlines()
        if line.strip()
    ]
    write_lines(output, results)

    # logger.info("Mantra results: %d", len(results))

    # return StageResult(
    #     name="mantra",
    #     status="SUCCESS",
    #     count=len(results),
    #     output_file=output,
    #     message="" if results else "command succeeded but returned no findings",
    # )


def generate_summary(
    domain: str,
    scan_dir: Path,
    stages: Sequence[StageResult],
    started: datetime,
    interrupted: bool,
) -> Path:
    counts = {
        "subdomains": len(read_lines(scan_dir / "subdomains.txt")),
        "resolved": len(read_lines(scan_dir / "resolved.txt")),
        "http": len(read_lines(scan_dir / "httpx.txt")),
        "live_urls": len(read_lines(scan_dir / "live_urls.txt")),
        "katana": len(read_lines(scan_dir / "katana.txt")),
        "js_urls": len(read_lines(scan_dir / "js_urls.txt")),
        # "mantra": len(read_lines(scan_dir / "mantra.txt")),
    }

    finished = datetime.now()

    lines = [
        "=" * 52,
        " Reconnaissance Summary",
        "=" * 52,
        "",
        f"Target:          {domain}",
        f"Scan directory:  {scan_dir}",
        "",
        f"Subdomains:      {counts['subdomains']}",
        f"DNS Resolved:    {counts['resolved']}",
        f"HTTP Services:   {counts['http']}",
        f"Live URLs:       {counts['live_urls']}",
        f"Katana URLs:     {counts['katana']}",
        f"JavaScript URLs: {counts['js_urls']}",
        # f"Mantra Results:  {counts['mantra']}",
        "",
        "Stages:",
    ]

    for stage in stages:
        suffix = f" ({stage.message})" if stage.message else ""
        lines.append(f"  {stage.name:<10} {stage.status}{suffix}")

    lines += [
        "",
        f"Scan started:    {started:%Y-%m-%d %H:%M:%S}",
        f"Scan completed:  {finished:%Y-%m-%d %H:%M:%S}",
    ]

    if interrupted:
        lines.append("Note:            Scan interrupted by user (Ctrl+C).")

    lines.append("=" * 52)

    path = scan_dir / "summary.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def print_summary(domain: str, scan_dir: Path, interrupted: bool) -> None:
    print("\n" + "=" * 52)
    print(" Scan Complete")
    print("=" * 52)
    print(f" Target:          {domain}")
    print(f" Subdomains:      {len(read_lines(scan_dir / 'subdomains.txt'))}")
    print(f" DNS Resolved:    {len(read_lines(scan_dir / 'resolved.txt'))}")
    print(f" HTTP Services:   {len(read_lines(scan_dir / 'httpx.txt'))}")
    print(f" Live URLs:       {len(read_lines(scan_dir / 'live_urls.txt'))}")
    print(f" Katana URLs:     {len(read_lines(scan_dir / 'katana.txt'))}")
    print(f" JavaScript URLs: {len(read_lines(scan_dir / 'js_urls.txt'))}")
    # print(f" Mantra Results:  {len(read_lines(scan_dir / 'mantra.txt'))}")

    if interrupted:
        print(" Status:           INTERRUPTED")

    print(f"\n Results:          {scan_dir}/")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description=f"{APP_NAME} v{VERSION}",
    )

    parser.add_argument("domain", nargs="?", help="root domain, e.g. example.com")
    parser.add_argument("--domain", dest="domain_flag", help="root domain")
    parser.add_argument("--output", help="output directory")
    parser.add_argument("--threads", type=int, help="override threads/concurrency")
    parser.add_argument("--timeout", type=int, help="override stage timeouts")
    parser.add_argument("--skip-dnsx", action="store_true")
    parser.add_argument("--skip-katana", action="store_true")
    # parser.add_argument("--skip-mantra", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--version", action="version", version=VERSION)

    args = parser.parse_args(argv)

    if args.domain and args.domain_flag:
        parser.error("Use either positional domain or --domain, not both.")

    domain = args.domain_flag or args.domain

    if not domain:
        parser.error("A domain is required. Example: python3 recon.py example.com")

    domain = normalize_domain(domain)

    if not validate_domain(domain):
        parser.error(
            f"Invalid domain: {domain!r}. Use a bare hostname such as example.com."
        )

    if args.threads is not None and args.threads < 1:
        parser.error("--threads must be >= 1")

    if args.timeout is not None and args.timeout < 1:
        parser.error("--timeout must be >= 1")

    args.target_domain = domain
    return args


def run_pipeline(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))

    base_output = Path(
        args.output or config.get("output", {}).get("directory", "output")
    )

    scan_dir = make_scan_dir(base_output, args.target_domain)
    logger = setup_logging(scan_dir, args.verbose)

    started = datetime.now()
    interrupted = False
    stages: List[StageResult] = []

    logger.info("Target: %s", args.target_domain)
    logger.info("Scan directory: %s", scan_dir)

    logger.info("Checking dependencies...")
    dependencies = check_dependencies()

    for name, path in dependencies.items():
        if path:
            logger.info("%s: OK -> %s", name, path)
        else:
            logger.error("%s: NOT FOUND", name)

    missing = [name for name, path in dependencies.items() if not path]

    if missing:
        logger.error("Missing required tools: %s", ", ".join(missing))
        logger.error("Install the missing tools and run the scan again.")
        return 1

    httpx_cfg = dict(config.get("httpx", {}))
    dnsx_cfg = dict(config.get("dnsx", {}))
    katana_cfg = dict(config.get("katana", {}))
    timeouts = dict(config.get("timeouts", {}))

    if args.threads:
        httpx_cfg["threads"] = args.threads
        dnsx_cfg["threads"] = args.threads
        katana_cfg["concurrency"] = args.threads

    if args.timeout:
        for key in timeouts:
            timeouts[key] = args.timeout

    try:
        # 1. SUBFINDER
        sub_stage = stage_subfinder(
            args.target_domain,
            dependencies["subfinder"],
            scan_dir,
            logger,
            int(timeouts.get("subfinder", 300)),
        )
        stages.append(sub_stage)

        subdomains = read_lines(scan_dir / "subdomains.txt")

        if not subdomains:
            # logger.warning("No subdomains. DNSx/httpx/katana/mantra cannot continue.")
            stages.extend([
                StageResult("dnsx", "SKIPPED", message="no subdomains"),
                StageResult("httpx", "SKIPPED", message="no subdomains"),
                StageResult("katana", "SKIPPED", message="no live URLs"),
                # StageResult("mantra", "SKIPPED", message="no katana output"),
            ])
        else:
            # 2. DNSX
            if args.skip_dnsx:
                stages.append(StageResult("dnsx", "SKIPPED", message="--skip-dnsx"))
                logger.warning("dnsx skipped.")
            else:
                stages.append(
                    stage_dnsx(
                        dependencies["dnsx"],
                        scan_dir,
                        logger,
                        dnsx_cfg,
                        int(timeouts.get("dnsx", 300)),
                    )
                )

            # 3. HTTPX
            http_stage = stage_httpx(
                dependencies["httpx"],
                scan_dir,
                logger,
                httpx_cfg,
                int(timeouts.get("httpx", 600)),
            )
            stages.append(http_stage)

            live_urls = read_lines(scan_dir / "live_urls.txt")

            # 4. KATANA
            if args.skip_katana:
                stages.append(StageResult("katana", "SKIPPED", message="--skip-katana"))
                logger.warning("katana skipped.")
            elif not live_urls:
                stages.append(StageResult("katana", "SKIPPED", message="no live URLs"))
                logger.warning("Katana skipped: no live URLs.")
            elif http_stage.status != "SUCCESS":
                stages.append(StageResult("katana", "SKIPPED", message="httpx failed"))
                logger.warning("Katana skipped: httpx failed.")
            else:
                katana_stage = stage_katana(
                    dependencies["katana"],
                    scan_dir,
                    logger,
                    katana_cfg,
                    int(timeouts.get("katana", 900)),
                )
                stages.append(katana_stage)

            # # 5. MANTRA
            # katana_urls = read_lines(scan_dir / "katana.txt")

            # if args.skip_mantra:
            #     stages.append(StageResult("mantra", "SKIPPED", message="--skip-mantra"))
            #     logger.warning("mantra skipped.")
            # elif not katana_urls:
            #     stages.append(StageResult("mantra", "SKIPPED", message="no katana output"))
            #     logger.warning("Mantra skipped: no Katana output.")
            # else:
            #     stages.append(
            #         stage_mantra(
            #             dependencies["mantra"],
            #             scan_dir,
            #             logger,
            #             int(timeouts.get("mantra", 600)),
            #         )
            #     )

    except KeyboardInterrupt:
        interrupted = True
        logger.warning("Interrupted by user. Preserving partial results.")
    except Exception as exc:
        logger.exception("Unexpected pipeline error: %s", exc)
        stages.append(StageResult("pipeline", "FAILED", message=str(exc)))

    summary = generate_summary(
        args.target_domain,
        scan_dir,
        stages,
        started,
        interrupted,
    )

    logger.info("Summary written to %s", summary)
    print_summary(args.target_domain, scan_dir, interrupted)

    # Non-zero only when interrupted or the pipeline itself had an unexpected
    # failure. Individual tool failures are preserved in summary.txt.
    if interrupted:
        return 130

    if any(stage.name == "pipeline" and stage.status == "FAILED" for stage in stages):
        return 1

    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    print("=" * 52)
    print(f" {APP_NAME} v{VERSION}")
    print("=" * 52)
    print(f"[+] Target: {args.target_domain}")
    print("[+] Authorized use only.")
    print()

    return run_pipeline(args)


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    sys.exit(main())