#!/usr/bin/env python3
# run_disguiser_sim.py
#
# Driver to run Disguiser-style application traceroute (pinpoint_censor.py)
# over domain lists kept in the SAME directory as this script.
#
# Output structure per input list file:
#   results/<basename>_csep/
#       summary.jsonl                   # one JSON line per (domain × protocol)
#       <domain_sanitized>/
#           dns_stdout.txt
#           dns_hops.json
#           dns_final.json
#           http_stdout.txt
#           http_hops.json
#           http_final.json
#           sni_stdout.txt
#           sni_hops.json
#           sni_final.json
#           aggregate.json              # per-domain summary across protocols
#
# Logging:
#   logs/disguiser_runner.log

import os
import sys
import time
import json
import logging
import pathlib
import subprocess
import re
import ast
import socket
from typing import Optional

# ===========================
#           CONFIG
# ===========================
# Toggle which lists to run. The files must be in the SAME directory as this script.
USE_CENSORED_LIST   = True
USE_UNCENSORED_LIST = True

# Names of the two list files (same directory as this script)
CENSORED_FILE_NAME   = "censored_us.txt"
UNCENSORED_FILE_NAME = "uncensored_us.txt"

# Path to the Disguiser traceroute script (same dir as this script)
PINPOINT_SCRIPT_NAME = "pinpoint_censor.py"

# Protocols and their target servers
# For http/sni we resolve the domain to an IPv4 address at runtime ("RESOLVE").
PROTOCOLS = {
    "dns":  {"server": "8.8.8.8"},   # DNS over TCP target
    "http": {"server": "RESOLVE"},   # resolve per-domain at runtime
    "sni":  {"server": "RESOLVE"},   # resolve per-domain at runtime
}

# TTL sweep
TTL_LOW  = 1
TTL_HIGH = 32

# Per-domain pacing (seconds)
SLEEP_BETWEEN_RUNS = 0.15

# Timeout per subprocess (seconds)
SUBPROCESS_TIMEOUT = 120

# Top-level output dirs
RESULTS_ROOT = "results"
LOGS_ROOT    = "logs"

# ===========================
#       HELPER SETUP
# ===========================
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PINPOINT_SCRIPT = str(SCRIPT_DIR / PINPOINT_SCRIPT_NAME)

# Derive list paths relative to script location
CENSORED_FILE_PATH   = str(SCRIPT_DIR / CENSORED_FILE_NAME)
UNCENSORED_FILE_PATH = str(SCRIPT_DIR / UNCENSORED_FILE_NAME)

os.makedirs(RESULTS_ROOT, exist_ok=True)
os.makedirs(LOGS_ROOT, exist_ok=True)

log = logging.getLogger("disguiser_runner")
log.setLevel(logging.INFO)
_fh = logging.FileHandler(os.path.join(LOGS_ROOT, "disguiser_runner.log"))
_fh.setLevel(logging.INFO)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_fh)
_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("%(message)s"))
log.addHandler(_ch)

# Example printed line from pinpoint_censor.py:
#   ttl = 7     {'timestamp': 169..., 'status': 'success', 'is_timeout': False, 'device': '1.2.3.4', ...}
TTL_LINE_RE   = re.compile(r"^\s*ttl\s*=\s*(\d+)\s*\t\s*(\{.*\})\s*$")
RCODE_ENUM_RE = re.compile(r"<Rcode\.[A-Z_]+:\s*(\d+)>")

def sanitize_payload_str(s: str) -> str:
    # Convert Dnspython enum reprs like "<Rcode.NOERROR: 0>" -> "0"
    return RCODE_ENUM_RE.sub(r"\1", s)

def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return s.strip("._-") or "unnamed"

def load_domains(path):
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            d = line.strip()
            if not d or d.startswith("#"):
                continue
            out.append(d)
    return out

def parse_ttl_line(line):
    """Parse a 'ttl = N \\t {dict}' line into (ttl:int, payload:dict)."""
    m = TTL_LINE_RE.match(line)
    if not m:
        return None, None
    ttl = int(m.group(1))
    raw = sanitize_payload_str(m.group(2))
    try:
        payload = ast.literal_eval(raw)
        if not isinstance(payload, dict):
            return ttl, None
        return ttl, payload
    except Exception:
        return ttl, None

def resolve_first_a(domain: str) -> Optional[str]:
    """Return first IPv4 address for domain, or None."""
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for fam, _stype, _proto, _canon, sockaddr in infos:
            if fam == socket.AF_INET:
                return sockaddr[0]
    except Exception:
        return None
    return None

def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def run_probe(protocol, domain, configured_server):
    """
    Run pinpoint_censor.py for (protocol, domain, server).
    Return dict with:
      ok, t_start, t_end, stdout_lines, stderr, hops(list), final(dict), completed(bool), last_device(str|None)
    """
    # Resolve HTTP/SNI server per domain when requested
    server = configured_server
    if server == "RESOLVE" and protocol in ("http", "sni"):
        resolved = resolve_first_a(domain)
        if not resolved:
            return {
                "ok": False, "t_start": time.time(), "t_end": time.time(),
                "stdout_lines": [], "stderr": "resolve_failed", "hops": [],
                "final": {}, "completed": False, "last_device": None
            }
        server = resolved

    # Optional preflight checks to fail fast with clear error
    if protocol == "dns":
        if not tcp_reachable(server, 53, timeout=2.0):
            return {
                "ok": False, "t_start": time.time(), "t_end": time.time(),
                "stdout_lines": [], "stderr": "dns_target_unreachable", "hops": [],
                "final": {}, "completed": False, "last_device": None
            }
    elif protocol == "http":
        if not tcp_reachable(server, 80, timeout=2.0):
            return {
                "ok": False, "t_start": time.time(), "t_end": time.time(),
                "stdout_lines": [], "stderr": "http_target_unreachable", "hops": [],
                "final": {}, "completed": False, "last_device": None
            }
    elif protocol == "sni":
        if not tcp_reachable(server, 443, timeout=2.0):
            return {
                "ok": False, "t_start": time.time(), "t_end": time.time(),
                "stdout_lines": [], "stderr": "sni_target_unreachable", "hops": [],
                "final": {}, "completed": False, "last_device": None
            }

    cmd = [
        sys.executable if sys.executable else "python3",
        PINPOINT_SCRIPT,
        protocol, domain, server, str(TTL_LOW), str(TTL_HIGH),
    ]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            cwd=str(SCRIPT_DIR),  # ensure relative paths resolve consistently
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "t_start": t0, "t_end": time.time(),
                "stdout_lines": [], "stderr": "timeout", "hops": [], "final": {}, "completed": False, "last_device": None}
    except Exception as e:
        return {"ok": False, "t_start": t0, "t_end": time.time(),
                "stdout_lines": [], "stderr": str(e), "hops": [], "final": {}, "completed": False, "last_device": None}

    t1 = time.time()
    stdout_lines = proc.stdout.splitlines()
    stderr = proc.stderr

    hops = []
    final_payload = {}
    for line in stdout_lines:
        ttl, payload = parse_ttl_line(line)
        if ttl is None or payload is None:
            continue
        hops.append({"ttl": ttl, **payload})
        final_payload = payload  # last parsed payload

    ok = (proc.returncode == 0)
    completed = isinstance(final_payload, dict) and (final_payload.get("is_timeout") is False)
    last_device = final_payload.get("device") if isinstance(final_payload, dict) else None

    return {
        "ok": ok,
        "t_start": t0,
        "t_end": t1,
        "stdout_lines": stdout_lines,
        "stderr": stderr,
        "hops": hops,
        "final": final_payload,
        "completed": completed,
        "last_device": last_device,
    }

def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def append_jsonl(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def process_list(list_path):
    """
    Run all protocols for all domains in list_path.
    Creates:
      results/<basename>_csep/summary.jsonl
      results/<basename>_csep/<domain>/... per protocol and aggregate.json
    """
    basename = pathlib.Path(list_path).stem
    root_out = os.path.join(RESULTS_ROOT, f"{basename}_csep")
    summary_path = os.path.join(root_out, "summary.jsonl")

    domains = load_domains(list_path)
    if not domains:
        log.info(f"[{basename}] No domains found or file missing: {list_path}")
        return

    log.info(f"[{basename}] Domains: {len(domains)}  -> {root_out}")

    for domain in domains:
        dom_slug = slugify(domain)
        dom_dir = os.path.join(root_out, dom_slug)

        per_domain_agg = {
            "domain": domain,
            "ts": int(time.time()),
            "protocols": {},
        }

        for proto, conf in PROTOCOLS.items():
            configured_server = conf["server"]

            # For logging, show the resolved server if dynamic
            if configured_server == "RESOLVE" and proto in ("http", "sni"):
                server_for_log = resolve_first_a(domain) or "RESOLVE_FAILED"
            else:
                server_for_log = configured_server

            log.info(f"[{basename}] RUN  proto={proto} domain={domain} server={server_for_log}")

            res = run_probe(proto, domain, configured_server)

            # Save raw stdout and hops JSON
            stdout_file = os.path.join(dom_dir, f"{proto}_stdout.txt")
            hops_file   = os.path.join(dom_dir, f"{proto}_hops.json")
            final_file  = os.path.join(dom_dir, f"{proto}_final.json")

            write_text(stdout_file, "\n".join(res["stdout_lines"]))
            write_json(hops_file, res["hops"])
            write_json(final_file, res["final"] if isinstance(res["final"], dict) else {"note": "no_final"})

            # Per-protocol record for domain aggregate
            per_domain_agg["protocols"][proto] = {
                "server": server_for_log,
                "ok": res["ok"],
                "completed": res["completed"],
                "last_device": res["last_device"],
                "runtime_s": round(res["t_end"] - res["t_start"], 3),
                "hops_count": len(res["hops"]),
                "stderr": res.get("stderr", ""),
            }

            # Single line to global summary.jsonl
            summary_record = {
                "ts": int(time.time()),
                "list_file": basename,
                "domain": domain,
                "protocol": proto,
                "server": server_for_log,
                "ok": res["ok"],
                "completed": res["completed"],
                "last_device": res["last_device"],
                "runtime_s": round(res["t_end"] - res["t_start"], 3),
                "hops_count": len(res["hops"]),
            }
            append_jsonl(summary_path, summary_record)

            time.sleep(SLEEP_BETWEEN_RUNS)

        # Write per-domain aggregate
        write_json(os.path.join(dom_dir, "aggregate.json"), per_domain_agg)

def main():
    any_run = False

    if USE_CENSORED_LIST and os.path.isfile(CENSORED_FILE_PATH):
        process_list(CENSORED_FILE_PATH)
        any_run = True
    elif USE_CENSORED_LIST:
        log.warning(f"Missing file: {CENSORED_FILE_PATH}")

    if USE_UNCENSORED_LIST and os.path.isfile(UNCENSORED_FILE_PATH):
        process_list(UNCENSORED_FILE_PATH)
        any_run = True
    elif USE_UNCENSORED_LIST:
        log.warning(f"Missing file: {UNCENSORED_FILE_PATH}")

    if not any_run:
        log.error("No work executed. Check config flags and file presence.")
        sys.exit(1)

    log.info("All done.")

if __name__ == "__main__":
    main()
