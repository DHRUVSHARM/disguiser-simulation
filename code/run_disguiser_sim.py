#!/usr/bin/env python3
# run_disguiser_sim.py

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
USE_CENSORED_LIST   = True
USE_UNCENSORED_LIST = True

CENSORED_FILE_NAME   = "censored_us.txt"
UNCENSORED_FILE_NAME = "uncensored_us.txt"

PINPOINT_SCRIPT_NAME = "pinpoint_censor.py"

# Order matters: DNS first, then HTTP/SNI consume the DNS A record.
PROTOCOLS = [
    ("dns",  {"server": "8.8.8.8"}),
    ("http", {"server": "USE_DNS_IP"}),
    ("sni",  {"server": "USE_DNS_IP"}),
]

TTL_LOW  = 1
TTL_HIGH = 32
SLEEP_BETWEEN_RUNS = 0.15
SUBPROCESS_TIMEOUT = 120

RESULTS_ROOT = "results"
LOGS_ROOT    = "logs"

# ===========================
#       HELPER SETUP
# ===========================
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PINPOINT_SCRIPT = str(SCRIPT_DIR / PINPOINT_SCRIPT_NAME)

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

TTL_LINE_RE   = re.compile(r"^\s*ttl\s*=\s*(\d+)\s*\t\s*(\{.*\})\s*$")
RCODE_ENUM_RE = re.compile(r"<Rcode\.[A-Z_]+:\s*(\d+)>")

def sanitize_payload_str(s: str) -> str:
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

def empty_failed_result(reason: str, server_for_log: str) -> dict:
    now = time.time()
    return {
        "ok": False,
        "t_start": now,
        "t_end": now,
        "stdout_lines": [],
        "stderr": reason,
        "hops": [],
        "final": {"error": reason},
        "completed": False,
        "last_device": None,
        "server_for_log": server_for_log,
    }

def run_probe(protocol: str, domain: str, server: str) -> dict:
    if protocol == "dns":
        port = 53
        err_tag = "dns_target_unreachable"
    elif protocol == "http":
        port = 80
        err_tag = "http_target_unreachable"
    elif protocol == "sni":
        port = 443
        err_tag = "sni_target_unreachable"
    else:
        return empty_failed_result("unknown_protocol", server)

    if not tcp_reachable(server, port, timeout=2.0):
        return empty_failed_result(err_tag, server)

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
            cwd=str(SCRIPT_DIR),
        )
    except subprocess.TimeoutExpired:
        return empty_failed_result("timeout", server)
    except Exception as e:
        return empty_failed_result(str(e), server)

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
        final_payload = payload

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
        "server_for_log": server,
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

def extract_first_dns_ip_from_hops(hops: list) -> Optional[str]:
    if not hops:
        return None
    last = hops[-1]
    ip_list = last.get("ip_list") or []
    if isinstance(ip_list, list) and ip_list:
        return ip_list[0]
    return None

def process_list(list_path):
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

        dns_ip_cache: Optional[str] = None
        used_fallback = False

        for proto, conf in PROTOCOLS:
            if proto == "dns":
                server_for_log = conf["server"]
                log.info(f"[{basename}] RUN  proto={proto} domain={domain} server={server_for_log}")
                res = run_probe(proto, domain, server_for_log)
                # Persist outputs
                write_text(os.path.join(dom_dir, f"{proto}_stdout.txt"), "\n".join(res.get("stdout_lines", [])))
                write_json(os.path.join(dom_dir, f"{proto}_hops.json"), res.get("hops", []))
                write_json(os.path.join(dom_dir, f"{proto}_final.json"), res.get("final", {}))

                dns_ip_cache = extract_first_dns_ip_from_hops(res.get("hops", []))
                if not dns_ip_cache:
                    # Fallback: try local resolver
                    dns_ip_cache = resolve_first_a(domain)
                    used_fallback = bool(dns_ip_cache)
                    if used_fallback:
                        log.info(f"[{basename}] DNS had no ip_list; used local resolver -> {dns_ip_cache}")
                    else:
                        log.info(f"[{basename}] DNS had no ip_list; local resolver also failed")

                per_domain_agg["protocols"][proto] = {
                    "server": server_for_log,
                    "ok": res.get("ok", False),
                    "completed": res.get("completed", False),
                    "last_device": res.get("last_device"),
                    "runtime_s": round(res.get("t_end", time.time()) - res.get("t_start", time.time()), 3),
                    "hops_count": len(res.get("hops", [])),
                    "stderr": res.get("stderr", ""),
                }

                append_jsonl(summary_path, {
                    "ts": int(time.time()),
                    "list_file": basename,
                    "domain": domain,
                    "protocol": proto,
                    "server": server_for_log,
                    "ok": res.get("ok", False),
                    "completed": res.get("completed", False),
                    "last_device": res.get("last_device"),
                    "runtime_s": round(res.get("t_end", time.time()) - res.get("t_start", time.time()), 3),
                    "hops_count": len(res.get("hops", [])),
                })

                time.sleep(SLEEP_BETWEEN_RUNS)
                continue

            # HTTP / SNI
            if conf["server"] == "USE_DNS_IP":
                if dns_ip_cache:
                    server_for_log = dns_ip_cache
                    log.info(f"[{basename}] RUN  proto={proto} domain={domain} server={server_for_log} (from DNS{', fallback' if used_fallback else ''})")
                    res = run_probe(proto, domain, server_for_log)
                else:
                    server_for_log = "RESOLVE_FAILED"
                    log.info(f"[{basename}] RUN  proto={proto} domain={domain} server=RESOLVE_FAILED (no DNS IP, no fallback)")
                    res = empty_failed_result("resolve_failed_no_dns_ip", server_for_log)
            else:
                server_for_log = conf["server"]
                log.info(f"[{basename}] RUN  proto={proto} domain={domain} server={server_for_log}")
                res = run_probe(proto, domain, server_for_log)

            # Persist outputs
            write_text(os.path.join(dom_dir, f"{proto}_stdout.txt"), "\n".join(res.get("stdout_lines", [])))
            write_json(os.path.join(dom_dir, f"{proto}_hops.json"), res.get("hops", []))
            final_payload = res.get("final", {})
            write_json(os.path.join(dom_dir, f"{proto}_final.json"),
                       final_payload if isinstance(final_payload, dict) else {"note": "no_final"})

            per_domain_agg["protocols"][proto] = {
                "server": server_for_log,
                "ok": res.get("ok", False),
                "completed": res.get("completed", False),
                "last_device": res.get("last_device"),
                "runtime_s": round(res.get("t_end", time.time()) - res.get("t_start", time.time()), 3),
                "hops_count": len(res.get("hops", [])),
                "stderr": res.get("stderr", ""),
            }

            append_jsonl(summary_path, {
                "ts": int(time.time()),
                "list_file": basename,
                "domain": domain,
                "protocol": proto,
                "server": server_for_log,
                "ok": res.get("ok", False),
                "completed": res.get("completed", False),
                "last_device": res.get("last_device"),
                "runtime_s": round(res.get("t_end", time.time()) - res.get("t_start", time.time()), 3),
                "hops_count": len(res.get("hops", [])),
            })

            time.sleep(SLEEP_BETWEEN_RUNS)

        # Domain aggregate (+ note if fallback used)
        if used_fallback:
            per_domain_agg["note"] = "http/sni used local resolver fallback"
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
