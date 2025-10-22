#!/usr/bin/env python3
# single_disguiser_check.py
#
# Quick single-domain runner for pinpoint_censor.py with robust parsing and
# per-domain HTTP/SNI resolution. Writes results under:
#   results/single_<domain>/{dns,http,sni}_stdout.txt|_hops.json|_final.json and aggregate.json

import os
import sys
import json
import time
import re
import ast
import socket
import subprocess
from typing import Optional

PINPOINT = "pinpoint_censor.py"
RESULTS_ROOT = "results"
TTL_LOW  = 1
TTL_HIGH = 32
TIMEOUT  = 120  # subprocess timeout

TTL_LINE_RE   = re.compile(r"^\s*ttl\s*=\s*(\d+)\s*\t\s*(\{.*\})\s*$")
RCODE_ENUM_RE = re.compile(r"<Rcode\.[A-Z_]+:\s*(\d+)>")

def sanitize_payload_str(s: str) -> str:
    return RCODE_ENUM_RE.sub(r"\1", s)

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

def run_one(protocol: str, domain: str, server_hint: Optional[str]) -> dict:
    server = server_hint
    if protocol in ("http", "sni"):
        if server is None or server == "RESOLVE":
            server = resolve_first_a(domain)
            if not server:
                return {"ok": False, "stdout": "", "stderr": "resolve_failed", "hops": [], "final": {}, "completed": False, "last_device": None}

    # preflight TCP reachability
    if protocol == "dns":
        if not tcp_reachable(server, 53, 2.0):
            return {"ok": False, "stdout": "", "stderr": "dns_target_unreachable", "hops": [], "final": {}, "completed": False, "last_device": None}
    elif protocol == "http":
        if not tcp_reachable(server, 80, 2.0):
            return {"ok": False, "stdout": "", "stderr": "http_target_unreachable", "hops": [], "final": {}, "completed": False, "last_device": None}
    elif protocol == "sni":
        if not tcp_reachable(server, 443, 2.0):
            return {"ok": False, "stdout": "", "stderr": "sni_target_unreachable", "hops": [], "final": {}, "completed": False, "last_device": None}

    cmd = [sys.executable if sys.executable else "python3", PINPOINT,
           protocol, domain, server, str(TTL_LOW), str(TTL_HIGH)]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timeout", "hops": [], "final": {}, "completed": False, "last_device": None}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e), "hops": [], "final": {}, "completed": False, "last_device": None}
    t1 = time.time()

    stdout_lines = p.stdout.splitlines()
    hops = []
    final_payload = {}
    for line in stdout_lines:
        ttl, payload = parse_ttl_line(line)
        if ttl is None or payload is None:
            continue
        hops.append({"ttl": ttl, **payload})
        final_payload = payload

    ok = (p.returncode == 0)
    completed = isinstance(final_payload, dict) and (final_payload.get("is_timeout") is False)
    last_device = final_payload.get("device") if isinstance(final_payload, dict) else None

    return {
        "ok": ok,
        "stdout": p.stdout,
        "stderr": p.stderr,
        "hops": hops,
        "final": final_payload,
        "completed": completed,
        "last_device": last_device,
        "runtime_s": round(t1 - t0, 3),
    }

def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def main():
    if len(sys.argv) < 2:
        print("Usage: single_disguiser_check.py <domain> [ttl_low ttl_high protocols]")
        print("  protocols: comma-separated subset of dns,http,sni (default: all)")
        sys.exit(1)

    domain   = sys.argv[1].strip()
    ttl_low  = int(sys.argv[2]) if len(sys.argv) >= 3 else TTL_LOW
    ttl_high = int(sys.argv[3]) if len(sys.argv) >= 4 else TTL_HIGH
    prolist  = sys.argv[4].split(",") if len(sys.argv) >= 5 else ["dns", "http", "sni"]

    # override globals if user provided bounds
    global TTL_LOW, TTL_HIGH
    TTL_LOW, TTL_HIGH = ttl_low, ttl_high

    out_dir = os.path.join(RESULTS_ROOT, f"single_{domain}")
    os.makedirs(out_dir, exist_ok=True)

    # DNS server fixed; HTTP/SNI resolved per domain
    plan = {
        "dns":  {"server": "8.8.8.8"},
        "http": {"server": "RESOLVE"},
        "sni":  {"server": "RESOLVE"},
    }

    aggregate = {"domain": domain, "ts": int(time.time()), "protocols": {}}

    for proto in prolist:
        if proto not in plan:
            continue
        server_hint = plan[proto]["server"]
        if server_hint == "RESOLVE":
            server_log = resolve_first_a(domain) or "RESOLVE_FAILED"
        else:
            server_log = server_hint

        print(f"RUN {proto}: domain={domain} server={server_log} ttl=[{TTL_LOW},{TTL_HIGH}]")
        res = run_one(proto, domain, server_hint)

        write_text(os.path.join(out_dir, f"{proto}_stdout.txt"), res["stdout"])
        write_json(os.path.join(out_dir, f"{proto}_hops.json"), res["hops"])
        write_json(os.path.join(out_dir, f"{proto}_final.json"), res["final"] if isinstance(res["final"], dict) else {"note": "no_final"})

        aggregate["protocols"][proto] = {
            "server": server_log,
            "ok": res["ok"],
            "completed": res["completed"],
            "last_device": res["last_device"],
            "runtime_s": res.get("runtime_s", None),
            "hops_count": len(res["hops"]),
            "stderr": res.get("stderr", ""),
        }

        print(f"{proto.upper()} ok={res['ok']} completed={res['completed']} hops={len(res['hops'])} last_device={res['last_device']}")

    write_json(os.path.join(out_dir, "aggregate.json"), aggregate)
    print(f"Saved: {os.path.join(out_dir, 'aggregate.json')}")

if __name__ == "__main__":
    main()
