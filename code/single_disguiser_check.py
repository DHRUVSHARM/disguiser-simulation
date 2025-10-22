#!/usr/bin/env python3
import os, sys, time, json, re, ast, socket, subprocess, pathlib

# Config defaults
TTL_LOW  = 1
TTL_HIGH = 32
SUBPROCESS_TIMEOUT = 120
RESULTS_ROOT = "results"

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PINPOINT = str(SCRIPT_DIR / "pinpoint_censor.py")

TTL_LINE_RE = re.compile(r"^\s*ttl\s*=\s*(\d+)\s*\t\s*(\{.*\})\s*$")

def slugify(s: str) -> str:
    import re
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s.strip())
    return s.strip("._-") or "unnamed"

def resolve_first_a(domain: str) -> str or None:
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for fam, _type, _proto, _canon, sockaddr in infos:
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

def parse_ttl_line(line: str):
    m = TTL_LINE_RE.match(line)
    if not m:
        return None, None
    ttl = int(m.group(1))
    try:
        payload = ast.literal_eval(m.group(2))
        if not isinstance(payload, dict):
            return ttl, None
        return ttl, payload
    except Exception:
        return ttl, None

def run_probe(protocol: str, domain: str, server: str):
    cmd = [sys.executable or "python3", PINPOINT, protocol, domain, server, str(TTL_LOW), str(TTL_HIGH)]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=SUBPROCESS_TIMEOUT, cwd=str(SCRIPT_DIR)
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "t_start": t0, "t_end": time.time(), "stderr": "timeout", "stdout": "", "hops": [], "final": {}}
    except Exception as e:
        return {"ok": False, "t_start": t0, "t_end": time.time(), "stderr": str(e), "stdout": "", "hops": [], "final": {}}

    stdout_lines = proc.stdout.splitlines()
    hops, final_payload = [], {}
    for line in stdout_lines:
        ttl, payload = parse_ttl_line(line)
        if ttl is None or payload is None:
            continue
        hops.append({"ttl": ttl, **payload})
        final_payload = payload

    return {
        "ok": (proc.returncode == 0),
        "t_start": t0, "t_end": time.time(),
        "stderr": proc.stderr, "stdout": proc.stdout,
        "hops": hops, "final": final_payload
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: single_disguiser_check.py <domain> [ttl_low] [ttl_high] [protocols]")
        print("  protocols: comma-separated subset of dns,http,sni (default: dns,http,sni)")
        sys.exit(1)

    domain = sys.argv[1].strip()
    ttl_low  = int(sys.argv[2]) if len(sys.argv) >= 3 else TTL_LOW
    ttl_high = int(sys.argv[3]) if len(sys.argv) >= 4 else TTL_HIGH
    if ttl_low != TTL_LOW: globals()["TTL_LOW"] = ttl_low
    if ttl_high != TTL_HIGH: globals()["TTL_HIGH"] = ttl_high

    protos = ["dns","http","sni"]
    if len(sys.argv) >= 5:
        protos = [p.strip() for p in sys.argv[4].split(",") if p.strip()]

    dom_slug = slugify(domain)
    out_dir = os.path.join(RESULTS_ROOT, f"single_{dom_slug}")
    os.makedirs(out_dir, exist_ok=True)

    # DNS target is fixed (TCP/53 to 8.8.8.8)
    targets = {
        "dns": {"server": "8.8.8.8"},
        "http": {"server": "RESOLVE"},
        "sni": {"server": "RESOLVE"},
    }

    summary = {"domain": domain, "ts": int(time.time()), "ttl_low": TTL_LOW, "ttl_high": TTL_HIGH, "protocols": {}}

    for proto in protos:
        if proto not in ("dns","http","sni"):
            print(f"Skip unknown proto: {proto}")
            continue

        # Resolve per-domain server for http/sni
        configured = targets[proto]["server"]
        if configured == "RESOLVE":
            ip = resolve_first_a(domain)
            if not ip:
                print(f"[{proto}] resolve_failed for {domain}")
                summary["protocols"][proto] = {"server": "RESOLVE_FAILED", "ok": False, "completed": False, "stderr": "resolve_failed"}
                continue
            server = ip
        else:
            server = configured

        # Preflight reachability
        if proto == "dns" and not tcp_reachable(server, 53, 2.0):
            print(f"[dns] {server}:53 unreachable")
            summary["protocols"][proto] = {"server": server, "ok": False, "completed": False, "stderr": "dns_target_unreachable"}
            continue
        if proto == "http" and not tcp_reachable(server, 80, 2.0):
            print(f"[http] {server}:80 unreachable")
            summary["protocols"][proto] = {"server": server, "ok": False, "completed": False, "stderr": "http_target_unreachable"}
            continue
        if proto == "sni" and not tcp_reachable(server, 443, 2.0):
            print(f"[sni] {server}:443 unreachable")
            summary["protocols"][proto] = {"server": server, "ok": False, "completed": False, "stderr": "sni_target_unreachable"}
            continue

        print(f"RUN {proto}: domain={domain} server={server} ttl=[{TTL_LOW},{TTL_HIGH}]")
        res = run_probe(proto, domain, server)

        # Save artifacts
        with open(os.path.join(out_dir, f"{proto}_stdout.txt"), "w", encoding="utf-8") as f:
            f.write(res["stdout"])
        with open(os.path.join(out_dir, f"{proto}_hops.json"), "w", encoding="utf-8") as f:
            json.dump(res["hops"], f, ensure_ascii=False, indent=2)
        with open(os.path.join(out_dir, f"{proto}_final.json"), "w", encoding="utf-8") as f:
            json.dump(res["final"] if isinstance(res["final"], dict) else {}, f, ensure_ascii=False, indent=2)

        completed = isinstance(res["final"], dict) and (res["final"].get("is_timeout") is False)
        last_device = res["final"].get("device") if isinstance(res["final"], dict) else None

        summary["protocols"][proto] = {
            "server": server,
            "ok": res["ok"],
            "completed": completed,
            "last_device": last_device,
            "runtime_s": round(res["t_end"] - res["t_start"], 3),
            "hops_count": len(res["hops"]),
            "stderr": res.get("stderr", ""),
        }

        # Console summary per proto
        print(f"{proto.upper()} ok={res['ok']} completed={completed} hops={len(res['hops'])} last_device={last_device}")

    with open(os.path.join(out_dir, "aggregate.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("Saved:", os.path.join(out_dir, "aggregate.json"))

if __name__ == "__main__":
    main()
