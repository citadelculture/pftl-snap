"""Pure boundary-probe decisions. No command, DNS, container or package execution."""
import hashlib
import ipaddress
import json
import re

IMAGE = "node@sha256:51b1100cc2a83d370c6a60952e3f2989c8a43159d0e38586e090f3b3326efefd"
HELPERS = {"egress_policy.py": "082262d5c3dd69a9411978225e94212ac83049f01417649dc92ca4cbdf0fad9c",
           "namespace_filter.py": "139e87b4851ed8e18e09c29fa4b499f397c6d5b7a91a0a04e6420593a699be3e"}
PHASE_SECONDS = 150
MAX_OUTPUT = 1024 * 1024

class Refusal(ValueError):
    pass

def controls(environment):
    return {key: value for key, value in environment.items()
            if key == "CODEX_SANDBOX" or key.startswith("CODEX_SANDBOX_")}

def controls_sha(environment):
    return hashlib.sha256(json.dumps(controls(environment), sort_keys=True,
                                    separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def check_environment(environment):
    if any(key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
           or key.startswith("DOCKER_") for key in environment):
        raise Refusal("Inherited proxy or Docker routing/TLS/context control requires explicit resolution")
    if environment.get("NODE_OPTIONS", "").strip():
        raise Refusal("Nonempty inherited NODE_OPTIONS refused")
    for key, value in controls(environment).items():
        if not re.fullmatch(r"CODEX_SANDBOX(?:_[A-Z0-9_]+)?", key):
            raise Refusal("Unsupported control name")
        if "NETWORK" in key and value.strip().lower() not in {"", "0", "false", "no", "off"}:
            raise Refusal("Inherited network restriction or unrecognized network control refused")

def child_environment(environment):
    check_environment(environment)
    return {"HOME": "/home/node", "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8", "CI": "true", **controls(environment)}

def probe_plan(public_address, gateway):
    public, private = ipaddress.ip_address(public_address), ipaddress.ip_address(gateway)
    if public.version != 4 or not public.is_global or public.is_reserved:
        raise Refusal("Public IPv4 positive control required")
    if private.version != 4 or private.is_global or private.is_loopback:
        raise Refusal("Private container gateway required")
    rows = [
        ("public_443", "tcp", str(public), 443, True),
        ("public_wrong_port", "tcp", str(public), 80, False),
        ("public_udp_443", "udp", str(public), 443, False),
        ("dns_udp", "udp", "1.1.1.1", 53, False),
        ("dns_tcp", "tcp", "1.1.1.1", 53, False),
        ("loopback_tcp", "tcp", "127.0.0.1", 443, False),
        ("loopback_udp", "udp", "127.0.0.1", 53, False),
        ("host_gateway", "tcp", str(private), 443, False),
        ("private_ipv4", "tcp", "10.255.255.254", 443, False),
        ("metadata_ipv4", "tcp", "169.254.169.254", 80, False),
        ("azure_platform", "tcp", "168.63.129.16", 443, False),
        ("ipv6_loopback_tcp", "tcp", "::1", 443, False),
        ("ipv6_loopback_udp", "udp", "::1", 53, False),
    ]
    return [{"id": name, "operation": op, "address": address, "port": port,
             "positive": positive} for name, op, address, port, positive in rows]

def assess_probe(case, result, before, after):
    if any(result.get(key) != case[key] for key in ("id", "operation", "address", "port")):
        raise Refusal("Probe response does not match exact commanded operation")
    if result.get("event") != "result" or result.get("outcome") not in {"connected", "sent", "error", "timeout"}:
        raise Refusal("Unsupported probe response")
    if result["outcome"] == "sent" and case["operation"] != "udp" or result["outcome"] == "connected" and case["operation"] != "tcp":
        raise Refusal("Probe outcome does not match transport")
    for counter in (before, after):
        if set(counter) != {"packets", "bytes"} or any(type(v) is not int or v < 0 for v in counter.values()):
            raise Refusal("Invalid actual kernel counter")
    delta = {key: after[key] - before[key] for key in before}
    if min(delta.values()) < 0:
        raise Refusal("Kernel counter regressed")
    if case["positive"]:
        passed = result["outcome"] == "connected" and delta == {"packets": 0, "bytes": 0}
        evidence = "actual public TCP443 connect" if passed else "public positive control did not connect"
    else:
        passed = result["outcome"] != "connected" and delta["packets"] > 0 and delta["bytes"] > 0
        evidence = "correlated kernel drop counter increase" if passed else "no sufficient correlated kernel denial evidence"
    return {"id": case["id"], "positive": case["positive"], "actual": result,
            "counterBefore": before, "counterAfter": after, "counterDelta": delta,
            "passed": passed, "evidence": evidence}

def confinement_result(ready_valid, probes, final_filter_valid, cleanup_valid,
                       workload_completed, source_pins_preserved):
    return (ready_valid is True and len(probes) == 13
            and all(row.get("passed") is True for row in probes)
            and final_filter_valid is True and cleanup_valid is True
            and workload_completed is True and source_pins_preserved is True)
