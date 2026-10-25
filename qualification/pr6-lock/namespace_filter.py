"""Trusted host adapter. Only main() may execute host namespace tools.

Never enter the target mount/user/PID namespaces. The held network-namespace FD
survives nsenter exec and removes /proc/PID reuse from the tool invocation path.
No dependency process or gate-release action is implemented in this helper.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from egress_policy import (TABLE, Refusal, address, canonical, compile_rules,
                           exact_keys, local_addresses, validate_policy, verify_readback)

def unique_json(text):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Refusal("Duplicate JSON key")
            out[key] = value
        return out
    return json.loads(text, object_pairs_hook=pairs)

def pinned_json(path, expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise Refusal("Expected SHA256 required")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.resolve() != path.absolute():
        raise Refusal("Regular canonical pinned file required")
    data = path.read_bytes()
    if len(data) > 65536 or hashlib.sha256(data).hexdigest() != expected:
        raise Refusal("Input pin mismatch")
    return unique_json(data)

def verify_tools(binding):
    exact_keys(binding, {"schemaVersion", "tools"})
    if binding["schemaVersion"] != 1:
        raise Refusal("Unsupported tool binding")
    exact_keys(binding["tools"], {"nsenter", "nft", "ip"})
    paths = {}
    for name, row in binding["tools"].items():
        exact_keys(row, {"path", "sha256"})
        path = Path(row["path"])
        if not path.is_absolute() or path.resolve() != path or path.parent not in {Path("/usr/bin"), Path("/usr/sbin")}:
            raise Refusal("Canonical host tool path required")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
            raise Refusal("Unsafe host tool ownership/mode")
        content = path.read_bytes()
        if not content.startswith(b"\x7fELF") or hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise Refusal("Host ELF tool pin mismatch")
        paths[name] = str(path)
    return paths

def route_addresses(document):
    if not isinstance(document, list):
        raise Refusal("Unsupported route inventory")
    values = set()
    for row in document:
        if not isinstance(row, dict) or "dst" not in row or any(k in row for k in {"nexthops", "nhid", "via"}):
            raise Refusal("Unsupported route shape")
        if "gateway" in row:
            values.add(str(address(row["gateway"])))
    return values

def verify_tables(document, *, installed=False):
    exact_keys(document, {"nftables"})
    metadata = False
    if not isinstance(document["nftables"], list):
        raise Refusal("Unsupported table inventory")
    tables = []
    for item in document["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            raise Refusal("Unsupported table inventory")
        if "metainfo" in item:
            if metadata or item["metainfo"].get("json_schema_version") != 1:
                raise Refusal("Unsupported table schema")
            metadata = True
        elif "table" in item:
            value = item["table"]
            if not isinstance(value, dict) or not {"family", "name"} <= value.keys():
                raise Refusal("Invalid table inventory")
            tables.append((value["family"], value["name"]))
        else:
            raise Refusal("Unexpected table inventory object")
    if not metadata:
        raise Refusal("No nft schema metadata")
    if tables != ([("inet", TABLE)] if installed else []):
        raise Refusal("Unexpected existing tables; no unknown NAT/filter coexistence or replacement")

def apply_and_verify(policy, tools, fd, run, now, *, phase_seconds):
    """Injectable command boundary for hermetic tests; never releases a workload."""
    prefix = [tools["nsenter"], "--net=/proc/self/fd/" + str(fd), "--"]
    def query(argv, namespace=False):
        return unique_json(run((prefix if namespace else []) + argv, None))
    denied = set()
    for namespace in (False, True):
        denied |= local_addresses(query([tools["ip"], "-j", "address", "show"], namespace))
        for family in ("-4", "-6"):
            denied |= route_addresses(query([tools["ip"], "-j", family, "route", "show", "table", "all"], namespace))
    addresses = validate_policy(policy, now(), denied, phase_seconds=phase_seconds)
    verify_tables(query([tools["nft"], "-j", "-n", "list", "tables"], True))
    batch = canonical(compile_rules(addresses)) + "\n"
    run(prefix + [tools["nft"], "-j", "-f", "-"], batch)
    result = verify_readback(query([tools["nft"], "-j", "-n", "list", "table", "inet", TABLE], True), addresses)
    verify_tables(query([tools["nft"], "-j", "-n", "list", "tables"], True), installed=True)
    # A slow tool call cannot turn an initially fresh observation into admission.
    validate_policy(policy, now(), denied, phase_seconds=phase_seconds)
    return {**result, "batchSha256": hashlib.sha256(batch.encode()).hexdigest(),
            "hostAndContainerLocalAndGatewayAddressesExcluded": sorted(denied),
            "namespaceEntry": "network-only-held-fd", "sourceCommandExecuted": False,
            "releaseAuthorized": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--namespace-dev", required=True, type=int)
    parser.add_argument("--namespace-inode", required=True, type=int)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--tools", required=True, type=Path)
    parser.add_argument("--tools-sha256", required=True)
    parser.add_argument("--phase-seconds", required=True, type=int)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 1 < args.pid < 2**31:
        raise Refusal("Trusted root host adapter and positive container PID required")
    policy = pinned_json(args.policy, args.policy_sha256)
    binding = pinned_json(args.tools, args.tools_sha256)
    tools = verify_tools(binding)
    fd = os.open(f"/proc/{args.pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        info, host = os.fstat(fd), os.stat("/proc/self/ns/net")
        identity = (info.st_dev, info.st_ino)
        if identity == (host.st_dev, host.st_ino) or identity != (args.namespace_dev, args.namespace_inode):
            raise Refusal("Host/shared or substituted namespace refused")
        def run(argv, data):
            # Empty environment: no Actions/service credentials enter these trusted tools.
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                completed = subprocess.run(argv, input=None if data is None else data.encode(),
                                           stdout=stdout, stderr=stderr, timeout=5, check=False,
                                           pass_fds=(fd,), env={"PATH": "/usr/bin:/usr/sbin:/bin", "LC_ALL": "C"})
                if completed.returncode or stdout.tell() > 1024**2 or stderr.tell() > 65536:
                    raise Refusal("Namespace tool failed or exceeded output bound")
                stdout.seek(0)
                return stdout.read().decode("utf-8", errors="strict")
        result = apply_and_verify(policy, tools, fd, run, lambda: dt.datetime.now(dt.timezone.utc),
                                  phase_seconds=args.phase_seconds)
        after = os.stat(f"/proc/{args.pid}/ns/net")
        if identity != (after.st_dev, after.st_ino):
            raise Refusal("Container namespace changed before receipt")
        result.update({"policySha256": args.policy_sha256, "toolsSha256": args.tools_sha256,
                       "pid": args.pid, "namespaceDevice": info.st_dev, "namespaceInode": info.st_ino})
        # Caller must require exact receipt, revalidate Docker state and pins, then release.
        with args.receipt.open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    finally:
        os.close(fd)

if __name__ == "__main__":
    main()
