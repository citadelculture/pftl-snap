"""Read-only root inspection of one nonce-bound owned gate's network namespace.

No namespace entry, command execution, signal, source read or filesystem write.
The separately pinned namespace filter must independently reopen and revalidate
the returned device/inode before applying its existing policy.
"""
import argparse
import json
import os
from pathlib import Path
import re


def read_limited(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Gate process metadata exceeds bounded read")
    return data


def request_valid(pid, phase, nonce):
    if (type(pid) is not int or not 1 < pid < 2**31
            or phase not in ("immutable", "compiler-identity", "typecheck", "production-build")
            or not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce)):
        raise ValueError("Exact owned gate PID, phase and nonce required")


def process_identity(pid, phase, nonce, read):
    prefix = f"/proc/{pid}"
    command = read(prefix + "/cmdline", 65536).rstrip(b"\0").split(b"\0")
    if command[-4:] != [b"/bin/sh", b"/lane/wait-for-filter.sh", phase.encode(), nonce.encode()]:
        raise ValueError("Process is not the exact nonce-bound trusted gate")
    lines = read(prefix + "/status", 65536).decode("ascii", errors="strict").splitlines()
    uid = [line for line in lines if line.startswith("Uid:")]
    if len(uid) != 1 or not re.fullmatch(r"Uid:[ \t]+1000[ \t]+1000[ \t]+1000[ \t]+1000", uid[0]):
        raise ValueError("Gate real/effective/saved/filesystem UIDs must all be1000")
    value = read(prefix + "/stat", 4096).decode("ascii", errors="strict")
    end = value.rfind(") ")
    if not value.startswith(str(pid) + " (") or end < len(str(pid)) + 2:
        raise ValueError("Malformed gate process identity")
    fields = value[end+2:].split()
    if len(fields) < 20 or not fields[19].isdigit() or int(fields[19]) <= 0:
        raise ValueError("Gate process start time missing")
    return {"pid": pid, "phase": phase, "nonce": nonce, "uid": 1000,
            "startTimeTicks": int(fields[19]), "commandlineMatched": True}


def inspect_gate(pid, phase, nonce, *, read=read_limited, effective_uid=os.geteuid,
                 open_namespace=os.open, fstat=os.fstat, stat_path=os.stat, close_fd=os.close):
    request_valid(pid, phase, nonce)
    if effective_uid() != 0:
        raise ValueError("Read-only namespace identity inspection requires root")
    before = process_identity(pid, phase, nonce, read)
    namespace = f"/proc/{pid}/ns/net"
    fd = open_namespace(namespace, os.O_RDONLY | os.O_CLOEXEC)
    try:
        target, host = fstat(fd), stat_path("/proc/self/ns/net")
        identity = (target.st_dev, target.st_ino)
        if identity == (host.st_dev, host.st_ino):
            raise ValueError("Host/shared network namespace refused")
        if process_identity(pid, phase, nonce, read) != before:
            raise ValueError("Gate PID/start identity changed during inspection")
        after = stat_path(namespace)
        if identity != (after.st_dev, after.st_ino):
            raise ValueError("Gate network namespace changed during inspection")
    finally:
        close_fd(fd)
    return {"schemaVersion": 1, "kind": "owned-gate-network-namespace-identity", **before,
            "namespaceDevice": target.st_dev, "namespaceInode": target.st_ino,
            "heldNamespaceFdClosed": True, "hostNamespaceRefused": True,
            "readOnlyInspection": True, "namespaceEntered": False, "sourceCommandExecuted": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--phase", required=True, choices=("immutable", "compiler-identity", "typecheck", "production-build"))
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    print(json.dumps(inspect_gate(args.pid, args.phase, args.nonce), sort_keys=True))


if __name__ == "__main__":
    main()
