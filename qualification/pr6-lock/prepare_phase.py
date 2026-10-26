"""Trusted phase preparation; no packages or compiler provisioning.
Functions derive from the frozen boundary controller; full install calls these
before each independently bounded phase, never reusing an expired observation.
"""

import re

import datetime as dt

import hashlib

import json

import shutil

from pathlib import Path

import stat

import subprocess

import tempfile

from egress_policy import HEAD, HOSTS, PAYLOAD_SHA

from namespace_filter import Refusal, unique_json, verify_tools

from boundary_contract import check_environment

HOST_ENV = {"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "LC_ALL": "C"}

MAX_OUTPUT = 1024 * 1024

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class CommandFailure(Refusal):
    def __init__(self, argv, code, out, err):
        self.evidence = {"command": Path(argv[0]).name, "exitCode": code,
                         "stdoutBytes": len(out), "stderrBytes": len(err),
                         "stdoutSha256": hashlib.sha256(out).hexdigest(),
                         "stderrSha256": hashlib.sha256(err).hexdigest()}
        super().__init__("Trusted command failed: " + self.evidence["command"] + ":" + str(code))

def bounded(argv, *, timeout=10, env=None, input_text=None):
    # Temporary files bound RAM; output over the explicit bound refuses the run.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(argv, input=None if input_text is None else input_text.encode(),
                                stdout=stdout, stderr=stderr, timeout=timeout,
                                env=HOST_ENV if env is None else env, check=False)
        if stdout.tell() > MAX_OUTPUT or stderr.tell() > 65536:
            raise Refusal("Trusted command output bound exceeded")
        stdout.seek(0); stderr.seek(0)
        out, err = stdout.read(), stderr.read()
    if result.returncode:
        raise CommandFailure(argv, result.returncode, out, err)
    return out.decode("utf8", errors="strict")

def canonical_elf(name):
    found = shutil.which(name, path=HOST_ENV["PATH"])
    if not found:
        raise Refusal("Required host tool absent: " + name)
    path = Path(found).resolve()
    info = path.lstat()
    if path.parent not in {Path("/usr/bin"), Path("/usr/sbin")} or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refusal("Host tool is not a canonical protected root-owned file: " + name)
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise Refusal("Native host ELF tool required: " + name)
    return {"path": str(path), "sha256": digest(path)}

def package_aliases(canonical):
    path = Path(canonical)
    parent = {"/usr/bin": "/bin", "/usr/sbin": "/sbin"}.get(str(path.parent))
    if parent is None:
        raise Refusal("Package lookup requires a canonical system tool path")
    return [str(path), str(Path(parent) / path.name)]

def alias_identity(candidate, row):
    canonical, alias = Path(row["path"]), Path(candidate)
    target = canonical.lstat()
    if (not stat.S_ISREG(target.st_mode) or target.st_uid != 0 or target.st_mode & 0o022
            or digest(canonical) != row["sha256"]):
        raise Refusal("Canonical protected tool changed during package lookup")
    with canonical.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise Refusal("Canonical tool lost its ELF identity")
    try:
        link, actual = alias.lstat(), alias.stat()
        parent = alias.parent.resolve(strict=True)
        parent_info = parent.stat()
        resolved = alias.resolve(strict=True)
    except FileNotFoundError:
        return {"path": candidate, "eligible": False, "reason": "absent"}
    if (candidate not in package_aliases(row["path"]) or resolved != canonical
            or parent != canonical.parent or parent_info.st_uid != 0
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022
            or link.st_uid != 0 or (not stat.S_ISLNK(link.st_mode) and link.st_mode & 0o022)
            or (actual.st_dev, actual.st_ino) != (target.st_dev, target.st_ino)):
        raise Refusal("Package alias is not the same protected canonical tool")
    return {"path": candidate, "eligible": True, "canonicalPath": str(canonical),
            "device": actual.st_dev, "inode": actual.st_ino,
            "sameCanonicalTarget": True, "sameDeviceAndInode": True}

def package_ownership(row, attempts, query=bounded, identify=alias_identity):
    for candidate in package_aliases(row["path"]):
        attempt = identify(candidate, row)
        attempts.append(attempt)
        if not attempt["eligible"]:
            continue
        try:
            output = query(["/usr/bin/dpkg-query", "-S", candidate]).strip()
        except CommandFailure as error:
            attempt["lookup"] = error.evidence
            # dpkg-query -S exit 1 with empty stdout is only a lookup miss.
            if error.evidence["exitCode"] == 1 and error.evidence["stdoutBytes"] == 0:
                continue
            raise
        owners = []
        for line in output.splitlines():
            package, separator, owned_path = line.partition(": ")
            if not separator or owned_path != candidate or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::[a-z0-9][a-z0-9-]*)?", package):
                raise Refusal("Exact package-owned tool path required")
            owners.append(package)
        if not owners or len(owners) != len(set(owners)):
            raise Refusal("Missing or duplicate package ownership record")
        # Detect a target swap after the metadata lookup before accepting it.
        if identify(candidate, row) != {key: value for key, value in attempt.items() if key != "lookup"}:
            raise Refusal("Package-owned tool identity changed during lookup")
        attempt["lookup"] = {"command": "dpkg-query", "exitCode": 0, "exactOwnedPath": True}
        return {"path": candidate, "packages": sorted(owners), "record": output}
    raise Refusal("No exact package-owned alias for protected tool")

def bind_tools(diagnostics):
    tools = {}
    descriptions = {}
    for name in ("nsenter", "nft", "ip"):
        progress = {"tool": name, "phase": "canonical-elf", "status": "pending", "ownershipAttempts": []}
        diagnostics.append(progress)
        try:
            row = canonical_elf(name); tools[name] = row
            progress["canonicalPath"] = row["path"]
            progress["phase"] = "version"
            version = bounded([row["path"], "-Version" if name == "ip" else "--version"]).strip()
            progress["phase"] = "package-ownership"
            ownership = package_ownership(row, progress["ownershipAttempts"])
            progress["phase"] = "package-version"
            versions = bounded(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package} ${Version} ${source:Package} ${source:Version}\\n", *ownership["packages"]]).strip()
            if not versions:
                raise Refusal("Empty installed package version evidence")
            descriptions[name] = {"version": version[:2048], "packageOwnership": ownership,
                                  "packageVersions": versions[:4096], **row}
            progress.update(status="bound", phase="complete")
        except Exception as error:
            progress["status"] = "failed"
            progress["failure"] = error.evidence if isinstance(error, CommandFailure) else {"kind": type(error).__name__}
            raise Refusal("Host tool binding failed: " + name + ":" + progress["phase"]) from error
    binding = {"schemaVersion": 1, "tools": tools}
    verify_tools(binding)
    return binding, descriptions

def fresh_policy():
    observed = dt.datetime.now(dt.timezone.utc)
    values = {}
    code = "import json,socket,sys;print(json.dumps(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_STREAM)})))"
    for host in sorted(HOSTS):
        # Exactly one resolver invocation per fixed hostname; no child DNS is allowed.
        values[host] = unique_json(bounded(["/usr/bin/python3", "-c", code, host], timeout=8))
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    return {"schemaVersion": 1, "head": HEAD, "payloadManifestSha256": PAYLOAD_SHA,
            "observedAtUtc": stamp(observed), "expiresAtUtc": stamp(observed + dt.timedelta(minutes=20)),
            "hosts": values}

def prepare_phase(directory, environment):
    check_environment(environment)
    directory.mkdir(mode=0o700)
    diagnostics = []
    try:
        binding, descriptions = bind_tools(diagnostics)
    except Exception:
        with (directory / "host-tool-binding-failure.json").open("x") as output:
            json.dump({"phase": "host-tool-binding", "toolBindings": diagnostics}, output, indent=2)
            output.write("\n")
        raise
    policy = fresh_policy()
    paths = {}
    for name, value in (("endpoint-policy", policy), ("host-tools", binding), ("host-tool-observations", descriptions), ("host-tool-binding-diagnostics", diagnostics)):
        path = directory / (name + ".json")
        with path.open("x") as output:
            json.dump(value, output, indent=2); output.write("\n")
        paths[name] = {"path": str(path), "sha256": digest(path)}
    return {"policy": policy, "binding": binding, "files": paths,
            "hostToolsProvisioned": False, "nativeCompilerProvisioned": False,
            "toolPinLimit": "Within-run drift pins plus installed package ownership, not externally authenticated binary checksums."}
