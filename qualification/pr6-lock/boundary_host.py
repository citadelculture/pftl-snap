#!/usr/bin/python3
"""Boundary-only hosted driver. No Yarn, repository JS or dependency command exists."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from boundary_contract import (HELPERS, IMAGE, MAX_OUTPUT, PHASE_SECONDS, Refusal,
                               assess_probe, check_environment, child_environment,
                               confinement_result, controls, controls_sha, probe_plan)

HERE = Path(__file__).resolve().parent
HOST_ENV = {"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "LC_ALL": "C"}
OWNER_LABEL = "org.postfiat.boundary.nonce"

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def failure_label(error, trusted_refusals=()):
    # Helper exception identity is admitted only after its frozen bytes verify.
    if type(error) in (Refusal, CommandFailure, *trusted_refusals):
        message = str(error)
        if len(message) <= 512 and all(32 <= ord(char) < 127 for char in message):
            return message
        return "Trusted refusal message exceeded safe diagnostic shape"
    return type(error).__name__

def namespace_operation(argv, data, paths, fd):
    prefix = [paths["nsenter"], "--net=/proc/self/fd/" + str(fd), "--"]
    child = argv[:3] == prefix
    command = argv[3:] if child else argv
    operations = {
        tuple([paths["ip"], "-j", "address", "show"]): "interface-inventory",
        **{tuple([paths["ip"], "-j", family, "route", "show", "table", "all"]): "route-inventory" for family in ("-4", "-6")},
    }
    if child:
        operations.update({
            (paths["nft"], "-j", "-n", "list", "tables"): "nft-tables",
            (paths["nft"], "-j", "-n", "list", "table", "inet", "pftl_lock_egress"): "nft-owned-table",
            (paths["nft"], "-j", "-f", "-"): "nft-install",
        })
    kind = operations.get(tuple(command))
    if kind is None or len(argv) > 12 or any(not isinstance(arg, str) or len(arg) > 128 for arg in argv):
        raise Refusal("Namespace diagnostic operation is outside fixed tool command set")
    encoded = b"" if data is None else data.encode()
    if (kind == "nft-install") != (data is not None) or len(encoded) > MAX_OUTPUT:
        raise Refusal("Namespace diagnostic stdin shape or bound exceeded")
    return {"argv": list(argv), "scope": "child-network-namespace" if child else "host",
            "operation": kind, "stdinBytes": len(encoded),
            "stdinSha256": hashlib.sha256(encoded).hexdigest()}

def nft_diagnostic(data):
    evidence = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "captured": False}
    if len(data) > 65536:
        return {**evidence, "reason": "nft-diagnostic-byte-bound"}
    keys = {"nftables", "metainfo", "version", "release_name", "json_schema_version", "table", "family", "name", "handle",
            "chain", "type", "hook", "prio", "policy", "rule", "expr", "match", "op", "left", "right", "payload",
            "protocol", "field", "set", "accept", "counter", "packets", "bytes", "drop", "meta", "key"}
    remaining = [4096]
    def inspect(value, depth=0):
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 16:
            raise ValueError()
        if isinstance(value, dict):
            if not set(value) <= keys: raise ValueError()
            for item in value.values(): inspect(item, depth+1)
        elif isinstance(value, list):
            for item in value: inspect(item, depth+1)
        elif isinstance(value, str):
            if len(value) > 128 or any(ord(char) < 32 or ord(char) >= 127 or char in "/\\" for char in value): raise ValueError()
        elif value is not None and type(value) not in (bool, int):
            raise ValueError()
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: raise ValueError()
                result[key] = value
            return result
        document = json.loads(data, object_pairs_hook=pairs)
        if not isinstance(document, dict) or set(document) != {"nftables"} or not isinstance(document["nftables"], list): raise ValueError()
        inspect(document)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return {**evidence, "reason": "nft-diagnostic-unsupported-or-private-shaped-content"}
    return {**evidence, "captured": True, "parsed": document}

def record_namespace_result(report, operation, out, err, code):
    operation.update(exitCode=code, stdoutBytes=len(out), stderrBytes=len(err),
                     stdoutSha256=hashlib.sha256(out).hexdigest(), stderrSha256=hashlib.sha256(err).hexdigest())
    if operation["operation"] in {"nft-tables", "nft-owned-table"}:
        # At most two bounded parsed snapshots; host interfaces/routes are never retained.
        report.setdefault("nftDiagnosticReadbacks", {})[operation["operation"]] = nft_diagnostic(out)

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

def validate_container(document, container_id, nonce, probe_source, expected_env):
    if document.get("Id") != container_id or document.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) != nonce:
        raise Refusal("Owned container identity changed")
    config, host, state = document["Config"], document["HostConfig"], document["State"]
    if config.get("User") != "1000:1000" or config.get("Entrypoint") != ["/usr/local/bin/node"] or config.get("Cmd") != ["/probe.cjs", nonce]:
        raise Refusal("Nonroot exact builtin workload identity mismatch")
    if not state.get("Running") or state.get("Pid", 0) <= 1:
        raise Refusal("Container is not running")
    if (host.get("Privileged") or host.get("ReadonlyRootfs") is not True or host.get("CapDrop") != ["ALL"]
            or host.get("CapAdd") not in (None, []) or host.get("PidMode") not in ("", "private")
            or host.get("IpcMode") != "private" or host.get("NetworkMode") != "bridge"
            or host.get("CgroupnsMode") != "private" or host.get("Runtime") != "runc"
            or host.get("Devices") not in (None, []) or host.get("DeviceRequests") not in (None, [])):
        raise Refusal("Container isolation settings differ from fixed boundary contract")
    options = host.get("SecurityOpt") or []
    if options != ["no-new-privileges"]:
        raise Refusal("Unexpected seccomp/security override")
    if host.get("Memory") != 512 * 1024**2 or host.get("NanoCpus") != 10**9 or host.get("PidsLimit") != 32:
        raise Refusal("Container resource limits changed")
    if host.get("Sysctls") != {"net.ipv6.conf.lo.disable_ipv6": "0"}:
        raise Refusal("Exact disposable namespace-local IPv6 loopback configuration required")
    mounts = document.get("Mounts", [])
    binds = [m for m in mounts if m.get("Type") == "bind"]
    if len(binds) != 1 or binds[0].get("Source") != str(probe_source) or binds[0].get("Destination") != "/probe.cjs" or binds[0].get("RW") is not False:
        raise Refusal("Only exact read-only builtin probe file may be bind-mounted")
    if any(m.get("Type") not in {"bind", "tmpfs"} for m in mounts):
        raise Refusal("Unexpected volume or credential mount")
    expected_tmpfs = {path: "rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700" for path in ("/home/node", "/tmp")}
    if host.get("Tmpfs") != expected_tmpfs:
        raise Refusal("Only bounded disposable home/tmp tmpfs mounts expected")
    env = {}
    for item in config.get("Env", []):
        key, value = item.split("=", 1)
        if key in env:
            raise Refusal("Duplicate container environment key")
        env[key] = value
    if env != {"NODE_VERSION": "24.21.0", "YARN_VERSION": "1.22.22", **expected_env}:
        raise Refusal("Container environment differs from exact safe image/control contract")
    gateway = document["NetworkSettings"]["Networks"]["bridge"]["Gateway"]
    return state["Pid"], gateway

def validate_ready(value, nonce, expected_controls_sha):
    expected = {"event": "ready", "nonce": nonce, "uid": 1000, "gid": 1000,
                "accountUid": 1000, "accountGid": 1000, "accountHome": "/home/node",
                "homeMatchesRealAccount": True, "canaryRoundTrip": True,
                **{key: "0000000000000000" for key in ("capInh", "capPrm", "capEff", "capBnd", "capAmb")},
                "noNewPrivs": "1", "seccomp": "2",
                "controlsSha256": expected_controls_sha, "unexpectedEnvironmentCount": 0,
                "dockerSocketStat": "absent", "nodeVersion": "24.21.0", "platform": "linux", "arch": "x64"}
    if value != expected:
        raise Refusal("Builtin ready event does not establish exact account/control/isolation facts")
    return True

class Events:
    def __init__(self, process):
        self.process = process
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        self.buffer = b""
        self.total = 0
        self.stderr_bytes = b""
    def receive(self, deadline):
        while True:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                return unique_json(line.decode("utf8", errors="strict"))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refusal("Bounded builtin probe event deadline exceeded")
            ready = self.selector.select(min(remaining, 0.5))
            if not ready and self.process.poll() is not None:
                raise Refusal("Builtin workload exited before expected event")
            for key, _ in ready:
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    self.selector.unregister(key.fileobj)
                    continue
                self.total += len(data)
                if self.total > MAX_OUTPUT:
                    raise Refusal("Builtin workload output bound exceeded")
                if key.data == "stderr":
                    self.stderr_bytes += data
                    if len(self.stderr_bytes) > 65536:
                        raise Refusal("Builtin stderr bound exceeded")
                else:
                    self.buffer += data

def fresh_policy():
    observed = dt.datetime.now(dt.timezone.utc)
    values = {}
    code = "import json,socket,sys;print(json.dumps(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_STREAM)})))"
    for host in sorted(HOSTS):
        # Exactly one resolver invocation per fixed hostname; no child DNS is allowed.
        values[host] = unique_json(bounded(["/usr/bin/python3", "-c", code, host], timeout=8))
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    return {"schemaVersion": 1, "head": HEAD, "payloadManifestSha256": PAYLOAD_SHA,
            "observedAtUtc": stamp(observed), "expiresAtUtc": stamp(observed + dt.timedelta(minutes=10)),
            "hosts": values}

def actual_identity(pid, nonce, fd):
    if Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1] != [b"/usr/local/bin/node", b"/probe.cjs", nonce.encode()]:
        raise Refusal("Local State.Pid is not the exact owned builtin process")
    status = Path(f"/proc/{pid}/status").read_text()
    uid = next(line for line in status.splitlines() if line.startswith("Uid:")).split()[1:]
    if uid != ["1000"] * 4:
        raise Refusal("Local process UID differs from nonroot container account")
    held = os.fstat(fd)
    current = os.stat(f"/proc/{pid}/ns/net")
    host = os.stat("/proc/self/ns/net")
    if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino) or held.st_ino == host.st_ino:
        raise Refusal("Held namespace identity mismatch or host namespace")
    for namespace in ("pid", "ipc"):
        if os.stat(f"/proc/{pid}/ns/{namespace}").st_ino == os.stat(f"/proc/self/ns/{namespace}").st_ino:
            raise Refusal("Container shares a host PID/IPC namespace")

def root_run(output):
    check_environment(os.environ)
    expected_env = child_environment(os.environ)
    nonce = uuid.uuid4().hex
    report = {"schemaVersion": 1, "kind": "confinement-boundary-only", "nonce": nonce,
              "image": IMAGE, "packageCommandsExecuted": False, "fullInstallAdmitted": False,
              "phase": "initial-source-pins", "probes": [], "setupComplete": False, "finalFilterValid": False,
              "workloadCompleted": False, "sourcePinsPreserved": False,
              "cleanup": {"complete": False}, "failures": [],
              "limits": ["Within-run tool drift pins are not externally authenticated binary checksums.",
                         "Counter attribution uses a single owned builtin process and one outstanding network operation.",
                         "This is confinement evidence only, not a package/native/install admission."]}
    container_id = None; process = None; events = None; fd = None; started = None
    work = None; trusted_refusals = ()
    try:
        output.mkdir(parents=True, exist_ok=True)
        os.chmod(output, 0o755)
        work = Path(tempfile.mkdtemp(prefix="pftl-boundary-"))
        os.chmod(work, 0o700)
        if sys.platform != "linux" or os.geteuid() != 0:
            raise Refusal("Native Linux trusted root controller required")
        for name, expected in HELPERS.items():
            if digest(HERE / name) != expected:
                raise Refusal("Frozen policy helper pin mismatch")
        # Verify immutable helper bytes before importing them into the root driver.
        global HEAD, HOSTS, PAYLOAD_SHA, TABLE, validate_policy, verify_readback
        global apply_and_verify, unique_json, verify_tables, verify_tools
        from egress_policy import HEAD, HOSTS, PAYLOAD_SHA, TABLE, validate_policy, verify_readback
        from egress_policy import Refusal as PolicyRefusal
        from namespace_filter import apply_and_verify, unique_json, verify_tables, verify_tools
        trusted_refusals = (PolicyRefusal,)
        source_names = ["boundary_host.py", "boundary_contract.py", "boundary_probe.cjs", *HELPERS]
        source_pins = {name: digest(HERE / name) for name in source_names}
        report["sourcePins"] = source_pins
        report["toolBindingProgress"] = []
        report["phase"] = "host-tool-binding"
        binding, descriptions = bind_tools(report["toolBindingProgress"])
        report["hostTools"] = descriptions
        report["phase"] = "docker-daemon-check"
        docker_binding = canonical_elf("docker")
        docker = docker_binding["path"]
        endpoint = Path("/run/docker.sock")
        info = endpoint.lstat()
        if endpoint.resolve() != endpoint or not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o002:
            raise Refusal("Native local protected rootful Docker socket required")
        config = work / "docker-config"; config.mkdir(mode=0o700)
        docker_prefix = [docker, "--host", "unix:///run/docker.sock", "--config", str(config)]
        def dock(*arguments, timeout=15):
            return bounded(docker_prefix + list(arguments), timeout=timeout)
        daemon = unique_json(dock("info", "--format", "{{json .}}"))
        security = daemon.get("SecurityOptions", [])
        if daemon.get("OSType") != "linux" or daemon.get("DefaultRuntime") != "runc" or any("rootless" in s for s in security) or "name=seccomp,profile=builtin" not in security:
            raise Refusal("Native local rootful Docker with builtin default seccomp required")
        report["docker"] = {**docker_binding, "version": dock("version", "--format", "{{.Server.Version}}")[:128],
                            "localRootfulDaemon": True, "builtinSeccomp": True}
        report["phase"] = "image-acquisition"
        dock("pull", IMAGE, timeout=180)
        image = unique_json(dock("image", "inspect", IMAGE))[0]
        if IMAGE not in image.get("RepoDigests", []) or image.get("Os") != "linux" or image.get("Architecture") != "amd64" or image.get("Config", {}).get("Volumes"):
            raise Refusal("Exact pinned native image identity/volume contract failed")
        report["phase"] = "endpoint-observation"
        policy = fresh_policy()
        report["endpointPolicy"] = policy
        source = (HERE / "boundary_probe.cjs").resolve()
        argv = ["create", "--interactive", "--name", "pftl-boundary-" + nonce,
                "--label", OWNER_LABEL + "=" + nonce, "--user", "1000:1000",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--network", "bridge", "--ipc", "private", "--cgroupns", "private",
                "--sysctl", "net.ipv6.conf.lo.disable_ipv6=0",
                "--memory", "512m", "--cpus", "1", "--pids-limit", "32",
                "--ulimit", "nofile=128:128", "--ulimit", "core=0:0", "--stop-timeout", "3",
                "--tmpfs", "/home/node:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700",
                "--mount", "type=bind,src=" + str(source) + ",dst=/probe.cjs,readonly",
                "--entrypoint", "/usr/local/bin/node", "--workdir", "/home/node"]
        for key, value in expected_env.items():
            argv.extend(["--env", key + "=" + value])
        argv.extend([IMAGE, "/probe.cjs", nonce])
        report["phase"] = "container-creation"
        container_id = dock(*argv).strip()
        if len(container_id) != 64 or any(c not in "0123456789abcdef" for c in container_id):
            raise Refusal("Invalid actual container ID")
        started = time.monotonic(); deadline = started + PHASE_SECONDS
        process = subprocess.Popen(docker_prefix + ["start", "--attach", "--interactive", container_id],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=HOST_ENV, close_fds=True, start_new_session=True)
        events = Events(process)
        report["phase"] = "container-ready"
        ready = events.receive(min(deadline, time.monotonic() + 15))
        ready_valid = validate_ready(ready, nonce, controls_sha(os.environ))
        report["ready"] = ready
        report["phase"] = "container-inspection"
        document = unique_json(dock("inspect", container_id))[0]
        pid, gateway = validate_container(document, container_id, nonce, source, expected_env)
        fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        actual_identity(pid, nonce, fd)
        paths = verify_tools(binding)
        def namespace_command(argv, data):
            operation = namespace_operation(argv, data, paths, fd)
            report["lastNamespaceToolOperation"] = operation
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                completed = subprocess.run(argv, input=None if data is None else data.encode(),
                                           stdout=stdout, stderr=stderr, timeout=min(5, max(0.1, deadline-time.monotonic())),
                                           check=False, pass_fds=(fd,), env=HOST_ENV)
                output_bytes, error_bytes = stdout.tell(), stderr.tell()
                if output_bytes > MAX_OUTPUT or error_bytes > 65536:
                    operation.update(exitCode=completed.returncode, stdoutBytes=output_bytes, stderrBytes=error_bytes,
                                     diagnosticOutputBoundExceeded=True)
                    raise Refusal("Pinned namespace command failed or exceeded bound")
                stdout.seek(0); stderr.seek(0)
                out, err = stdout.read(), stderr.read()
                record_namespace_result(report, operation, out, err, completed.returncode)
                if completed.returncode:
                    raise Refusal("Pinned namespace command failed or exceeded bound")
                return out.decode("utf8", errors="strict")
        report["phase"] = "filter-install-and-readback"
        installed = apply_and_verify(policy, paths, fd, namespace_command,
                                     lambda: dt.datetime.now(dt.timezone.utc), phase_seconds=PHASE_SECONDS)
        prefix = [paths["nsenter"], "--net=/proc/self/fd/" + str(fd), "--"]
        def counter():
            tables = unique_json(namespace_command(prefix + [paths["nft"], "-j", "-n", "list", "tables"], None))
            verify_tables(tables, installed=True)
            value = unique_json(namespace_command(prefix + [paths["nft"], "-j", "-n", "list", "table", "inet", TABLE], None))
            return verify_readback(value, tuple(installed["addresses"]))["outputDropCounter"]
        report["phase"] = "filter-gate-revalidation"
        # Rebind actual Docker/PID/pins after filter installation before gate release.
        validate_container(unique_json(dock("inspect", container_id))[0], container_id, nonce, source, expected_env)
        actual_identity(pid, nonce, fd)
        verify_tools(binding)
        if any(digest(HERE / n) != h for n, h in source_pins.items()):
            raise Refusal("Source changed before probe gate release")
        report["filterInstall"] = installed
        report["phase"] = "ipv6-loopback-route"
        ipv6_routes = unique_json(namespace_command(prefix + [paths["ip"], "-j", "-6", "route", "show", "table", "all"], None))
        report["ipv6LoopbackRoutePresent"] = any(row.get("dst") in {"::1", "::1/128"} and row.get("dev") == "lo" for row in ipv6_routes)
        if not report["ipv6LoopbackRoutePresent"]:
            raise Refusal("IPv6 loopback route absent; actual IPv6 denial test is inconclusive")
        report["setupComplete"] = True
        for case in probe_plan(policy["hosts"]["nodejs.org"][0], gateway):
            report["phase"] = "network-probe:" + case["id"]
            before = counter()
            time.sleep(0.1)
            quiet = counter()
            if before != quiet:
                raise Refusal("Drop counter changed without an outstanding probe; attribution inconclusive")
            command = {key: case[key] for key in ("id", "operation", "address", "port")}
            process.stdin.write((json.dumps(command, separators=(",", ":")) + "\n").encode()); process.stdin.flush()
            result = events.receive(min(deadline, time.monotonic() + 4))
            time.sleep(0.1)
            after = counter()
            assessed = assess_probe(case, result, before, after)
            report["probes"].append(assessed)
            if not assessed["passed"]:
                raise Refusal("Boundary probe lacked required evidence: " + case["id"])
        report["phase"] = "final-filter-and-identity"
        report["finalCounter"] = counter()
        actual_identity(pid, nonce, fd)
        verify_tools(binding)
        report["finalFilterValid"] = True
        report["phase"] = "workload-completion"
        process.stdin.close()
        if events.receive(min(deadline, time.monotonic() + 5)) != {"event": "complete", "operations": 13} or process.wait(timeout=5) != 0:
            raise Refusal("Actual builtin workload did not complete exactly")
        report["workloadCompleted"] = True
        report["phase"] = "final-source-pins"
        if any(digest(HERE / n) != h for n, h in source_pins.items()):
            raise Refusal("Frozen source changed during probe")
        report["sourcePinsPreserved"] = True
        report["phase"] = "complete"
    except Exception as error:
        # Refusals contain fixed operation labels only; no stack, env or owner paths.
        report["failurePhase"] = report["phase"]
        report["failures"].append(failure_label(error, trusted_refusals))
    finally:
        cleanup_errors = []
        if fd is not None:
            try:
                os.close(fd); fd = None
            except Exception:
                cleanup_errors.append("held-namespace-fd-close-not-proven")
        if "dock" in locals():
            try:
                owned = dock("ps", "--all", "--quiet", "--no-trunc", "--filter", "label=" + OWNER_LABEL + "=" + nonce).split()
                if len(owned) > 1 or (container_id and owned and owned != [container_id]):
                    raise Refusal("Unexpected owned container inventory")
                if owned:
                    dock("rm", "--force", "--volumes", *owned, timeout=15)
                remaining = dock("ps", "--all", "--quiet", "--filter", "label=" + OWNER_LABEL + "=" + nonce).split()
                if remaining:
                    raise Refusal("Owned container survived cleanup")
            except Exception:
                cleanup_errors.append("owned-container-removal-not-proven")
        if process is not None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.kill(); process.wait(timeout=5)
                except Exception:
                    cleanup_errors.append("attach-client-exit-not-proven")
                cleanup_errors.append("attach-client-required-kill")
            except Exception:
                cleanup_errors.append("attach-client-wait-failed")
        if events is not None:
            report["workloadStderr"] = {"bytes": len(events.stderr_bytes),
                                        "sha256": hashlib.sha256(events.stderr_bytes).hexdigest()}
            try:
                events.selector.close()
            except Exception:
                cleanup_errors.append("event-reader-close-failed")
        if "pid" in locals() and Path(f"/proc/{pid}/cmdline").exists():
            try:
                if nonce.encode() in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0"):
                    cleanup_errors.append("original-owned-process-survived")
            except FileNotFoundError:
                pass
            except Exception:
                cleanup_errors.append("original-process-absence-not-proven")
        if work is not None:
            try:
                shutil.rmtree(work)
            except Exception:
                cleanup_errors.append("owned-private-work-removal-not-proven")
        report["cleanup"] = {"complete": not cleanup_errors, "errors": cleanup_errors,
                             "heldNamespaceFdClosed": fd is None,
                             "persistentVolumesCreated": 0, "tmpfsLifetime": "owned container only",
                             "ownedContainerAbsent": "dock" in locals() and not cleanup_errors}
        report["elapsedPhaseSeconds"] = round(time.monotonic()-started, 3) if started else None
        report["confinementQualified"] = confinement_result(report.get("setupComplete"), report["probes"],
                                                            report["finalFilterValid"], report["cleanup"]["complete"],
                                                            report["workloadCompleted"], report["sourcePinsPreserved"]) and not report["failures"]
        target = output / "boundary-report.json"
        try:
            with target.open("x") as stream:
                json.dump(report, stream, indent=2); stream.write("\n")
            os.chmod(target, 0o644)
        except Exception:
            report["confinementQualified"] = False
            report["failures"].append("root-readable-report-write-failed")
            print(json.dumps({"failureReportFallback": report}))
    print(json.dumps({"report": "boundary-report.json", "confinementQualified": report["confinementQualified"]}))
    return 0 if report["confinementQualified"] else 1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root-controls-sha")
    args = parser.parse_args()
    try:
        check_environment(os.environ)
    except Refusal as error:
        failure = {"schemaVersion": 1, "kind": "confinement-boundary-only", "confinementQualified": False,
                   "setupComplete": False, "failures": [str(error)], "probes": [],
                   "packageCommandsExecuted": False, "fullInstallAdmitted": False,
                   "cleanup": {"complete": True, "ownedResourcesCreated": 0}}
        try:
            args.output.mkdir(parents=True, exist_ok=True)
            with (args.output / "boundary-report.json").open("x") as stream:
                json.dump(failure, stream, indent=2); stream.write("\n")
            os.chmod(args.output / "boundary-report.json", 0o644)
        except Exception:
            print(json.dumps({"failureReportFallback": failure}))
        return 1
    expected = controls_sha(os.environ)
    if os.geteuid() != 0:
        keys = sorted(controls(os.environ))
        argv = ["/usr/bin/sudo", "-n"]
        if keys:
            argv.append("--preserve-env=" + ",".join(keys))
        argv += ["/usr/bin/python3", "-I", str(Path(__file__).resolve()), "--output", str(args.output.resolve()),
                 "--root-controls-sha", expected]
        return subprocess.run(argv, env={**HOST_ENV, **controls(os.environ)}, check=False).returncode
    if args.root_controls_sha != expected:
        raise Refusal("Inherited sandbox controls changed during root bootstrap")
    return root_run(args.output.resolve())

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        # Setup refusal is explicit and cannot be an empty/hidden success report.
        print(json.dumps({"confinementQualified": False, "setupRefusal": str(error)}))
        raise SystemExit(1)
