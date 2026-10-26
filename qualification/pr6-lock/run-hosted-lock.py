"""Prepared hosted controller. Not executed during source preparation."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parent))
from egress_policy import Refusal, hosts_text, utc, validate_policy, refuse_proxy_controls, refuse_docker_controls
from namespace_filter import pinned_json
from boundary_contract import HELPERS, check_environment
from install_contract import install_admission, phase_admission
from prepare_phase import canonical_elf, prepare_phase

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / "payload"
PAYLOAD_SHA = "2b34bd97b9610342d294e00d30a4ecbe131528c17449a9679c1b1cd3ec2a6545"
HEAD = "0820278c1cd38e6dd6a1ae38631889041bd6f9ba"
TREE = "2d6666aba60dbd00d912034cc2d4def5200ceac9"
IMAGE = "node@sha256:51b1100cc2a83d370c6a60952e3f2989c8a43159d0e38586e090f3b3326efefd"
RESERVE = 4 * 1024**3
OUTPUT_LIMIT = 16 * 1024**2
PREPARATION_ONLY = False  # Exact proof/native/resource admission bound in this reviewed runtime candidate.
FULL_INSTALL_ADMITTED = True  # Requires pinned expiring admission and separate normal-reviewed dispatch.
DOCKER_PREFIX = None
DOCKER_BINDING = None

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command(args, timeout=30, check=True):
    return subprocess.run(docker_args(args), check=check, text=True, capture_output=True, timeout=timeout)

def docker_args(args):
    if args and args[0] == "docker":
        if DOCKER_PREFIX is None or DOCKER_BINDING is None:
            raise ValueError("Local Docker endpoint has not been bound")
        # Re-use the reviewed protected ELF identity check before every Docker
        # command, including attach and cleanup. Never execute a substituted CLI.
        if canonical_elf("docker") != DOCKER_BINDING:
            raise ValueError("Bound Docker executable identity changed")
        return DOCKER_PREFIX + args[1:]
    return args

def configure_local_docker(config_directory):
    global DOCKER_PREFIX, DOCKER_BINDING
    refuse_docker_controls(os.environ)
    DOCKER_BINDING = canonical_elf("docker")
    socket = Path("/run/docker.sock")
    info = socket.lstat()
    if (os.uname().sysname != "Linux" or socket.resolve() != socket or not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o002):
        raise ValueError("Canonical root-owned native Linux Docker socket required")
    config_directory.mkdir(mode=0o700)
    # Explicit local daemon and empty owned config, without changing HOME or
    # reading runner Docker credentials/context. Every Docker call shares this.
    DOCKER_PREFIX = [DOCKER_BINDING["path"], "--host", "unix:///run/docker.sock", "--config", str(config_directory)]
    daemon = json.loads(command(["docker", "info", "--format", "{{json .}}"]).stdout)
    security = daemon.get("SecurityOptions", [])
    if (daemon.get("OSType") != "linux" or "desktop" in daemon.get("OperatingSystem", "").lower()
            or daemon.get("DefaultRuntime") != "runc"
            or not isinstance(security, list) or any(not isinstance(value, str) for value in security)
            or any("rootless" in value.lower() for value in security)
            or "name=seccomp,profile=builtin" not in security
            or daemon.get("Name") != os.uname().nodename):
        raise ValueError("Native local rootful Docker daemon with builtin default seccomp required")
    return {**DOCKER_BINDING, "endpoint": "unix:///run/docker.sock", "daemonId": daemon.get("ID"),
            "nativeLinux": True, "rootless": False, "localRootfulDaemon": True,
            "builtinSeccomp": True, "runnerDockerConfigRead": False}

def verify_local_gate(pid, phase, nonce):
    path = Path(f"/proc/{pid}")
    commandline = (path / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    tail = [b"/bin/sh", b"/lane/wait-for-filter.sh", phase.encode(), nonce.encode()]
    if commandline[-4:] != tail:
        raise ValueError("Docker PID is not this local nonce-bound trusted wait process")
    status = (path / "status").read_text()
    if not re.search(r"^Uid:\s+1000\s+1000\s+1000\s+1000$", status, re.MULTILINE):
        raise ValueError("Local gate UID differs from image account")

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")

def regular(path):
    return not path.is_symlink() and path.is_file()

def source_regular(root, path):
    cursor = root
    for component in path.relative_to(root).parts:
        cursor = cursor / component
        if cursor.is_symlink():
            return False
    return path.is_file()

def within(root, name):
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unsafe manifest path")
    return root / relative

def source_check(project, inventory, allow_lock=False):
    expected = {row["path"] for row in inventory}
    for row in inventory:
        p = within(project, row["path"])
        if not source_regular(project, p):
            raise ValueError("Nonregular source: " + row["path"])
        if row["path"] == "yarn.lock" and allow_lock:
            continue
        if sha(p) != row["sha256"] or oct(stat.S_IMODE(p.stat().st_mode)) != row["mode"]:
            raise ValueError("Frozen source changed: " + row["path"])
    for parent, dirs, names in os.walk(project, followlinks=False):
        parent = Path(parent)
        kept = []
        for name in dirs:
            path = parent / name
            relative = path.relative_to(project).as_posix()
            if name == "node_modules" or relative in {".yarn/cache", ".yarn/unplugged"}:
                continue
            if path.is_symlink():
                raise ValueError("Unexpected source symlink")
            kept.append(name)
        dirs[:] = kept
        for name in names:
            relative = (parent / name).relative_to(project).as_posix()
            if relative not in expected and relative != ".yarn/install-state.gz":
                raise ValueError("Unexpected source file: " + relative)

def lock_check(original, current, project):
    before, after = lock_entries(original), lock_entries(current)
    for descriptor, entry in before.items():
        if descriptor not in after:
            raise ValueError("Original lock descriptor removed: " + descriptor)
        for field in ["version", "resolution", "checksum"]:
            if entry["fields"].get(field) != after[descriptor]["fields"].get(field):
                raise ValueError("Existing lock resolution/checksum drift: " + descriptor)
    for descriptor in ["root@workspace:.", "site@workspace:packages/site", "@postfiat/pftl-snap@workspace:packages/snap"]:
        if before[descriptor]["body"] != after[descriptor]["body"]:
            raise ValueError("Protected workspace lock entry changed")
    host = "@postfiat/pftl-host-lite@workspace:packages/host-lite"
    manifest = json.loads((project / "packages/host-lite/package.json").read_text())
    dependencies = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
    if after.get(host, {}).get("dependencies") != dependencies:
        raise ValueError("Host-lite workspace lock dependencies differ")
    for descriptor in ["typescript@npm:5.0.4", "vite@npm:^5.2.0", "@vitejs/plugin-react@npm:^4.2.1"]:
        if descriptor not in after:
            raise ValueError("Required new tool descriptor missing")
    if after["typescript@npm:5.0.4"]["fields"].get("version") != "5.0.4":
        raise ValueError("Wrong TypeScript version")
    if original == current:
        raise ValueError("No candidate lock generated")
    return {"originalDescriptors": len(before), "candidateDescriptors": len(after), "originalResolutionsAndChecksumsPreserved": True}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--outputs", required=True, type=Path)
    parser.add_argument("--admission", required=True, type=Path)
    parser.add_argument("--admission-sha256", required=True)
    parser.add_argument("--boundary-report", required=True, type=Path)
    parser.add_argument("--boundary-provenance", required=True, type=Path)
    args = parser.parse_args()
    outputs = args.outputs.resolve()
    outputs.mkdir(exist_ok=False)
    report = {"qualified": False, "phases": [], "cleanupVerified": False, "hookOrPolicyModified": False,
              "mode": "full-install", "boundaryRuntimeQualified": False, "installExecuted": False,
              "qualificationScope": "Candidate lock plus actual immutable original-hook install only",
              "limits": "Lock/install evidence only; not a Sharp native-load, Vite/product, wallet, or transaction test."}
    runtime = None
    containers = []
    volume = None
    active_client = None
    host_home = os.environ.get("HOME")
    controls = {k: v for k, v in os.environ.items() if k == "CODEX_SANDBOX" or k.startswith("CODEX_SANDBOX_")}
    token = "pr6-lock-" + uuid.uuid4().hex
    try:
        # Required actual proof is evaluated even in preparation mode; toggling
        # either constant cannot manufacture the missing historical evidence.
        admission = pinned_json(args.admission, args.admission_sha256)
        pinned_json(args.boundary_report, admission["boundaryReportSha256"])
        pinned_json(args.boundary_provenance, admission["boundaryProvenanceSha256"])
        proof = install_admission(admission, args.boundary_report.read_bytes(), args.boundary_provenance.read_bytes(),
                                  os.environ, datetime.datetime.now(datetime.timezone.utc))
        report["actualBoundaryProof"] = proof
        if PREPARATION_ONLY or not FULL_INSTALL_ADMITTED:
            raise ValueError("Proof alone does not authorize install: separately reviewed runtime revision still required")
        check_environment(os.environ)
        for helper, expected in HELPERS.items():
            if sha(HERE / helper) != expected:
                raise ValueError("Boundary-qualified helper bytes changed")
        refuse_proxy_controls(os.environ)
        refuse_docker_controls(os.environ)
        if os.environ.get("GITHUB_REPOSITORY") != "citadelculture/pftl-snap" or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            raise ValueError("Exact owned repository/manual event required")
        if controls.get("CODEX_SANDBOX_NETWORK_DISABLED") == "1":
            raise ValueError("Inherited network restriction prevents this online lane")
        if sha(PAYLOAD / "manifest.json") != PAYLOAD_SHA:
            raise ValueError("Public payload manifest changed")
        payload_manifest = json.loads((PAYLOAD / "manifest.json").read_text())
        for row in payload_manifest["files"]:
            path = within(PAYLOAD, row["path"])
            if not regular(path) or sha(path) != row["sha256"]:
                raise ValueError("Public payload pin mismatch")
        source = args.source.resolve()
        if command(["git", "-C", str(source), "rev-parse", "HEAD"]).stdout.strip() != HEAD:
            raise ValueError("Upstream HEAD mismatch")
        if command(["git", "-C", str(source), "rev-parse", "HEAD^{tree}"]).stdout.strip() != TREE:
            raise ValueError("Upstream Git tree mismatch")
        if command(["git", "-C", str(source), "status", "--porcelain"]).stdout:
            raise ValueError("Checkout is dirty")
        inventory = json.loads((PAYLOAD / "frozen-candidate-files.json").read_text())
        if len(inventory) != 4473:
            raise ValueError("Unexpected frozen source count")
        runtime = Path(tempfile.mkdtemp(prefix=token + "-", dir=os.environ["RUNNER_TEMP"]))
        project = runtime / "project"
        project.mkdir()
        for row in inventory:
            relative = row["path"]
            candidate = within(PAYLOAD / "candidate", relative)
            src = candidate if candidate.exists() else within(source, relative)
            if not regular(src):
                raise ValueError("Missing/nonregular input")
            target = within(project, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
        source_check(project, inventory)
        if (project / ".git").exists():
            raise ValueError("Git credentials/metadata may not enter workload")
        original_lock = (project / "yarn.lock").read_text()
        bin_dir = runtime / "bin"
        bin_dir.mkdir()
        (bin_dir / "node").symlink_to("/usr/local/bin/node")
        (bin_dir / "yarn").symlink_to("/work/project/.yarn/releases/yarn-3.2.1.cjs")
        # Only this newly created public-source copy changes owner, never host HOME.
        command(["sudo", "-n", "chown", "-R", "--no-dereference", "1000:1000", str(project)], timeout=60)
        if shutil.disk_usage(runtime).free < 8 * 1024**3:
            raise ValueError("At least 8 GiB free space required")
        report["dockerDaemon"] = configure_local_docker(runtime / "docker-config")
        pull = command(["docker", "pull", "--platform", "linux/amd64", IMAGE], timeout=240, check=False)
        write_json(outputs / "image-pull.json", {"exitCode": pull.returncode, "image": IMAGE})
        if pull.returncode:
            raise ValueError("Pinned image pull failed")
        volume = token + "-home"
        command(["docker", "volume", "create", "--label", "pr6-owner=" + token, volume])
        candidate_sha = None
        for phase in ["generate", "immutable"]:
            admission = pinned_json(args.admission, args.admission_sha256)
            pinned_json(args.boundary_report, admission["boundaryReportSha256"])
            pinned_json(args.boundary_provenance, admission["boundaryProvenanceSha256"])
            phase_admission(admission, args.boundary_report.read_bytes(), args.boundary_provenance.read_bytes(),
                            os.environ, datetime.datetime.now(datetime.timezone.utc), phase_seconds=900)
            # Trusted host DNS/tool observations are fresh for each phase. No
            # stale first-phase pins or unseen auto-renewal within a child run.
            preparation = prepare_phase(outputs / (phase + "-inputs"), os.environ)
            endpoint_policy = preparation["policy"]
            policy_path = Path(preparation["files"]["endpoint-policy"]["path"])
            policy_sha = preparation["files"]["endpoint-policy"]["sha256"]
            tools_path = Path(preparation["files"]["host-tools"]["path"])
            tools_sha = preparation["files"]["host-tools"]["sha256"]
            write_json(outputs / (phase + "-preparation.json"), preparation)
            for helper, expected in HELPERS.items():
                if sha(HERE / helper) != expected:
                    raise ValueError("Boundary-qualified helper bytes changed before phase")
            endpoint_hosts = runtime / (phase + "-hosts")
            endpoint_hosts.write_text(hosts_text(endpoint_policy))
            empty_resolver = runtime / (phase + "-resolv.conf")
            empty_resolver.write_bytes(b"")
            endpoint_hosts.chmod(0o444); empty_resolver.chmod(0o444)
            if phase != "boundary":
                source_check(project, inventory, allow_lock=phase == "immutable")
            name = token + "-" + phase
            gate = runtime / (phase + "-gate")
            gate.mkdir(mode=0o755)
            nonce = uuid.uuid4().hex
            phase_seconds = 900
            containers.append(name)
            argv = ["docker", "create", "--name", name, "--platform", "linux/amd64", "--user", "node",
                    "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--init",
                    "--ipc", "private", "--cgroupns", "private", "--runtime", "runc",
                    "--pids-limit", "256", "--memory", "4g", "--memory-swap", "4g", "--cpus", "2",
                    "--network", "bridge",
                    "--tmpfs", "/tmp:rw,nosuid,nodev,size=536870912,mode=1777",
                    "--mount", "type=bind,src=" + str(project) + ",dst=/work/project",
                    "--mount", "type=bind,src=" + str(bin_dir) + ",dst=/lane-bin,readonly",
                    "--mount", "type=bind,src=" + str(HERE) + ",dst=/lane,readonly",
                    "--mount", "type=bind,src=" + str(gate) + ",dst=/lane-gate,readonly",
                    "--mount", "type=bind,src=" + str(endpoint_hosts) + ",dst=/etc/hosts,readonly",
                    "--mount", "type=bind,src=" + str(empty_resolver) + ",dst=/etc/resolv.conf,readonly",
                    "--mount", "type=volume,src=" + volume + ",dst=/home/node",
                    "--workdir", "/work/project", "--entrypoint", "/bin/sh"]
            for key, value in {"HOME": "/home/node", "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "CI": "true"}.items():
                argv.extend(["--env", key + "=" + value])
            for key in sorted(controls):
                argv.extend(["--env", key])  # Docker copies the original value; none is printed.
            argv.extend([IMAGE, "/lane/wait-for-filter.sh", phase, nonce])
            command(argv)
            config = json.loads(command(["docker", "inspect", name]).stdout)[0]
            host = config["HostConfig"]
            if host["Privileged"] or host["PidMode"] or host["IpcMode"] != "private" or not host["ReadonlyRootfs"]:
                raise ValueError("Container namespace/root boundary mismatch")
            if (host["CapDrop"] != ["ALL"] or host.get("CapAdd") not in (None, [])
                    or host["SecurityOpt"] != ["no-new-privileges"] or host.get("CgroupnsMode") != "private"
                    or host.get("Runtime") != "runc" or host.get("Devices") not in (None, [])
                    or host.get("DeviceRequests") not in (None, [])):
                raise ValueError("Container capability boundary mismatch")
            if (config["Config"]["Image"] != IMAGE or config["Config"]["User"] != "node"
                    or config["Image"] != "sha256:470015c1ab1577c19efce2e80cdad4afd9c682cf8f4dcf3dccae5abfd9113397"
                    or host["Memory"] != 4 * 1024**3 or host["MemorySwap"] != 4 * 1024**3
                    or host["PidsLimit"] != 256 or host["NanoCpus"] != 2 * 10**9
                    or host["NetworkMode"] != "bridge"):
                raise ValueError("Container image/resource/network binding mismatch")
            env = dict(item.split("=", 1) for item in config["Config"]["Env"])
            if any(env.get(k) != v for k, v in controls.items()):
                raise ValueError("Inherited control value changed")
            if any(re.match(r"^(ACTIONS_|GITHUB_|INPUT_|RUNNER_)", k) for k in env):
                raise ValueError("Runner/service environment entered container")
            expected_mounts = {"/work/project": str(project), "/lane-bin": str(bin_dir), "/lane": str(HERE),
                               "/lane-gate": str(gate), "/etc/hosts": str(endpoint_hosts),
                               "/etc/resolv.conf": str(empty_resolver)}
            actual_mounts = {m["Destination"]: m["Source"] for m in config["Mounts"] if m["Type"] == "bind"}
            if actual_mounts != expected_mounts:
                raise ValueError("Unadmitted host mount")
            if {m["Destination"] for m in config["Mounts"]} != set(expected_mounts) | {"/home/node"}:
                raise ValueError("Unexpected additional mount")
            for mount in config["Mounts"]:
                if mount["Destination"] in set(expected_mounts) - {"/work/project"} and mount["RW"]:
                    raise ValueError("Control mount is writable")
                if mount["Destination"] == "/home/node" and (mount["Type"] != "volume" or mount["Name"] != volume):
                    raise ValueError("Home is not the owned disposable volume")
            write_json(outputs / (phase + "-boundary.json"), {
                "imageConfigId": config["Image"], "image": IMAGE, "user": "node",
                "readOnlyRoot": host["ReadonlyRootfs"], "capDrop": host["CapDrop"],
                "pidMode": host["PidMode"], "ipcMode": host["IpcMode"], "networkMode": host["NetworkMode"],
                "memoryBytes": host["Memory"], "pidsLimit": host["PidsLimit"],
                "mounts": [{"type": m["Type"], "destination": m["Destination"], "writable": m["RW"]} for m in config["Mounts"]],
                "inheritedSandboxControlNames": sorted(controls), "controlValuesComparedExactly": True,
                "environmentValuesLogged": False, "hostHomeMounted": False,
            })
            start = time.monotonic()
            reason = None
            with (outputs / (phase + ".stdout")).open("wb") as stdout, (outputs / (phase + ".stderr")).open("wb") as stderr:
                process = subprocess.Popen(docker_args(["docker", "start", "--attach", name]), stdout=stdout, stderr=stderr)
                active_client = process
                # Only the trusted shell wait loop is now running. No Node/Yarn
                # source command may start before installed kernel policy readback.
                running = None
                for _ in range(50):
                    running = json.loads(command(["docker", "inspect", name]).stdout)[0]
                    if running["State"]["Running"] and running["State"]["Pid"] > 1:
                        break
                    if process.poll() is not None:
                        raise ValueError("Trusted wait gate exited before filter installation")
                    time.sleep(0.1)
                if not running or not running["State"]["Running"]:
                    raise ValueError("No live trusted wait gate")
                pid = running["State"]["Pid"]
                verify_local_gate(pid, phase, nonce)
                netns = os.stat(f"/proc/{pid}/ns/net")
                receipt_path = outputs / (phase + "-filter.json")
                helper = ["sudo", "-n", "/usr/bin/python3", "-B", str(HERE / "namespace_filter.py"),
                          "--pid", str(pid), "--namespace-dev", str(netns.st_dev),
                          "--namespace-inode", str(netns.st_ino),
                          "--policy", str(policy_path.resolve()),
                          "--policy-sha256", policy_sha,
                          "--tools", str(tools_path.resolve()), "--tools-sha256", tools_sha,
                          "--phase-seconds", str(phase_seconds), "--receipt", str(receipt_path)]
                command(helper, timeout=55)
                receipt = json.loads(receipt_path.read_text())
                after = json.loads(command(["docker", "inspect", name]).stdout)[0]
                if (after["Id"] != running["Id"] or not after["State"]["Running"] or after["State"]["Pid"] != pid
                        or receipt.get("pid") != pid or receipt.get("namespaceDevice") != netns.st_dev
                        or receipt.get("namespaceInode") != netns.st_ino or receipt.get("exactReadback") is not True
                        or receipt.get("policySha256") != policy_sha
                        or receipt.get("toolsSha256") != tools_sha):
                    raise ValueError("Filter/container identity binding failed")
                verify_local_gate(pid, phase, nonce)
                # Re-check pins and resources immediately before release. Receipt
                # booleans are not an execution authorization or negative-probe pass.
                endpoint_policy = pinned_json(policy_path, policy_sha)
                pinned_json(tools_path, tools_sha)
                validate_policy(endpoint_policy, datetime.datetime.now(datetime.timezone.utc),
                                set(receipt["hostAndContainerLocalAndGatewayAddressesExcluded"]),
                                phase_seconds=phase_seconds)
                source_check(project, inventory, allow_lock=phase == "immutable")
                if shutil.disk_usage(runtime).free < RESERVE or process.poll() is not None:
                    raise ValueError("Resource/process guard failed before release")
                # Atomic read-only marker; child cannot create it. This is the first
                # point at which the trusted wrapper (then possibly Yarn) may start.
                marker = gate / "pending"
                marker.write_text(nonce + "\n")
                marker.chmod(0o444)
                # Slow DNS/tool/source/filter preparation cannot carry stale
                # authority across the package gate. Reload all exact proof pins
                # and require the complete phase+cleanup lifetime at release.
                admission = pinned_json(args.admission, args.admission_sha256)
                pinned_json(args.boundary_report, admission["boundaryReportSha256"])
                pinned_json(args.boundary_provenance, admission["boundaryProvenanceSha256"])
                release_proof = phase_admission(admission, args.boundary_report.read_bytes(), args.boundary_provenance.read_bytes(),
                                                os.environ, datetime.datetime.now(datetime.timezone.utc),
                                                phase_seconds=phase_seconds)
                marker.rename(gate / "release")
                report.setdefault("phaseReleaseProofs", []).append({"phase": phase, **release_proof})
                while process.poll() is None:
                    timeout = 900
                    if datetime.datetime.now(datetime.timezone.utc) >= utc(admission["expiresAtUtc"]):
                        reason = "install-admission-expired"
                    elif datetime.datetime.now(datetime.timezone.utc) >= utc(endpoint_policy["expiresAtUtc"]):
                        reason = "endpoint-policy-expired"
                    elif time.monotonic() - start > timeout:
                        reason = "phase-timeout"
                    elif shutil.disk_usage(runtime).free < RESERVE:
                        reason = "disk-reserve"
                    elif sum((outputs / (phase + "." + s)).stat().st_size for s in ["stdout", "stderr"]) > OUTPUT_LIMIT:
                        reason = "output-limit"
                    if reason:
                        command(["docker", "kill", name], check=False)
                        break
                    time.sleep(1)
                process.wait(timeout=30)
                active_client = None
            state = json.loads(command(["docker", "inspect", name]).stdout)[0]["State"]
            result = {"phase": phase, "exitCode": state["ExitCode"], "oomKilled": state["OOMKilled"],
                      "runningAfter": state["Running"], "stopReason": reason,
                      "stdoutSha256": sha(outputs / (phase + ".stdout")), "stderrSha256": sha(outputs / (phase + ".stderr"))}
            report["phases"].append(result)
            if phase != "boundary":
                report["installExecuted"] = True
            if phase != "boundary":
                if source_regular(project, project / "yarn.lock"):
                    shutil.copyfile(project / "yarn.lock", outputs / "candidate-yarn.lock")
                source_check(project, inventory, allow_lock=True)
            if reason or state["Running"] or state["OOMKilled"] or state["ExitCode"] != 0:
                raise ValueError("Phase did not complete successfully: " + phase)
            if phase != "boundary":
                report["lockValidation"] = lock_check(original_lock, (project / "yarn.lock").read_text(), project)
                if not source_regular(project, project / "node_modules/.yarn-state.yml"):
                    raise ValueError("Actual linker state absent")
                actual_sha = sha(project / "yarn.lock")
                if phase == "immutable" and actual_sha != candidate_sha:
                    raise ValueError("Immutable install changed candidate lock")
                candidate_sha = actual_sha
            for helper, expected in HELPERS.items():
                if sha(HERE / helper) != expected:
                    raise ValueError("Boundary-qualified helper bytes changed during phase")
        report["qualified"] = True
        # Negative route/counter probes and persistence checks are distinct. The
        # account-only wrapper cannot authorize a later install automatically.
        report["boundaryRuntimeQualified"] = True  # Pinned historical report, not a new traffic probe.
        report["candidateLockSha256"] = candidate_sha
    except Exception as error:
        report["failure"] = str(error)
    finally:
        cleanup_errors = []
        for name in containers:
            try:
                command(["docker", "rm", "--force", name], check=False)
                remaining = command(["docker", "ps", "-aq", "--filter", "name=^/" + name + "$" ]).stdout.strip()
                if remaining:
                    raise ValueError("Owned container remains")
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if active_client is not None:
            try:
                if active_client.poll() is None:
                    active_client.terminate()
                try:
                    active_client.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    active_client.kill()
                    active_client.wait(timeout=10)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if volume:
            try:
                info = json.loads(command(["docker", "volume", "inspect", volume]).stdout)[0]
                if info.get("Labels", {}).get("pr6-owner") != token:
                    raise ValueError("Volume ownership mismatch")
                command(["docker", "volume", "rm", volume])
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if runtime:
            try:
                command(["sudo", "-n", "chown", "-R", "--no-dereference", str(os.getuid()) + ":" + str(os.getgid()), str(runtime)], timeout=60)
                shutil.rmtree(runtime)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        report["hostHomeUnchanged"] = os.environ.get("HOME") == host_home
        report["cleanupVerified"] = not cleanup_errors
        report["cleanupErrors"] = cleanup_errors
        report["qualified"] = report["qualified"] and report["cleanupVerified"] and report["hostHomeUnchanged"]
        report["finishedAtUtc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(outputs / "result.json", report)
    return 0 if report["qualified"] else 1



def scalar(value):
    return json.loads(value) if value.startswith('"') else value

def lock_entries(text):
    """Read Yarn's quoted top-level entries and indentation, not arbitrary YAML."""
    entries = {}
    for block in re.split(r"\n\s*\n", text):
        lines = block.splitlines()
        if not lines or not lines[0].startswith('"'):
            continue
        if not lines[0].endswith('":'):
            raise ValueError("Unsupported multiline/top-level lock header")
        header = json.loads(lines[0][:-1])
        fields = {}
        for line in lines[1:]:
            match = re.match(r"^  ([A-Za-z][A-Za-z0-9]*): (.+)$", line)
            if match:
                fields[match.group(1)] = scalar(match.group(2))
        dependencies = {}
        in_dependencies = False
        for line in lines[1:]:
            if line.startswith("  ") and not line.startswith("    "):
                in_dependencies = line == "  dependencies:"
            elif in_dependencies:
                match = re.match(r"^    (.+?): (.+)$", line)
                if not match:
                    raise ValueError("Unsupported dependency entry")
                dependencies[scalar(match.group(1))] = scalar(match.group(2))
        value = {"fields": fields, "dependencies": dependencies,
                 "body": "\n".join(lines[1:]).strip()}
        for descriptor in header.split(", "):
            if descriptor in entries:
                raise ValueError("Duplicate lock descriptor: " + descriptor)
            entries[descriptor] = value
    if not entries:
        raise ValueError("No lock entries found")
    return entries

if __name__ == "__main__":
    raise SystemExit(main())
