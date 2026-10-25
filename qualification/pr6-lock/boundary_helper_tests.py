"""Pure synthetic decision tests; no subprocess, DNS, Node, Docker or namespace tools."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from boundary_contract import (Refusal, assess_probe, check_environment, child_environment, confinement_result,
                               controls_sha, probe_plan)
from boundary_host import validate_container, validate_ready

NONCE = "a" * 32
ID = "b" * 64
SOURCE = Path("/public/probe.cjs")

def ready():
    return {"event": "ready", "nonce": NONCE, "uid": 1000, "gid": 1000,
            "accountUid": 1000, "accountGid": 1000, "accountHome": "/home/node",
            "homeMatchesRealAccount": True, "canaryRoundTrip": True,
            **{key: "0000000000000000" for key in ("capInh", "capPrm", "capEff", "capBnd", "capAmb")},
            "noNewPrivs": "1", "seccomp": "2", "controlsSha256": controls_sha({}),
            "unexpectedEnvironmentCount": 0, "dockerSocketStat": "absent",
            "nodeVersion": "24.21.0", "platform": "linux", "arch": "x64"}

def inspection():
    return {"Id": ID, "Config": {"Labels": {"org.postfiat.boundary.nonce": NONCE},
            "User": "1000:1000", "Entrypoint": ["/usr/local/bin/node"], "Cmd": ["/probe.cjs", NONCE],
            "Env": [key + "=" + value for key, value in {"NODE_VERSION": "24.21.0", "YARN_VERSION": "1.22.22", **child_environment({})}.items()]},
            "State": {"Running": True, "Pid": 12345},
            "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": None,
             "PidMode": "", "IpcMode": "private", "NetworkMode": "bridge", "CgroupnsMode": "private",
             "Runtime": "runc", "Devices": [], "DeviceRequests": None, "SecurityOpt": ["no-new-privileges"],
             "Memory": 512 * 1024**2, "NanoCpus": 10**9, "PidsLimit": 32,
             "Sysctls": {"net.ipv6.conf.lo.disable_ipv6": "0"},
             "Tmpfs": {path: "rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700" for path in ("/home/node", "/tmp")}},
            "Mounts": [{"Type": "bind", "Source": str(SOURCE), "Destination": "/probe.cjs", "RW": False}],
            "NetworkSettings": {"Networks": {"bridge": {"Gateway": "172.17.0.1"}}}}

class BoundaryDecisions(unittest.TestCase):
    def test_environment_never_forwards_service_credentials(self):
        env = child_environment({"GITHUB_TOKEN": "SYNTHETIC", "ACTIONS_RUNTIME_TOKEN": "SYNTHETIC", "CODEX_SANDBOX": "synthetic"})
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("ACTIONS_RUNTIME_TOKEN", env)
        self.assertEqual(env["CODEX_SANDBOX"], "synthetic")
        self.assertEqual(env["HOME"], "/home/node")
    def test_routing_and_enforced_controls_refuse_instead_of_disappearing(self):
        for key, value in [("HTTPS_PROXY", "SYNTHETIC"), ("NO_PROXY", ""), ("DOCKER_HOST", "SYNTHETIC"),
                           ("DOCKER_CONTEXT", "SYNTHETIC"), ("DOCKER_TLS_VERIFY", "1"),
                           ("CODEX_SANDBOX_NETWORK_DISABLED", "1"), ("NODE_OPTIONS", "SYNTHETIC")]:
            with self.subTest(key=key), self.assertRaises(Refusal):
                child_environment({key: value})
    def test_control_hash_is_order_independent_and_utf8(self):
        a = {"CODEX_SANDBOX_Z": "synthetic-é", "CODEX_SANDBOX": "first"}
        b = dict(reversed(list(a.items())))
        self.assertEqual(controls_sha(a), controls_sha(b))
        expected = hashlib.sha256(json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(controls_sha(a), expected)
    def test_exact_nonroot_container_contract_and_mutation_refusal(self):
        self.assertEqual(validate_container(inspection(), ID, NONCE, SOURCE, child_environment({})), (12345, "172.17.0.1"))
        for key, value in [("Privileged", True), ("ReadonlyRootfs", False), ("CapAdd", ["NET_ADMIN"]),
                           ("SecurityOpt", ["seccomp=unconfined"]), ("NetworkMode", "host"),
                           ("PidMode", "host"), ("IpcMode", "host"), ("Memory", 0), ("Tmpfs", {})]:
            document = inspection(); document["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(Refusal):
                validate_container(document, ID, NONCE, SOURCE, child_environment({}))
    def test_credentials_mount_and_wrong_node_are_rejected(self):
        for mutation in ("mount", "environment", "command"):
            document = inspection()
            if mutation == "mount": document["Mounts"][0]["Destination"] = "/var/run/docker.sock"
            elif mutation == "environment": document["Config"]["Env"].append("GITHUB_TOKEN=SYNTHETIC")
            else: document["Config"]["Cmd"] = ["repository.js", NONCE]
            with self.subTest(mutation=mutation), self.assertRaises(Refusal):
                validate_container(document, ID, NONCE, SOURCE, child_environment({}))
    def test_all_five_capability_sets_and_identity_are_required(self):
        self.assertTrue(validate_ready(ready(), NONCE, controls_sha({})))
        for key in ("capInh", "capPrm", "capEff", "capBnd", "capAmb"):
            event = ready(); event[key] = "0000000000000001"
            with self.subTest(key=key), self.assertRaises(Refusal): validate_ready(event, NONCE, controls_sha({}))
        event = ready(); event["uid"] = 0
        with self.assertRaises(Refusal): validate_ready(event, NONCE, controls_sha({}))
    def test_plan_is_finite_and_has_every_boundary_class(self):
        plan = probe_plan("1.1.1.1", "172.17.0.1")
        self.assertEqual(len(plan), 13)
        self.assertEqual(sum(row["positive"] for row in plan), 1)
        self.assertEqual({row["operation"] for row in plan}, {"tcp", "udp"})
        for bad in ("127.0.0.1", "169.254.169.254", "10.1.2.3"):
            with self.assertRaises(Refusal): probe_plan(bad, "172.17.0.1")
    def test_timeouts_errors_and_udp_sent_do_not_establish_denial(self):
        plan = probe_plan("1.1.1.1", "172.17.0.1")
        for case in plan[1:]:
            outcome = "sent" if case["operation"] == "udp" else "timeout"
            result = {key: case[key] for key in ("id", "operation", "address", "port")}
            result.update(event="result", outcome=outcome)
            self.assertFalse(assess_probe(case, result, {"packets": 0, "bytes": 0}, {"packets": 0, "bytes": 0})["passed"])
            self.assertTrue(assess_probe(case, result, {"packets": 0, "bytes": 0}, {"packets": 1, "bytes": 64})["passed"])
    def test_connected_negative_cannot_pass_despite_counter_noise(self):
        case = probe_plan("1.1.1.1", "172.17.0.1")[1]
        result = {key: case[key] for key in ("id", "operation", "address", "port")}
        result.update(event="result", outcome="connected")
        self.assertFalse(assess_probe(case, result, {"packets": 0, "bytes": 0}, {"packets": 1, "bytes": 64})["passed"])
    def test_positive_requires_actual_connection_and_counters_cannot_regress(self):
        case = probe_plan("1.1.1.1", "172.17.0.1")[0]
        result = {key: case[key] for key in ("id", "operation", "address", "port")}
        result.update(event="result", outcome="connected")
        self.assertTrue(assess_probe(case, result, {"packets": 0, "bytes": 0}, {"packets": 0, "bytes": 0})["passed"])
        self.assertFalse(assess_probe(case, result, {"packets": 0, "bytes": 0}, {"packets": 1, "bytes": 64})["passed"])
        with self.assertRaises(Refusal): assess_probe(case, result, {"packets": 2, "bytes": 128}, {"packets": 1, "bytes": 64})
    def test_no_qualification_without_all_results_final_filter_and_cleanup(self):
        rows = [{"passed": True}] * 13
        self.assertTrue(confinement_result(True, rows, True, True, True, True))
        self.assertFalse(confinement_result(True, rows[:-1], True, True, True, True))
        self.assertFalse(confinement_result(True, rows, False, True, True, True))
        self.assertFalse(confinement_result(True, rows, True, False, True, True))
        self.assertFalse(confinement_result(True, rows, True, True, False, True))
        self.assertFalse(confinement_result(True, rows, True, True, True, False))

if __name__ == "__main__":
    if sys.argv[1:] == ["--check-current-environment"]:
        check_environment(os.environ)
        print("Current inherited controls permit the selected boundary preparation; no environment values logged.")
    else:
        unittest.main(verbosity=2)
