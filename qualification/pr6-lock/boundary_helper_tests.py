"""Pure synthetic decision tests; no subprocess, DNS, Node, Docker or namespace tools."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from boundary_contract import (Refusal, assess_probe, check_environment, child_environment, confinement_result,
                               controls_sha, probe_plan)
import boundary_host
from boundary_host import (CommandFailure, alias_identity, bind_tools, package_aliases,
                           package_ownership, validate_container, validate_ready,
                           failure_label, namespace_operation, nft_diagnostic, record_namespace_result)
from egress_policy import Refusal as TrustedPolicyRefusal
from egress_policy import verify_readback as verify_policy_readback

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

class ProtectedPackageAliases(unittest.TestCase):
    row = {"path": "/usr/sbin/ip", "sha256": "a" * 64}
    def identify(self, candidate, row):
        return {"path": candidate, "eligible": True, "canonicalPath": row["path"],
                "device": 2, "inode": 19, "sameCanonicalTarget": True, "sameDeviceAndInode": True}
    def test_candidates_are_only_exact_conventional_spellings(self):
        self.assertEqual(package_aliases("/usr/sbin/ip"), ["/usr/sbin/ip", "/sbin/ip"])
        self.assertEqual(package_aliases("/usr/bin/nsenter"), ["/usr/bin/nsenter", "/bin/nsenter"])
        with self.assertRaises(Refusal): package_aliases("/tmp/ip")
    def test_canonical_owner_needs_no_alias_lookup(self):
        query = mock.Mock(return_value="iproute2: /usr/sbin/ip\n")
        result = package_ownership(self.row, [], query, self.identify)
        self.assertEqual(result["packages"], ["iproute2"])
        query.assert_called_once_with(["/usr/bin/dpkg-query", "-S", "/usr/sbin/ip"])
    def test_merged_usr_alias_is_accepted_only_after_exact_miss(self):
        miss = CommandFailure(["/usr/bin/dpkg-query"], 1, b"", b"synthetic no matching path")
        query = mock.Mock(side_effect=[miss, "iproute2:amd64: /sbin/ip\n"])
        attempts = []
        result = package_ownership(self.row, attempts, query, self.identify)
        self.assertEqual(result, {"path": "/sbin/ip", "packages": ["iproute2:amd64"], "record": "iproute2:amd64: /sbin/ip"})
        self.assertEqual([row["path"] for row in attempts], ["/usr/sbin/ip", "/sbin/ip"])
        self.assertEqual(attempts[0]["lookup"]["exitCode"], 1)
        self.assertNotIn("synthetic no matching path", json.dumps(attempts))
    def test_unknown_ownership_and_absent_alias_remain_fail_closed(self):
        miss = CommandFailure(["/usr/bin/dpkg-query"], 1, b"", b"synthetic miss")
        def identify(candidate, row):
            return self.identify(candidate, row) if candidate==row["path"] else {"path":candidate,"eligible":False,"reason":"absent"}
        query = mock.Mock(side_effect=miss)
        with self.assertRaises(Refusal): package_ownership(self.row, [], query, identify)
        self.assertEqual(query.call_count, 1)
    def test_nonlookup_command_failures_never_trigger_alias_fallback(self):
        for code, output in [(2, b""), (1, b"unexpected partial output")]:
            query = mock.Mock(side_effect=CommandFailure(["/usr/bin/dpkg-query"], code, output, b"synthetic"))
            with self.subTest(code=code), self.assertRaises(CommandFailure):
                package_ownership(self.row, [], query, self.identify)
            self.assertEqual(query.call_count, 1)
    def test_wrong_path_glob_diversion_duplicate_and_invalid_owner_are_rejected(self):
        for output in ["iproute2: /tmp/ip", "iproute2: /usr/sbin/*", "diversion by hostile from: /usr/sbin/ip",
                       "iproute2: /usr/sbin/ip\niproute2: /usr/sbin/ip", "hostile;exec: /usr/sbin/ip", ""]:
            with self.subTest(output=output), self.assertRaises(Refusal):
                package_ownership(self.row, [], lambda argv: output, self.identify)
    def test_post_lookup_target_swap_is_rejected(self):
        first = self.identify(self.row["path"], self.row)
        identify = mock.Mock(side_effect=[first, {**first, "inode":20}])
        with self.assertRaises(Refusal):
            package_ownership(self.row, [], lambda argv:"iproute2: /usr/sbin/ip", identify)
    def check_identity(self, *, inode=19, device=2, target="/usr/sbin/ip", uid=0, mode=0o755, parent_uid=0, parent_mode=0o755, elf=True, pin=True):
        canonical = Path(self.row["path"]); alias = Path("/sbin/ip")
        file_info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_dev=2, st_ino=19)
        alias_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_dev=device, st_ino=inode)
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | parent_mode, st_uid=parent_uid)
        def lstat(path): return file_info if path==canonical else alias_info
        def actual_stat(path): return directory if path==canonical.parent else alias_info
        def resolve(path, strict=False): return Path(target) if path==alias else canonical.parent
        with mock.patch.object(Path,"lstat",lstat), mock.patch.object(Path,"stat",actual_stat), mock.patch.object(Path,"resolve",resolve), \
             mock.patch.object(Path,"open",lambda *args,**kwargs:io.BytesIO(b"\x7fELF" if elf else b"fake")), \
             mock.patch.object(boundary_host,"digest",return_value=self.row["sha256"] if pin else "b"*64):
            return alias_identity(str(alias), self.row)
    def test_alias_requires_same_actual_inode_device_and_canonical_target(self):
        self.assertTrue(self.check_identity()["eligible"])
        for change in ({"inode":20},{"device":3},{"target":"/tmp/ip"},{"uid":1000},{"mode":0o777},
                       {"parent_uid":1000},{"parent_mode":0o777},{"elf":False},{"pin":False}):
            with self.subTest(change=change), self.assertRaises(Refusal): self.check_identity(**change)
    def test_failure_report_identifies_tool_phase_without_raw_diagnostics(self):
        progress=[]
        with mock.patch.object(boundary_host,"canonical_elf",return_value=self.row), \
             mock.patch.object(boundary_host,"bounded",return_value="synthetic version"), \
             mock.patch.object(boundary_host,"package_ownership",side_effect=Refusal("synthetic refusal")):
            with self.assertRaisesRegex(Refusal,"nsenter:package-ownership"): bind_tools(progress)
        self.assertEqual(progress[0]["tool"],"nsenter")
        self.assertEqual(progress[0]["phase"],"package-ownership")
        self.assertEqual(progress[0]["status"],"failed")

class BoundedTrustedDiagnostics(unittest.TestCase):
    paths={"nsenter":"/usr/bin/nsenter","nft":"/usr/sbin/nft","ip":"/usr/bin/ip"}
    prefix=["/usr/bin/nsenter","--net=/proc/self/fd/7","--"]
    def test_distinct_pinned_helper_refusal_survives_without_class_name_confusion(self):
        error=TrustedPolicyRefusal("Unexpected existing tables; no unknown NAT/filter coexistence or replacement")
        self.assertIsNot(type(error), Refusal)
        self.assertEqual(failure_label(error,(TrustedPolicyRefusal,)),str(error))
        self.assertEqual(failure_label(error),"Refusal")
    def test_unrelated_same_name_and_subclasses_never_leak_error_text(self):
        OtherRefusal=type("Refusal",(ValueError,),{})
        Derived=type("Derived",(TrustedPolicyRefusal,),{})
        for error in (RuntimeError("SYNTHETIC_SECRET /home/private"),OtherRefusal("SYNTHETIC_SECRET"),Derived("SYNTHETIC_SECRET")):
            self.assertNotIn("SYNTHETIC_SECRET",failure_label(error,(TrustedPolicyRefusal,)))
        self.assertNotIn("\n",failure_label(TrustedPolicyRefusal("unsafe\nmessage"),(TrustedPolicyRefusal,)))
        self.assertLess(len(failure_label(TrustedPolicyRefusal("x"*513),(TrustedPolicyRefusal,))),513)
    def test_exact_host_and_child_operations_are_captured_without_output(self):
        host=namespace_operation([self.paths["ip"],"-j","address","show"],None,self.paths,7)
        child=namespace_operation(self.prefix+[self.paths["nft"],"-j","-n","list","tables"],None,self.paths,7)
        self.assertEqual(host["scope"],"host")
        self.assertEqual(host["operation"],"interface-inventory")
        self.assertEqual(child["argv"],self.prefix+[self.paths["nft"],"-j","-n","list","tables"])
        self.assertEqual(child["operation"],"nft-tables")
    def test_unknown_commands_other_namespace_fd_and_stdin_bounds_refuse(self):
        invalid=[([self.paths["nft"],"-j","-n","list","tables"],None),
                 ([self.paths["ip"],"-j","address","show","/home/private"],None),
                 ([self.paths["nsenter"],"--net=/proc/self/fd/8","--",self.paths["ip"],"-j","address","show"],None),
                 (self.prefix+[self.paths["nft"],"-j","-f","-"],"x"*(1024**2+1)),
                 ([self.paths["ip"],"-j","address","show"],"unexpected input")]
        for command,data in invalid:
            with self.subTest(command=command),self.assertRaises(Refusal): namespace_operation(command,data,self.paths,7)
    def test_bounded_nft_json_is_preserved_as_parsed_structure(self):
        document={"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"pftl_lock_egress","handle":3}}]}
        result=nft_diagnostic(json.dumps(document).encode())
        self.assertTrue(result["captured"])
        self.assertEqual(result["parsed"],document)
    def test_full_owned_rule_readback_preserves_meta_keys_and_actual_counter_shape(self):
        document={"nftables":[
            {"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak #3","json_schema_version":1}},
            {"table":{"family":"inet","name":"pftl_lock_egress","handle":1}},
            {"chain":{"family":"inet","table":"pftl_lock_egress","name":"output","type":"filter",
                      "hook":"output","prio":-300,"policy":"drop","handle":2}},
            {"chain":{"family":"inet","table":"pftl_lock_egress","name":"forward","type":"filter",
                      "hook":"forward","prio":-300,"policy":"drop","handle":3}},
            {"rule":{"family":"inet","table":"pftl_lock_egress","chain":"output","handle":4,"expr":[
                {"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},
                {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"1.1.1.1"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
                {"accept":None}]}},
            {"rule":{"family":"inet","table":"pftl_lock_egress","chain":"output","handle":5,
                     "expr":[{"counter":{"packets":13,"bytes":832}},{"drop":None}]}}
        ]}
        # Independent literal fixture must also satisfy the unchanged policy verifier.
        verified=verify_policy_readback(document,("1.1.1.1",))
        self.assertTrue(verified["exactReadback"])
        self.assertEqual(verified["outputDropCounter"],{"packets":13,"bytes":832})
        diagnostic=nft_diagnostic(json.dumps(document).encode())
        self.assertTrue(diagnostic["captured"])
        self.assertEqual(diagnostic["parsed"],document)
        for key,value in (("unknown", "synthetic"),("comment", "/home/private")):
            changed=copy.deepcopy(document);changed["nftables"][4]["rule"][key]=value
            refused=nft_diagnostic(json.dumps(changed).encode())
            self.assertFalse(refused["captured"])
            self.assertNotIn("parsed",refused)
    def test_large_duplicate_deep_and_private_shaped_nft_outputs_are_hash_only(self):
        deeply_nested=[];cursor=deeply_nested
        for _ in range(18): child=[];cursor.append(child);cursor=child
        outputs=[b"x"*65537,b'{"nftables":[],"nftables":[]}',b'{"nftables":[{"table":{"name":"/home/private"}}]}',
                 b'{"nftables":[{"comment":"SYNTHETIC_SECRET"}]}',json.dumps({"nftables":deeply_nested}).encode(),
                 json.dumps({"nftables":[None]*4100}).encode()]
        for output in outputs:
            result=nft_diagnostic(output)
            self.assertFalse(result["captured"])
            self.assertNotIn("parsed",result)
            self.assertNotIn("SYNTHETIC_SECRET",json.dumps(result))
            self.assertEqual(result["sha256"],hashlib.sha256(output).hexdigest())
    def test_interface_route_and_stderr_payloads_never_enter_report(self):
        report={}
        op=namespace_operation([self.paths["ip"],"-j","address","show"],None,self.paths,7)
        record_namespace_result(report,op,b'SYNTHETIC_INTERFACE_DATA',b'SYNTHETIC_STDERR /home/private',1)
        self.assertNotIn("nftDiagnosticReadbacks",report)
        self.assertNotIn("SYNTHETIC",json.dumps({"report":report,"operation":op}))
        self.assertEqual(op["exitCode"],1)
    def test_only_two_latest_nft_snapshots_are_retained(self):
        report={}
        for _ in range(4):
            for suffix in (["tables"],["table","inet","pftl_lock_egress"]):
                operation=namespace_operation(self.prefix+[self.paths["nft"],"-j","-n","list",*suffix],None,self.paths,7)
                record_namespace_result(report,operation,b'{"nftables":[]}',b'',0)
        self.assertEqual(set(report["nftDiagnosticReadbacks"]),{"nft-tables","nft-owned-table"})

class ExactReadbackCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw=(Path(__file__).resolve().parent/"fixtures/nft-1.0.9-captured-readback.json").read_bytes()
        if hashlib.sha256(raw).hexdigest()!="cf403d3de5e8187ee61633b272c1324e563d887b5e5ecab9a24349731bf2cc43":
            raise AssertionError("Captured fixture byte pin mismatch")
        cls.fixture=json.loads(raw)
    def forms(self):
        canonical=copy.deepcopy(self.fixture["readback"])
        explicit=copy.deepcopy(canonical)
        for item in explicit["nftables"]:
            rule=item.get("rule")
            if rule and rule["expr"][-1]=={"accept":None}:
                rule["expr"][:0]=[
                    {"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},
                    {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}}]
        return {"typed-payload-protocol-canonical":canonical,"explicit-protocol-guards":explicit}
    def payload(self, document, field):
        return next(expression["match"] for expression in document["nftables"][4]["rule"]["expr"]
                    if expression.get("match",{}).get("left",{}).get("payload",{}).get("field")==field)
    def assert_mutations_refuse(self, mutations):
        for representation,original in self.forms().items():
            for label,mutate in mutations.items():
                document=copy.deepcopy(original);mutate(document)
                with self.subTest(representation=representation,mutation=label),self.assertRaises(TrustedPolicyRefusal):
                    verify_policy_readback(document,tuple(self.fixture["addresses"]))
    def test_actual_captured_readback_is_pure_replay_not_runtime_qualification(self):
        self.assertEqual(self.fixture["origin"]["runId"],40248118244)
        self.assertEqual(self.fixture["origin"]["reportSha256"],"b528a85c7d20333923bea5531bbf65b973919dc718cb56130058ffffd37869c4")
        self.assertEqual(self.fixture["origin"]["rawNftStdoutSha256"],"4795e97f2fab5cd64384268f477ffebd25df1a37e0c963510c0caf8c6691eed3")
        self.assertEqual(self.fixture["origin"]["actualNetworkProbeCount"],0)
        self.assertIs(self.fixture["origin"]["actualRuntimeConfinementQualified"],False)
        result=verify_policy_readback(self.fixture["readback"],tuple(self.fixture["addresses"]))
        self.assertEqual(result["readbackRepresentation"],"typed-payload-protocol-canonical")
        self.assertEqual(result["outputDropCounter"],{"packets":0,"bytes":0})
    def test_exact_whole_explicit_and_typed_payload_forms_are_accepted(self):
        for name,document in self.forms().items():
            self.assertEqual(verify_policy_readback(document,tuple(self.fixture["addresses"]))["readbackRepresentation"],name)
    def test_udp_ipv6_raw_payload_wrong_port_address_field_and_operator_refuse(self):
        self.assert_mutations_refuse({
            "udp":lambda d:self.payload(d,"dport")["left"]["payload"].update(protocol="udp"),
            "ipv6":lambda d:self.payload(d,"daddr")["left"]["payload"].update(protocol="ip6"),
            "raw-payload":lambda d:self.payload(d,"daddr").update(left={"payload":{"base":"network header","offset":16,"len":32}}),
            "wrong-port":lambda d:self.payload(d,"dport").update(right=80),
            "wrong-address":lambda d:self.payload(d,"daddr").update(right="1.1.1.1"),
            "wrong-field":lambda d:self.payload(d,"daddr")["left"]["payload"].update(field="saddr"),
            "wrong-operator":lambda d:self.payload(d,"dport").update(op="!=")})
    def test_rule_match_order_extra_or_missing_accept_and_early_drop_refuse(self):
        def reorder_matches(d):
            expr=d["nftables"][4]["rule"]["expr"];expr[-3],expr[-2]=expr[-2],expr[-3]
        def reorder_rules(d): d["nftables"][4],d["nftables"][5]=d["nftables"][5],d["nftables"][4]
        def early_drop(d): d["nftables"].insert(4,d["nftables"].pop())
        self.assert_mutations_refuse({"match-order":reorder_matches,"rule-order":reorder_rules,
            "extra-rule":lambda d:d["nftables"].insert(-1,copy.deepcopy(d["nftables"][4])),
            "missing-rule":lambda d:d["nftables"].pop(4),"early-drop":early_drop,
            "missing-address-match":lambda d:d["nftables"][4]["rule"]["expr"].remove({"match":self.payload(d,"daddr")})})
    def test_missing_duplicate_or_invalid_counters_refuse(self):
        self.assert_mutations_refuse({
            "missing-counter":lambda d:d["nftables"][-1]["rule"]["expr"].pop(0),
            "duplicate-counter":lambda d:d["nftables"][-1]["rule"]["expr"].insert(0,{"counter":{"packets":0,"bytes":0}}),
            "negative-counter":lambda d:d["nftables"][-1]["rule"]["expr"][0]["counter"].update(packets=-1),
            "boolean-counter":lambda d:d["nftables"][-1]["rule"]["expr"][0]["counter"].update(bytes=True),
            "extra-counter-field":lambda d:d["nftables"][-1]["rule"]["expr"][0]["counter"].update(extra=1)})
    def test_hooks_priority_policy_family_and_schema_remain_exact(self):
        self.assert_mutations_refuse({
            "output-hook":lambda d:d["nftables"][2]["chain"].update(hook="input"),
            "forward-hook":lambda d:d["nftables"][3]["chain"].update(hook="input"),
            "priority":lambda d:d["nftables"][2]["chain"].update(prio=0),
            "output-policy":lambda d:d["nftables"][2]["chain"].update(policy="accept"),
            "forward-policy":lambda d:d["nftables"][3]["chain"].update(policy="accept"),
            "table-family":lambda d:d["nftables"][1]["table"].update(family="ip"),
            "schema":lambda d:d["nftables"][0]["metainfo"].update(json_schema_version=2)})
    def test_partial_guards_and_mixed_rule_representations_refuse(self):
        explicit=self.forms()["explicit-protocol-guards"]
        for pattern in ("only-nfproto","only-l4proto","one-explicit-rule"):
            document=copy.deepcopy(self.fixture["readback"])
            for index,item in enumerate(document["nftables"]):
                if "rule" not in item or item["rule"]["expr"][-1]!={"accept":None}: continue
                guards=copy.deepcopy(explicit["nftables"][index]["rule"]["expr"][:2])
                if pattern=="only-nfproto": item["rule"]["expr"][:0]=guards[:1]
                elif pattern=="only-l4proto": item["rule"]["expr"][:0]=guards[1:]
                elif index==4: item["rule"]["expr"][:0]=guards
            with self.subTest(pattern=pattern),self.assertRaises(TrustedPolicyRefusal):
                verify_policy_readback(document,tuple(self.fixture["addresses"]))

if __name__ == "__main__":
    if sys.argv[1:] == ["--check-current-environment"]:
        check_environment(os.environ)
        print("Current inherited controls permit the selected boundary preparation; no environment values logged.")
    else:
        unittest.main(verbosity=2)
