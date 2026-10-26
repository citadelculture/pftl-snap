"""Pure admission decisions. A pinned actual report is required; no runtime here."""
import datetime as dt
import hashlib
import json
import re
from boundary_contract import IMAGE, HELPERS, assess_probe, check_environment, probe_plan
from egress_policy import HEAD, PAYLOAD_SHA, exact_keys, utc, validate_policy
from namespace_filter import Refusal, unique_json

BOUNDARY_COMMIT = "c1e3f4f52f286ab0133e56b472a975cfde8cb9d1"
BOUNDARY_SOURCES = {
    **HELPERS,
    "boundary_host.py": "4353f50ce7d66ff728fd62bf350b5b672cc156160baa2f8687a63c4a7e8a687d",
    "boundary_contract.py": "6e5c9215f9f4c1619278681ec59dc76c69f3b03db0e568301ea2a4d74f061751",
    "boundary_probe.cjs": "1b84490f8a9cf3a6f9899c158d1792c6cf058984cba5f5594fc9eab436fb4644",
}
REPOSITORY = "citadelculture/pftl-snap"

def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()

def actual_boundary_report(report_data, provenance, now):
    """Validate a root-pinned receipt and separately observed public run provenance.

    This recomputes recorded decisions, not past traffic; provenance authenticity
    is supplied by the normal-reviewed exact SHA pin in the workflow revision.
    """
    exact_keys(provenance, {"schemaVersion", "repository", "runId", "runAttempt", "headSha", "workflowPath",
                            "status", "conclusion", "completedAtUtc", "artifactName", "reportSha256"})
    if (provenance["schemaVersion"] != 1 or provenance["repository"] != REPOSITORY
            or provenance["headSha"] != BOUNDARY_COMMIT
            or provenance["workflowPath"] != ".github/workflows/pr6-lock-qualification.yml"
            or provenance["status"] != "completed" or provenance["conclusion"] != "success"
            or provenance["artifactName"] != "pr6-confinement-boundary"
            or type(provenance["runId"]) is not int or provenance["runId"] <= 0
            or type(provenance["runAttempt"]) is not int or provenance["runAttempt"] <= 0
            or digest_bytes(report_data) != provenance["reportSha256"]):
        raise Refusal("Actual successful exact boundary run provenance required")
    completed = utc(provenance["completedAtUtc"])
    if now.tzinfo is None or not dt.timedelta(0) <= now-completed <= dt.timedelta(hours=24):
        raise Refusal("Boundary evidence is future-dated or outside the24-hour admission window")
    report = unique_json(report_data)
    if (report.get("schemaVersion") != 1 or report.get("kind") != "confinement-boundary-only"
            or report.get("image") != IMAGE or report.get("sourcePins") != BOUNDARY_SOURCES
            or report.get("sourcePinsPreserved") is not True or report.get("packageCommandsExecuted") is not False
            or report.get("fullInstallAdmitted") is not False or report.get("confinementQualified") is not True
            or report.get("setupComplete") is not True or report.get("finalFilterValid") is not True
            or report.get("workloadCompleted") is not True or report.get("ipv6LoopbackRoutePresent") is not True
            or report.get("failures") != []):
        raise Refusal("Actual boundary report is incomplete, failed, or linked to different source/image")
    cleanup = report.get("cleanup", {})
    if (cleanup.get("complete") is not True or cleanup.get("errors") != []
            or cleanup.get("heldNamespaceFdClosed") is not True or cleanup.get("ownedContainerAbsent") is not True
            or cleanup.get("persistentVolumesCreated") != 0 or cleanup.get("tmpfsLifetime") != "owned container only"):
        raise Refusal("Boundary cleanup not established")
    ready = report.get("ready", {})
    if (ready.get("event") != "ready" or not re.fullmatch(r"[0-9a-f]{64}", ready.get("controlsSha256", ""))
            or ready.get("uid") != 1000 or ready.get("gid") != 1000 or ready.get("accountUid") != 1000
            or ready.get("accountGid") != 1000 or ready.get("accountHome") != "/home/node"
            or ready.get("homeMatchesRealAccount") is not True or ready.get("canaryRoundTrip") is not True
            or ready.get("unexpectedEnvironmentCount") != 0 or ready.get("dockerSocketStat") != "absent"
            or ready.get("nodeVersion") != "24.21.0" or ready.get("platform") != "linux" or ready.get("arch") != "x64"
            or ready.get("noNewPrivs") != "1" or ready.get("seccomp") != "2"
            or any(ready.get(key) != "0000000000000000" for key in ("capInh", "capPrm", "capEff", "capBnd", "capAmb"))):
        raise Refusal("Boundary account/control checks missing")
    if report.get("docker", {}).get("localRootfulDaemon") is not True or report.get("docker", {}).get("builtinSeccomp") is not True:
        raise Refusal("Boundary native local daemon contract missing")
    if not re.fullmatch(r"[0-9a-f]{32}", report.get("nonce", "")) or ready.get("nonce") != report["nonce"]:
        raise Refusal("Boundary process nonce binding missing")
    installed = report.get("filterInstall", {})
    observed_policy = report.get("endpointPolicy", {})
    if (installed.get("exactReadback") is not True or installed.get("namespaceEntry") != "network-only-held-fd"
            or installed.get("readbackRepresentation") not in ("explicit-protocol-guards", "typed-payload-protocol-canonical")
            or installed.get("outputPriority") != -300 or installed.get("ipv4DefaultDrop") is not True
            or installed.get("ipv6DefaultDrop") is not True or installed.get("dnsPermitted") is not False
            or installed.get("tcpDestinationPort") != 443 or installed.get("table") != "pftl_lock_egress"
            or installed.get("sourceCommandExecuted") is not False or installed.get("releaseAuthorized") is not False):
        raise Refusal("Boundary filter linkage missing")
    # Historical policy need not remain live; it must have covered the recorded
    # boundary. Install phases obtain new observations rather than reuse this.
    observed = utc(observed_policy.get("observedAtUtc", ""))
    addresses = validate_policy(observed_policy, observed, set(installed.get("hostAndContainerLocalAndGatewayAddressesExcluded", [])), phase_seconds=150)
    if list(addresses) != installed.get("addresses") or observed > completed:
        raise Refusal("Boundary endpoint/source binding missing")
    probes = report.get("probes")
    if not isinstance(probes, list) or len(probes) != 13:
        raise Refusal("Exactly13 executed boundary probes required")
    gateway = next((row.get("actual", {}).get("address") for row in probes if row.get("id") == "host_gateway"), None)
    expected = probe_plan(observed_policy["hosts"]["nodejs.org"][0], gateway)
    for case, row in zip(expected, probes):
        recomputed = assess_probe(case, row.get("actual", {}), row.get("counterBefore", {}), row.get("counterAfter", {}))
        if row != recomputed or recomputed["passed"] is not True:
            raise Refusal("Recorded probe outcome is skipped, substituted, or not supported by counters")
    if report.get("finalCounter") != probes[-1]["counterAfter"]:
        raise Refusal("Final kernel counter does not bind completed probe sequence")
    return {"boundaryReportSha256": provenance["reportSha256"], "boundaryRunId": provenance["runId"],
            "boundaryRunAttempt": provenance["runAttempt"], "boundaryCommit": BOUNDARY_COMMIT,
            "recordedProbesRecomputed": 13, "actualTrafficReexecuted": False,
            "readbackRepresentation": installed["readbackRepresentation"],
            "image": IMAGE, "helpers": HELPERS, "rootSourceHead": HEAD,
            "rootPayloadManifestSha256": PAYLOAD_SHA}

def install_admission(admission, report_data, provenance_data, environment, now):
    exact_keys(admission, {"schemaVersion", "operation", "executionAdmitted", "repository", "sourceHead",
                           "payloadManifestSha256", "image", "boundaryReportSha256", "boundaryProvenanceSha256",
                           "allowedPhases", "originalHookRequired", "rootPoliciesUnchanged", "nativeEffectsReviewed",
                           "expiresAtUtc"})
    if (admission["schemaVersion"] != 1 or admission["operation"] != "original-hook-full-install"
            or admission["executionAdmitted"] is not True or admission["repository"] != REPOSITORY
            or admission["sourceHead"] != HEAD or admission["payloadManifestSha256"] != PAYLOAD_SHA
            or admission["image"] != IMAGE or admission["allowedPhases"] != ["generate", "immutable"]
            or any(admission[key] is not True for key in ("originalHookRequired", "rootPoliciesUnchanged", "nativeEffectsReviewed"))
            or admission["boundaryReportSha256"] != digest_bytes(report_data)
            or admission["boundaryProvenanceSha256"] != digest_bytes(provenance_data)
            or not dt.timedelta(0) < utc(admission["expiresAtUtc"])-now <= dt.timedelta(hours=1)):
        raise Refusal("Separate exact original-hook/native full-install admission missing")
    check_environment(environment)
    if environment.get("GITHUB_REPOSITORY") != REPOSITORY or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise Refusal("Exact owned manual workflow required")
    return actual_boundary_report(report_data, unique_json(provenance_data), now)

def phase_admission(admission, report_data, provenance_data, environment, now, *, phase_seconds):
    """Re-evaluate exact proof and enough lifetime immediately before release."""
    if type(phase_seconds) is not int or phase_seconds <= 0 or phase_seconds > 900:
        raise Refusal("Unsupported phase duration")
    proof = install_admission(admission, report_data, provenance_data, environment, now)
    if now + dt.timedelta(seconds=phase_seconds + 30) >= utc(admission["expiresAtUtc"]):
        raise Refusal("Full-install admission cannot cover phase plus cleanup allowance")
    return proof
