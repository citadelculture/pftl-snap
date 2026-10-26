"""Separate locked compiler/build admission, with historical proof recomputation."""
import datetime as dt
from boundary_contract import IMAGE, check_environment
from egress_policy import HEAD, exact_keys, utc
from install_contract import actual_boundary_report, digest_bytes
from namespace_filter import Refusal, unique_json

BUILD_PAYLOAD_SHA = '534290266513aee886e459f741e06fc9bed5da6cf0b133bb88138137775977e8'
LOCK_SHA = '7e7d3d81d902cc4af88f38cf3a43eb831eeb20861d9097b23b4859f4844e4340'
INSTALL_RESULT_SHA = 'dad90af019cc281f379d6f2ebec3efd000e21ad990527c7831ff887c0de0d607'
INSTALL_PROVENANCE_SHA = 'f987ff88c464eace566a8c2a1c2c3a656500d94f73506c468cd2161e0a5fad09'
PHASE_SECONDS = {'immutable': 900, 'compiler-identity': 30, 'typecheck': 300, 'production-build': 300}
PHASES = list(PHASE_SECONDS)


def actual_install(result_data, provenance_data):
    if digest_bytes(result_data) != INSTALL_RESULT_SHA or digest_bytes(provenance_data) != INSTALL_PROVENANCE_SHA:
        raise Refusal('Exact successful install evidence required')
    result, provenance = unique_json(result_data), unique_json(provenance_data)
    if (provenance.get('runId') != 40251608388 or provenance.get('headSha') != 'f4cf957ce33f5bafb7cab2e4a5af75bbb851476c'
            or provenance.get('workflowPath') != '.github/workflows/pr6-original-hook-install.yml'
            or provenance.get('status') != 'completed' or provenance.get('conclusion') != 'success'
            or provenance.get('resultSha256') != INSTALL_RESULT_SHA
            or provenance.get('candidateLockSha256') != LOCK_SHA
            or result.get('qualified') is not True or result.get('installExecuted') is not True
            or result.get('hookOrPolicyModified') is not False or result.get('cleanupVerified') is not True
            or result.get('cleanupErrors') != [] or result.get('hostHomeUnchanged') is not True
            or result.get('candidateLockSha256') != LOCK_SHA
            or result.get('lockValidation') != {'originalDescriptors': 3757, 'candidateDescriptors': 3846, 'originalResolutionsAndChecksumsPreserved': True}):
        raise Refusal('Original-hook install completion/lock/cleanup not established')
    phases = result.get('phases', [])
    if [p.get('phase') for p in phases] != ['generate', 'immutable']:
        raise Refusal('Both actual install phases required')
    if any(type(p.get('exitCode')) is not int or p['exitCode'] != 0 or p.get('oomKilled') is not False
           or p.get('runningAfter') is not False or p.get('stopReason') is not None for p in phases):
        raise Refusal('Actual install phase failed')
    return {'successfulInstallRunId': 40251608388, 'successfulInstallResultSha256': INSTALL_RESULT_SHA,
            'candidateLockSha256': LOCK_SHA, 'historicalInstallReexecuted': False}


def build_admission(admission, report_data, provenance_data, environment, now, *, install_result, install_provenance):
    exact_keys(admission, {'schemaVersion', 'operation', 'executionAdmitted', 'repository', 'sourceHead',
                           'payloadManifestSha256', 'candidateLockSha256', 'image', 'boundaryReportSha256',
                           'boundaryProvenanceSha256', 'successfulInstallResultSha256', 'successfulInstallProvenanceSha256',
                           'allowedPhases', 'originalHookRequired', 'rootPoliciesUnchanged', 'buildNativeEffectsReviewed', 'expiresAtUtc'})
    if (admission['schemaVersion'] != 1 or admission['operation'] != 'locked-host-lite-compiler-build'
            or admission['executionAdmitted'] is not True or admission['repository'] != 'citadelculture/pftl-snap'
            or admission['sourceHead'] != HEAD or admission['payloadManifestSha256'] != BUILD_PAYLOAD_SHA
            or admission['candidateLockSha256'] != LOCK_SHA or admission['image'] != IMAGE
            or admission['allowedPhases'] != PHASES
            or any(admission[k] is not True for k in ('originalHookRequired', 'rootPoliciesUnchanged', 'buildNativeEffectsReviewed'))
            or admission['boundaryReportSha256'] != digest_bytes(report_data)
            or admission['boundaryProvenanceSha256'] != digest_bytes(provenance_data)
            or admission['successfulInstallResultSha256'] != INSTALL_RESULT_SHA
            or admission['successfulInstallProvenanceSha256'] != INSTALL_PROVENANCE_SHA
            or now.tzinfo is None or not dt.timedelta(0) < utc(admission['expiresAtUtc']) - now <= dt.timedelta(hours=1)):
        raise Refusal('Separate exact locked-build/native admission missing')
    check_environment(environment)
    if environment.get('GITHUB_REPOSITORY') != 'citadelculture/pftl-snap' or environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise Refusal('Exact owned manual workflow required')
    proof = actual_boundary_report(report_data, unique_json(provenance_data), now)
    proof.update(actual_install(install_result, install_provenance))
    proof['buildPayloadManifestSha256'] = BUILD_PAYLOAD_SHA
    return proof


def phase_admission(admission, report_data, provenance_data, environment, now, *, phase, install_result, install_provenance):
    if phase not in PHASE_SECONDS:
        raise Refusal('Unadmitted compiler/build phase')
    proof = build_admission(admission, report_data, provenance_data, environment, now,
                            install_result=install_result, install_provenance=install_provenance)
    if now + dt.timedelta(seconds=PHASE_SECONDS[phase] + 30) >= utc(admission['expiresAtUtc']):
        raise Refusal('Build admission cannot cover phase and cleanup allowance')
    return proof
