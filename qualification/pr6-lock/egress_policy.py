"""Pure, fail-closed policy compiler. No DNS lookup or command execution."""
import datetime as dt
import ipaddress
import json

HEAD = "0820278c1cd38e6dd6a1ae38631889041bd6f9ba"
PAYLOAD_SHA = "2b34bd97b9610342d294e00d30a4ecbe131528c17449a9679c1b1cd3ec2a6545"
TABLE = "pftl_lock_egress"
HOSTS = frozenset({"registry.yarnpkg.com", "registry.npmjs.org", "github.com",
                   "release-assets.githubusercontent.com", "nodejs.org"})
AZURE_PLATFORM = "168.63.129.16"

class Refusal(ValueError):
    pass

def refuse_proxy_controls(environment):
    if any(key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"} for key in environment):
        raise Refusal("Inherited proxy controls require a separately reviewed proxy-compatible lane")

def refuse_docker_controls(environment):
    if any(key.startswith("DOCKER_") for key in environment):
        raise Refusal("Inherited Docker endpoint/configuration controls require separate admission")

def exact_keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Refusal("Unexpected object keys")

def utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Refusal("UTC timestamp ending Z required")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise Refusal("Invalid timestamp") from error
    return parsed

def address(value):
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError) as error:
        raise Refusal("Literal address required") from error
    if not isinstance(value, str) or str(ip) != value:
        raise Refusal("Canonical address required")
    return ip

def local_addresses(document):
    """Consume numeric `ip -j address show`; unexpected shapes fail closed."""
    if not isinstance(document, list) or not document:
        raise Refusal("Missing interface inventory")
    result = set()
    for interface in document:
        if not isinstance(interface, dict) or not isinstance(interface.get("addr_info"), list):
            raise Refusal("Unsupported interface inventory")
        for info in interface["addr_info"]:
            if not isinstance(info, dict) or info.get("family") not in {"inet", "inet6"}:
                raise Refusal("Unsupported address family")
            ip = address(info.get("local"))
            if (ip.version == 4) != (info["family"] == "inet"):
                raise Refusal("Interface family mismatch")
            result.add(str(ip))
    if not result:
        raise Refusal("Empty interface inventory")
    return result

def validate_policy(policy, now, forbidden_addresses, *, phase_seconds=0):
    exact_keys(policy, {"schemaVersion", "head", "payloadManifestSha256", "observedAtUtc",
                        "expiresAtUtc", "hosts"})
    if policy["schemaVersion"] != 1 or policy["head"] != HEAD or policy["payloadManifestSha256"] != PAYLOAD_SHA:
        raise Refusal("Workload binding mismatch")
    if now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        raise Refusal("Aware UTC clock required")
    created, expires = utc(policy["observedAtUtc"]), utc(policy["expiresAtUtc"])
    if created > now or expires <= now or not dt.timedelta(0) < expires-created <= dt.timedelta(minutes=30):
        raise Refusal("Stale, future, or overlong endpoint observation")
    if isinstance(phase_seconds, bool) or not isinstance(phase_seconds, int) or phase_seconds < 0:
        raise Refusal("Invalid phase duration")
    if now + dt.timedelta(seconds=phase_seconds + 30) >= expires:
        raise Refusal("Endpoint policy expires before bounded phase plus cleanup allowance")
    if not isinstance(forbidden_addresses, (set, frozenset)) or not forbidden_addresses:
        raise Refusal("Fresh local interface addresses required")
    forbidden = {str(address(value)) for value in forbidden_addresses} | {AZURE_PLATFORM}
    if not isinstance(policy["hosts"], dict) or not policy["hosts"] or not set(policy["hosts"]) <= HOSTS:
        raise Refusal("Unreviewed hostname")
    admitted = set()
    for host, values in policy["hosts"].items():
        if not isinstance(values, list) or not values or len(values) != len(set(values)):
            raise Refusal("Empty or duplicate host addresses")
        for value in values:
            ip = address(value)
            if ip.version != 4 or not ip.is_global or ip.is_multicast or ip.is_reserved or value in forbidden:
                raise Refusal("Nonpublic, local, metadata, reserved, or unsupported endpoint")
            admitted.add(value)
    if len(admitted) > 64:
        raise Refusal("Endpoint set exceeds bound")
    return tuple(sorted(admitted, key=lambda value: int(address(value))))

def match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}

def expected_objects(addresses):
    if not addresses:
        raise Refusal("Empty allowlist")
    objects = [{"table": {"family": "inet", "name": TABLE}},
               {"chain": {"family": "inet", "table": TABLE, "name": "output", "type": "filter",
                           "hook": "output", "prio": -300, "policy": "drop"}},
               {"chain": {"family": "inet", "table": TABLE, "name": "forward", "type": "filter",
                           "hook": "forward", "prio": -300, "policy": "drop"}}]
    # No ct-state exemption, set updates, DNS, IPv6, loopback, or generic 443 rule.
    for value in addresses:
        objects.append({"rule": {"family": "inet", "table": TABLE, "chain": "output", "expr": [
            match({"meta": {"key": "nfproto"}}, "ipv4"),
            match({"meta": {"key": "l4proto"}}, "tcp"),
            match({"payload": {"protocol": "ip", "field": "daddr"}}, value),
            match({"payload": {"protocol": "tcp", "field": "dport"}}, 443),
            {"accept": None}]}})
    objects.append({"rule": {"family": "inet", "table": TABLE, "chain": "output",
                             "expr": [{"counter": None}, {"drop": None}]}})
    return objects

def compile_rules(addresses):
    return {"nftables": [{"add": item} for item in expected_objects(addresses)]}

def verify_readback(document, addresses):
    exact_keys(document, {"nftables"})
    if not isinstance(document["nftables"], list):
        raise Refusal("Unsupported nft readback")
    actual = []
    drop_counter = None
    metadata_seen = False
    for item in document["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            raise Refusal("Malformed nft object")
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            if metadata_seen or not isinstance(value, dict) or value.get("json_schema_version") != 1:
                raise Refusal("Unsupported nft schema")
            metadata_seen = True
            continue
        if kind not in {"table", "chain", "rule"} or not isinstance(value, dict):
            raise Refusal("Unexpected nft object")
        # nft-generated handle IDs carry no policy meaning; everything else is exact.
        cleaned = {key: val for key, val in value.items() if key != "handle"}
        if kind == "rule" and isinstance(cleaned.get("expr"), list):
            expressions = []
            for expression in cleaned["expr"]:
                if isinstance(expression, dict) and set(expression) == {"counter"}:
                    counter = expression["counter"]
                    exact_keys(counter, {"packets", "bytes"})
                    if any(type(v) is not int or v < 0 for v in counter.values()) or drop_counter is not None:
                        raise Refusal("Invalid/duplicate kernel counter")
                    drop_counter = counter.copy()
                    expressions.append({"counter": None})
                else:
                    expressions.append(expression)
            cleaned["expr"] = expressions
        actual.append({kind: cleaned})
    # nft lists rules beside their chain; compare object classes separately while
    # retaining the exact rule order. No reordering can hide an earlier accept.
    expected = expected_objects(addresses)
    same = all([item for item in actual if kind in item] == [item for item in expected if kind in item]
               for kind in ("table", "chain", "rule"))
    if not metadata_seen or not same or drop_counter is None:
        raise Refusal("Kernel readback does not equal exact compiled policy")
    return {"exactReadback": True, "outputPriority": -300, "ipv4DefaultDrop": True,
            "ipv6DefaultDrop": True, "dnsPermitted": False, "tcpDestinationPort": 443,
            "addresses": list(addresses), "table": TABLE, "outputDropCounter": drop_counter}

def hosts_text(policy):
    return "# Immutable workload endpoint observations; no network DNS.\n" + "".join(
        value + " " + host + "\n" for host, values in sorted(policy["hosts"].items()) for value in sorted(values))

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
