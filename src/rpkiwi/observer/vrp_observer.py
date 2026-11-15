from __future__ import annotations

import ipaddress
import json
import socket
import struct
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from urllib.request import urlopen, Request
from urllib.error import URLError

try:
    import requests
except ImportError:
    requests = None

PDU_SERIAL_NOTIFY = 0
PDU_SERIAL_QUERY = 1
PDU_RESET_QUERY = 2
PDU_CACHE_RESPONSE = 3
PDU_IPV4_PREFIX = 4
PDU_IPV6_PREFIX = 6
PDU_END_OF_DATA = 7
PDU_CACHE_RESET = 8
PDU_ROUTER_KEY = 9
PDU_ERROR_REPORT = 10
PDU_ASPA = 11

FLAG_ANNOUNCEMENT = 1

REPO_ROOT = Path(__file__).resolve().parents[3]

BASELINE_VRPS = {
    ("3.0.0.0", 24, 24, 1000),
    ("4.0.0.0", 24, 24, 2000),
    ("5.0.0.0", 24, 24, 3000),
}
WARMUP_VRPS = {
    ("4.0.0.0", 24, 24, 2000),
    ("5.0.0.0", 24, 24, 3000),
}
BASELINE_ASPAS = {
    1000: {1001, 1002},
    2000: {1001, 1002},
    3000: {2001, 2002},
}

CANARY_VRP = ("5.0.0.0", 24, 24, 3000)
CANARY_VRP_T2 = ("5.1.0.0", 24, 24, 3000)
VICTIM_VRP_A = ("4.0.0.0", 24, 24, 2000)
VICTIM_VRP_B = ("4.1.0.0", 24, 24, 1001)
VICTIM_VRP_C = ("4.2.0.0", 24, 24, 1002)
ATTACKER_VRP = ("3.0.0.0", 24, 24, 1000)

CANARY_ASPA = (3000, frozenset({2001, 2002}))
VICTIM_ASPA = (2000, frozenset({1001, 1002}))
ATTACKER_ASPA = (1000, frozenset({1001, 1002}))

CANARY_V4_ZONE = ipaddress.ip_network("5.0.0.0/8")
VICTIM_V4_ZONE = ipaddress.ip_network("4.0.0.0/8")
ATTACKER_V4_ZONE = ipaddress.ip_network("3.0.0.0/8")

CANARY_ASN_RANGE = range(2001, 3001)
VICTIM_ASN_RANGE = range(1001, 2001)
ATTACKER_ASN_RANGE = range(1000, 1001)

VALIDATOR_CONFIG = {
    "routinator": {"host": "localhost", "port": 35001, "http_api": "http://localhost:35000/api/v1/origins/"},
    "cfrpki": {"type": "http_api", "url": "http://localhost:35002/output.json"},
    "fort-validator": {"host": "localhost", "port": 35005,
                       "docker_csv": {"container": "rpkiwi-fuzz_fort-validator_1",
                                      "path": "/var/local/fort/vrps.csv"}},
    "rpki-client": {"type": "docker_json",
                     "container": "rpkiwi-fuzz_rpki-client_1",
                     "path": "/var/lib/rpki-client/json"},
    "rpki-prover": {"host": "localhost", "port": 30283,
                     "type": "http_api_list", "url": "http://localhost:39999/api/vrps",
                     "aspa_url": "http://localhost:39999/api/aspa"},
    "rpki-validator-3": {"type": "docker_json_v3",
                          "url": "http://localhost:35011/api/objects/validated"},
    "rpstir2": {"type": "rpstir2_mysql",
                 "container": "rpkiwi-fuzz_rpstir2_1",
                 "mysql_container": "rpkiwi-fuzz_rpstir2-mysql_1"},
}

EXPECT_ASPA = {
    "routinator": True,
    "rpki-client": True,
    "cfrpki": False,
    "fort-validator": False,
    "rpki-prover": True,
    "rpki-validator-3": False,
    "rpstir2": False,
}

@dataclass
class ValidatorSnapshot:
    name: str
    vrps: list[dict] = field(default_factory=list)
    aspas: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

@dataclass
class ValidatorSemantics:
    canary_zone_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    canary_zone_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)
    victim_zone_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    victim_zone_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)
    canary_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    canary_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)
    victim_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    victim_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)
    attacker_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    attacker_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)
    victim_zone_unauthorized_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    victim_zone_unauthorized_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)

@dataclass
class Observation:
    validators: dict[str, ValidatorSnapshot]
    semantics: dict[str, ValidatorSemantics]

def _normalize_asn(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    return int(text)

def normalize_vrp_key(vrp: dict) -> tuple[str, int, int, int] | None:
    try:
        prefix = vrp.get("prefix", "")
        if "/" in prefix:
            ip_text, prefix_length = prefix.split("/", 1)
            prefix_length = int(prefix_length)
        else:
            ip_text = prefix
            prefix_length = int(vrp.get("prefix_length"))
        max_length = int(vrp.get("max_length", vrp.get("maxLength", prefix_length)))
        asn = _normalize_asn(vrp.get("asn"))
        normalized_ip = str(ipaddress.ip_network(f"{ip_text}/{prefix_length}", strict=False).network_address)
        return normalized_ip, prefix_length, max_length, asn
    except Exception:
        return None

def normalize_aspa_key(aspa: dict) -> tuple[int, frozenset[int]] | None:
    try:
        customer = aspa.get("customer_asn", aspa.get("customer_asid", aspa.get("customer")))
        customer = _normalize_asn(customer)
        providers = aspa.get("providers", aspa.get("providerAsns", []))
        normalized = set()
        for provider in providers:
            if isinstance(provider, dict):
                provider = provider.get("provider_asn", provider.get("asn", provider.get("provider")))
            normalized.add(_normalize_asn(provider))
        return customer, frozenset(normalized)
    except Exception:
        return None

def _ip_in_any_zone(ip_text: str, *zones: ipaddress._BaseNetwork) -> bool:
    ip = ipaddress.ip_address(ip_text)
    return any(ip in zone for zone in zones)

def derive_semantics(snapshot: ValidatorSnapshot) -> ValidatorSemantics:
    semantics = ValidatorSemantics()
    for vrp in snapshot.vrps:
        key = normalize_vrp_key(vrp)
        if key is None:
            continue
        ip_text, _, _, asn = key
        if _ip_in_any_zone(ip_text, CANARY_V4_ZONE):
            semantics.canary_zone_vrps.add(key)
        if key == CANARY_VRP:
            semantics.canary_vrps.add(key)
        if _ip_in_any_zone(ip_text, VICTIM_V4_ZONE):
            semantics.victim_zone_vrps.add(key)
            semantics.victim_zone_unauthorized_vrps.add(key)
        if key == ATTACKER_VRP:
            semantics.attacker_vrps.add(key)
    for aspa in snapshot.aspas:
        key = normalize_aspa_key(aspa)
        if key is None:
            continue
        customer, providers = key
        if customer in CANARY_ASN_RANGE:
            semantics.canary_zone_vaps.add(key)
        if key == CANARY_ASPA:
            semantics.canary_vaps.add(key)
        if customer in VICTIM_ASN_RANGE:
            semantics.victim_zone_vaps.add(key)
        if key == VICTIM_ASPA:
            semantics.victim_vaps.add(key)
        if key == ATTACKER_ASPA:
            semantics.attacker_vaps.add(key)
        if customer in VICTIM_ASN_RANGE and key != VICTIM_ASPA:
            semantics.victim_zone_unauthorized_vaps.add(key)
    return semantics

def _send_reset_query(sock: socket.socket, version: int) -> None:
    pdu = struct.pack("!BBHI", version, PDU_RESET_QUERY, 0, 8)
    sock.sendall(pdu)

def _receive_pdu(sock: socket.socket):
    header = b""
    while len(header) < 8:
        chunk = sock.recv(8 - len(header))
        if not chunk:
            return None
        header += chunk
    _, pdu_type, _, length = struct.unpack("!BBHI", header[:8])
    remaining = length - 8
    body = b""
    while len(body) < remaining:
        chunk = sock.recv(remaining - len(body))
        if not chunk:
            return None
        body += chunk
    return pdu_type, header + body

def rtr_collect(host: str, port: int, *, logger: Callable[[str], None] | None = None, version: int = 2) -> tuple[list[dict], list[dict]]:
    logger = logger or (lambda m: None)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        _send_reset_query(sock, version)
        vrps, aspas = [], []
        while True:
            result = _receive_pdu(sock)
            if result is None:
                break
            pdu_type, data = result
            if pdu_type == PDU_IPV4_PREFIX:
                _, _, _, _ = struct.unpack("!BBHI", data[:8])
                flags, prefix_len, max_len, _ = struct.unpack("!BBBB", data[8:12])
                prefix = socket.inet_ntoa(data[12:16])
                asn = struct.unpack("!I", data[16:20])[0]
                vrps.append({"prefix": prefix, "prefix_length": prefix_len, "max_length": max_len, "asn": asn})
            elif pdu_type == PDU_IPV6_PREFIX:
                _, _, _, _ = struct.unpack("!BBHI", data[:8])
                _, prefix_len, max_len, _ = struct.unpack("!BBBB", data[8:12])
                prefix = socket.inet_ntop(socket.AF_INET6, data[12:28])
                asn = struct.unpack("!I", data[28:32])[0]
                vrps.append({"prefix": prefix, "prefix_length": prefix_len, "max_length": max_len, "asn": asn})
            elif pdu_type == PDU_ASPA:
                _, _, flags, length = struct.unpack("!BBHI", data[:8])
                customer_asn = struct.unpack("!I", data[8:12])[0]
                provider_count = (length - 12) // 4
                providers = [struct.unpack("!I", data[12 + i*4:16 + i*4])[0] for i in range(provider_count)]
                aspas.append({"customer_asn": customer_asn, "providers": providers})
            elif pdu_type == PDU_END_OF_DATA:
                break
            elif pdu_type == PDU_CACHE_RESET:
                break
            elif pdu_type == PDU_ERROR_REPORT:
                if version > 0:
                    sock.close()
                    logger(f"  RTR version {version} rejected, falling back to version {version - 1}")
                    return rtr_collect(host, port, logger=logger, version=version - 1)
                break
        sock.close()
        return vrps, aspas
    except Exception as exc:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        logger(f"  RTR error: {exc}")
        return [], []

def _fetch_json(url: str, timeout: int = 10) -> dict | None:
    if requests is not None:
        try:
            resp = requests.get(url, timeout=timeout)
            return resp.json()
        except Exception:
            pass
    try:
        with urlopen(Request(url), timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

def collect_http_json(url: str, *, logger: Callable[[str], None] | None = None) -> tuple[list[dict], list[dict]]:
    logger = logger or (lambda m: None)
    data = _fetch_json(url)
    if data is None:
        logger(f"  HTTP API returned no data from {url}")
        return [], []
    vrps = data.get("roas", [])
    normalized = []
    for vrp in vrps:
        entry = dict(vrp)
        if "maxLength" in entry and "max_length" not in entry:
            entry["max_length"] = entry["maxLength"]
        if "prefix" in entry and "/" in str(entry["prefix"]):
            parts = str(entry["prefix"]).split("/", 1)
            entry["prefix"] = parts[0]
            entry["prefix_length"] = int(parts[1])
        normalized.append(entry)
    logger(f"  HTTP API: {len(normalized)} VRPs from {url}")
    return normalized, []

def collect_http_json_list(url: str, *, logger: Callable[[str], None] | None = None) -> tuple[list[dict], list[dict]]:
    logger = logger or (lambda m: None)
    data = _fetch_json(url)
    if data is None:
        logger(f"  HTTP API returned no data from {url}")
        return [], []
    vrps = data if isinstance(data, list) else data.get("roas", [])
    normalized = []
    for vrp in vrps:
        entry = dict(vrp)
        if "maxLength" in entry and "max_length" not in entry:
            entry["max_length"] = entry["maxLength"]
        if "prefix" in entry and "/" in str(entry["prefix"]):
            parts = str(entry["prefix"]).split("/", 1)
            entry["prefix"] = parts[0]
            entry["prefix_length"] = int(parts[1])
        normalized.append(entry)
    logger(f"  HTTP API (list): {len(normalized)} VRPs from {url}")
    return normalized, []

def collect_rpki_prover_aspa(url: str, *, logger: Callable[[str], None] | None = None) -> list[dict]:
    logger = logger or (lambda m: None)
    data = _fetch_json(url)
    if data is None:
        logger(f"  rpki-prover ASPA API returned no data from {url}")
        return []
    entries = data if isinstance(data, list) else data.get("aspas", [])
    aspas: list[dict] = []
    for aspa in entries:
        if not isinstance(aspa, dict):
            continue
        customer = aspa.get("customer") or aspa.get("customer_asn") or aspa.get("customer_asid")
        providers_raw = aspa.get("providers") or aspa.get("providerAsns") or []
        providers: list[int] = []
        for p in providers_raw:
            if isinstance(p, dict):
                v = p.get("provider_asn") or p.get("asn") or p.get("provider")
                if v is not None:
                    providers.append(v)
            else:
                providers.append(p)
        aspas.append({"customer_asn": customer, "providers": providers})
    logger(f"  rpki-prover ASPA API: {len(aspas)} VAPs from {url}")
    return aspas

def collect_csv(file_path: str) -> list[dict]:
    try:
        entries = []
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[1:]:
            fields = line.strip().split(",")
            if len(fields) >= 3:
                asn, prefix, max_length = fields[0], fields[1], fields[2]
                entries.append({
                    "asn": int(str(asn).replace("AS", "")),
                    "prefix": prefix.split("/")[0],
                    "prefix_length": int(prefix.split("/")[1]),
                    "max_length": int(max_length),
                })
        return entries
    except Exception:
        return []

def collect_docker_csv(container: str, path: str, *, logger: Callable[[str], None] | None = None) -> list[dict]:
    logger = logger or (lambda m: None)
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["sudo", "podman", "exec", container, "cat", path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                if "is paused" in result.stderr:
                    logger(f"  docker exec: container paused, retrying ({attempt+1}/3)...")
                    time.sleep(2)
                    continue
                logger(f"  docker exec cat failed: {result.stderr.strip()}")
                return []
            entries = []
            for line in result.stdout.strip().splitlines()[1:]:
                fields = line.strip().split(",")
                if len(fields) >= 3:
                    asn, prefix, max_length = fields[0], fields[1], fields[2]
                    entries.append({
                        "asn": int(str(asn).replace("AS", "")),
                        "prefix": prefix.split("/")[0],
                        "prefix_length": int(prefix.split("/")[1]),
                        "max_length": int(max_length),
                    })
            logger(f"  docker CSV: {len(entries)} VRPs from {container}:{path}")
            return entries
        except Exception as exc:
            logger(f"  docker CSV error: {exc}")
            if attempt < 2:
                time.sleep(2)
    return []

def collect_docker_json(container: str, path: str, *, logger: Callable[[str], None] | None = None) -> tuple[list[dict], list[dict]]:
    logger = logger or (lambda m: None)
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["sudo", "podman", "exec", container, "cat", path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                if "is paused" in result.stderr or "is not running" in result.stderr:
                    logger(f"  docker JSON: container not ready, retrying ({attempt+1}/3)...")
                    time.sleep(2)
                    continue
                logger(f"  docker JSON read failed: {result.stderr.strip()}")
                return [], []
            data = json.loads(result.stdout)
            vrps = []
            for vrp in data.get("roas", []):
                entry = dict(vrp)
                if "maxLength" in entry and "max_length" not in entry:
                    entry["max_length"] = entry["maxLength"]
                if "prefix" in entry and "/" in str(entry["prefix"]):
                    parts = str(entry["prefix"]).split("/", 1)
                    entry["prefix"] = parts[0]
                    entry["prefix_length"] = int(parts[1])
                vrps.append(entry)
            aspas = []
            for aspa in data.get("aspas", []):
                aspas.append({
                    "customer_asn": aspa.get("customer_asid", aspa.get("customer_asn")),
                    "providers": aspa.get("providers", []),
                })
            logger(f"  docker JSON: {len(vrps)} VRPs, {len(aspas)} ASPAs from {container}:{path}")
            return vrps, aspas
        except Exception as exc:
            logger(f"  docker JSON error: {exc}")
            if attempt < 2:
                time.sleep(2)
    return [], []

def collect_validator3_api(url: str, *, logger: Callable[[str], None] | None = None) -> tuple[list[dict], list[dict]]:
    logger = logger or (lambda m: None)
    data = _fetch_json(url)
    if data is None:
        logger(f"  validator-3 API returned no data from {url}")
        return [], []
    roas = data.get("data", {}).get("roas", []) if isinstance(data.get("data"), dict) else []
    vrps = []
    for vrp in roas:
        entry = dict(vrp)
        if "maxLength" in entry and "max_length" not in entry:
            entry["max_length"] = entry["maxLength"]
        if "prefix" in entry and "/" in str(entry["prefix"]):
            parts = str(entry["prefix"]).split("/", 1)
            entry["prefix"] = parts[0]
            entry["prefix_length"] = int(parts[1])
        vrps.append(entry)
    logger(f"  validator-3 API: {len(vrps)} VRPs from {url}")
    return vrps, []

def collect_rpstir2_mysql(container: str, *, mysql_container: str | None = None, logger: Callable[[str], None] | None = None) -> tuple[list[dict], list[dict]]:
    logger = logger or (lambda m: None)
    vrps: list[dict] = []
    aspas: list[dict] = []

    try:
        r = subprocess.run(
            ["sudo", "podman", "inspect", container, "--format", "{{.State.Running}}"],
            capture_output=True, text=True, timeout=5)
        if r.stdout.strip() != "true":
            logger(f"  rpstir2 container not running (crashed?) → returning empty VRPs")
            return [], []
    except Exception:
        logger(f"  rpstir2 container inspect failed → returning empty VRPs")
        return [], []

    def _pad_ipv4(addr: str) -> str:
        parts = addr.split(".")
        while len(parts) < 4:
            parts.append("0")
        return ".".join(parts)

    mysql_target = mysql_container or container
    sqlite_cmd = [
        "sudo", "podman", "exec", container, "sqlite3", "-separator", "\t",
        "/root/rpki/data/db/rpstir2.db",
        "SELECT asn, address, prefixLength, maxLength FROM lab_rpki_rtr_full;",
    ]
    mysql_cmd = [
        "sudo", "podman", "exec", mysql_target, "mysql",
        "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}", "rpstir2",
        "--batch", "-N",
        "-e", "SELECT asn, address, prefixLength, maxLength FROM lab_rpki_rtr_full",
    ]

    for cmd in (mysql_cmd, sqlite_cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().splitlines():
                    fields = line.split("\t")
                    if len(fields) >= 4:
                        vrps.append({
                            "asn": int(fields[0]),
                            "prefix": _pad_ipv4(fields[1]),
                            "prefix_length": int(fields[2]),
                            "max_length": int(fields[3]),
                        })
                break
        except Exception:
            continue

    sqlite_aspa_cmd = [
        "sudo", "podman", "exec", container, "sqlite3", "-separator", "\t",
        "/root/rpki/data/db/rpstir2.db",
        "SELECT customerAsn, providerAsn FROM lab_rpki_rtr_asa_full;",
    ]
    mysql_aspa_cmd = [
        "sudo", "podman", "exec", mysql_target, "mysql",
        "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}", "rpstir2",
        "--batch", "-N",
        "-e", "SELECT customerAsn, providerAsn FROM lab_rpki_rtr_asa_full",
    ]

    for cmd in (mysql_aspa_cmd, sqlite_aspa_cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout.strip():
                aspa_map: dict[int, list[int]] = {}
                for line in result.stdout.strip().splitlines():
                    fields = line.split("\t")
                    if len(fields) >= 2:
                        customer = int(fields[0])
                        provider = int(fields[1])
                        aspa_map.setdefault(customer, []).append(provider)
                aspas = [{"customer_asn": k, "providers": v} for k, v in aspa_map.items()]
                break
        except Exception:
            continue

    logger(f"  rpstir2 MySQL: {len(vrps)} VRPs, {len(aspas)} ASPAs from {mysql_target}")
    return vrps, aspas
def collect_validator_observations(
    validators: list[str] | None = None,
    *,
    logger: Callable[[str], None] | None = None,
) -> Observation:
    logger = logger or (lambda m: None)
    if validators is None:
        validators = list(VALIDATOR_CONFIG.keys())
    snapshots: dict[str, ValidatorSnapshot] = {}
    for name in validators:
        cfg = VALIDATOR_CONFIG.get(name, {})
        vrps, aspas = [], []
        if cfg.get("type") == "http_api":
            vrps, aspas = collect_http_json(cfg["url"], logger=logger)
        elif cfg.get("type") == "file":
            vrps = collect_csv(cfg["file"])
        elif "docker_csv" in cfg:
            dc = cfg["docker_csv"]
            vrps = collect_docker_csv(dc["container"], dc["path"], logger=logger)
        elif cfg.get("type") == "http_api_list":
            vrps, aspas = collect_http_json_list(cfg["url"], logger=logger)
            if "aspa_url" in cfg:
                aspas = collect_rpki_prover_aspa(cfg["aspa_url"], logger=logger)
        elif cfg.get("type") == "docker_json":
            vrps, aspas = collect_docker_json(cfg["container"], cfg["path"], logger=logger)
        elif cfg.get("type") == "docker_json_v3":
            vrps, aspas = collect_validator3_api(cfg["url"], logger=logger)
        elif cfg.get("type") == "rpstir2_mysql":
            vrps, aspas = collect_rpstir2_mysql(
                cfg["container"],
                mysql_container=cfg.get("mysql_container"),
                logger=logger,
            )
        else:
            vrps, aspas = rtr_collect(cfg.get("host", "localhost"), cfg.get("port", 323), logger=logger)
            if not aspas and "http_api" in cfg:
                h_vrps, h_aspas = collect_http_json(cfg["http_api"], logger=logger)
                if not vrps and h_vrps:
                    vrps = h_vrps
                if h_aspas:
                    aspas = h_aspas
        snapshots[name] = ValidatorSnapshot(name=name, vrps=vrps, aspas=aspas)

    semantics = {name: derive_semantics(snap) for name, snap in snapshots.items()}
    return Observation(validators=snapshots, semantics=semantics)

def run_baseline_check(
    validators: list[str] | None = None,
    *,
    logger: Callable[[str], None] | None = None,
) -> tuple[Observation, list[str]]:
    observation = collect_validator_observations(validators, logger=logger)
    failures = []
    for name, snapshot in observation.validators.items():
        matched = {key for vrp in snapshot.vrps if (key := normalize_vrp_key(vrp)) in BASELINE_VRPS}
        if len(matched) < len(BASELINE_VRPS):
            failures.append(f"{name}: baseline VRP missing ({len(matched)}/{len(BASELINE_VRPS)})")
    return observation, failures

def run_warmup_baseline_check(
    validators: list[str] | None = None,
    *,
    expected_vrps: set[tuple] | None = None,
    logger: Callable[[str], None] | None = None,
) -> tuple[Observation, list[str]]:
    target = expected_vrps or WARMUP_VRPS
    observation = collect_validator_observations(validators, logger=logger)
    failures = []
    for name, snapshot in observation.validators.items():
        matched = {key for vrp in snapshot.vrps if (key := normalize_vrp_key(vrp)) in target}
        if len(matched) < len(target):
            failures.append(f"{name}: warmup VRP missing ({len(matched)}/{len(target)})")
    return observation, failures
