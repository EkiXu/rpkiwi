"""Concretize SAT witnesses from the bounded audit into candidate seed inputs.

A seed records the Alloy command it came from, the witness bindings it
concretizes, and the byte-level postconditions actually observed in the
produced input. It establishes field conditions on an input — never that any
validator accepts it. Witness bindings that have no concrete byte
representation (abstract parse outcomes, infrastructure-only relations) are
recorded as mutation energy guidance instead of being invented.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Callable

from rpkiwi.alloy.energy import (
    ASSERTION_FIELDS, ALL_VALIDATORS, assertion_object_types, fields_for,
    load_all_results, model_stem,
)
from rpkiwi.alloy.fields import energy_paths, field_path, load_fields
from rpkiwi.alloy.results import MODEL_DIR, OUTPUT_DIR, InvalidRun
from rpkiwi.alloy.seed_conditions import SeedConditionError, check_postconditions, json_value
from rpkiwi.alloy.witness import Witness, atom_kind, load_witness
from rpkiwi.config import RPKIConfig, attacker_config, victim_config
from rpkiwi.input.ast_node import ASTNode, serialize
from rpkiwi.input.asnme.model.der.encoder import DEREncoder
from rpkiwi.input.asnme.model.der.length import encode_tlv
from rpkiwi.input.asnme.model.misc.ips import (
    encode_as_resources_explicit, encode_ip_resources_explicit, encode_ip_resources_inherit,
)
from rpkiwi.input.ast_encoder import ast_to_der
from rpkiwi.input.der_ast import DERNode
from rpkiwi.input.generator import generate
from rpkiwi.input.test_input import FORMAT_MAP, SERIALIZATION_KEYS

_DIR = Path(__file__).resolve().parent
_CORPUS_DIR = _DIR.parents[2] / "corpus" / "initial"
_BUILD_DIR = _DIR.parents[2] / "build"

# MFT and CRL are the publication point's own index and revocation list: an
# appended copy would be ignored in favour of the regenerated baseline, so the
# seed has to take their place. ROA/ASPA/CER are additional objects.
SCAFFOLD_MODES = {
    "ROA": "append", "ASPA": "append", "CER": "append",
    "MFT": "replace", "CRL": "replace",
    "SNAPSHOT": "replace", "NOTIFICATION": "replace", "DELTA": "replace",
}
EXT_MAP = {"ROA": "roa", "ASPA": "asa", "MFT": "mft", "CRL": "crl", "CER": "cer"}
_VICTIM_TYPE_EXT = {"ROA": ".roa", "MFT": ".mft", "CRL": ".crl", "ASPA": ".asa"}
_RRDP_TYPES = {"SNAPSHOT", "NOTIFICATION", "DELTA"}

_OID_SKI = "2.5.29.14"
_OID_AKI = "2.5.29.35"
_OID_IP_RESOURCES = "1.3.6.1.5.5.7.1.7"
_OID_AS_RESOURCES = "1.3.6.1.5.5.7.1.8"
_OID_BASIC_CONSTRAINTS = "2.5.29.19"


class SeedFactoryError(ValueError):
    """The lab or the witness does not support concretizing this candidate."""


# =====================================================================
# Lab ground truth
# =====================================================================

@dataclass(frozen=True)
class Identity:
    name: str
    ski: bytes
    subject_der: bytes
    serial: int
    host: str
    prefix: str
    asn: int

    @classmethod
    def parse(cls, name: str, entry: dict) -> Identity:
        missing = [k for k in ("ski", "subject_der", "serial_number", "host") if not entry.get(k)]
        if missing:
            raise SeedFactoryError(f"public_constants.json: {name} lacks {missing}")
        return cls(name=name, ski=base64.b64decode(entry["ski"]),
                   subject_der=base64.b64decode(entry["subject_der"]),
                   serial=int(entry["serial_number"]), host=entry["host"],
                   prefix=entry["roa_prefix"], asn=int(entry["roa_asn"]))


@dataclass(frozen=True)
class PublishedObject:
    object_type: str
    filename: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def ast(self) -> ASTNode:
        return ASTNode.from_der(self.data, self.object_type)


class Lab:
    """Concrete values exported by the experiment scaffold.

    Everything here is read from the built lab; nothing is defaulted, so a
    missing lab fails loudly instead of yielding seeds with invented values.
    """

    def __init__(self, build_dir: Path | None = None):
        self.build_dir = build_dir or _BUILD_DIR
        path = self.build_dir / "public_constants.json"
        if not path.is_file():
            raise SeedFactoryError(f"{path}: no lab ground truth; bootstrap the lab first")
        constants = json.loads(path.read_text())
        identity = constants.get("identity", {})
        self.victim = Identity.parse("victim-ca", identity.get("victim-ca", {}))
        self.attacker = Identity.parse("attacker-ca", identity.get("attacker-ca", {}))
        self.victim_config = victim_config()
        self._versions = self.build_dir / "versions"
        self._cache: dict[str, PublishedObject | None] = {}

    def victim_object(self, object_type: str) -> PublishedObject | None:
        """The victim's published object of this type, as actually served at T0."""
        if object_type in self._cache:
            return self._cache[object_type]
        found = None
        extension = _VICTIM_TYPE_EXT.get(object_type)
        repo = self._versions / "victim-pp" / "t0" / "repo"
        if extension and repo.is_dir():
            for candidate in sorted(repo.iterdir()):
                if candidate.is_file() and candidate.name.endswith(extension):
                    found = PublishedObject(object_type, candidate.name, candidate.read_bytes())
                    break
        self._cache[object_type] = found
        return found

    def victim_uri(self, object_type: str) -> str | None:
        published = self.victim_object(object_type)
        if published is None:
            return None
        return f"{self.victim_config.ca_sia_repo_uri}{published.filename}"


# =====================================================================
# Witness atom -> concrete value
# =====================================================================

def _topology_values(lab: Lab) -> dict[str, object]:
    return {
        "VictimSKI": lab.victim.ski, "AttackerSKI": lab.attacker.ski,
        "VictimPrefix": lab.victim.prefix, "AttackerPrefix": lab.attacker.prefix,
        "VictimASN": lab.victim.asn, "AttackerASN": lab.attacker.asn,
        "VictimSerial": lab.victim.serial, "AttackerSerial": lab.attacker.serial,
        "VictimDN": lab.victim.subject_der, "AttackerDN": lab.attacker.subject_der,
        "VictimHost": lab.victim.host, "AttackerHost": lab.attacker.host,
        "True": True, "False": False,
    }


# =====================================================================
# DER encoders for the registry's addressable nodes
# =====================================================================

def _extension(oid: str, inner: bytes) -> bytes:
    """The extension leaf payload: extnID plus extnValue, as the parser stores it."""
    return DEREncoder.encode_object_identifier(oid) + encode_tlv(b"\x04", inner)


def _ski_inner(key_id: bytes) -> bytes:
    return encode_tlv(b"\x04", key_id)


def _aki_inner(key_id: bytes) -> bytes:
    return encode_tlv(b"\x30", encode_tlv(b"\x80", key_id))


def _basic_constraints_inner(is_ca: bool) -> bytes:
    return encode_tlv(b"\x30", b"\x01\x01\xff" if is_ca else b"")


def _decode_key_id(node: ASTNode) -> bytes:
    """Read the key identifier back out of an encoded SKI or AKI extension."""
    extension = DERNode.parse(ast_to_der(node))
    value = extension.children[-1]
    if value.tag != 0x04:
        raise SeedFactoryError("key identifier extension has no extnValue")
    inner = DERNode.parse(value.content)
    if inner.tag == 0x04:
        return inner.content
    if inner.children and inner.children[0].tag == 0x80:
        return inner.children[0].content
    raise SeedFactoryError("unrecognized key identifier extension shape")


def _roa_families(prefixes: list[str]) -> list[ASTNode]:
    import ipaddress

    by_family: dict[str, list[ASTNode]] = {}
    for prefix in prefixes:
        network = ipaddress.ip_network(prefix, strict=False)
        family = "ipv4" if network.version == 4 else "ipv6"
        by_family.setdefault(family, []).append(ASTNode("ROAIPAddress", children=[
            ASTNode("address", value=prefix),
            ASTNode("maxLength", value=network.prefixlen),
        ]))
    return [ASTNode("ROAIPAddressFamily", children=[
        ASTNode("addressFamily", value=family),
        ASTNode("addresses", children=entries),
    ]) for family, entries in by_family.items()]


def _set_leaf(path: str, value: object) -> Callable[[ASTNode], None]:
    def apply(ast: ASTNode) -> None:
        node = ast.find(path)
        if node is None:
            raise SeedFactoryError(f"baseline AST lacks {path}")
        node.children = []
        node.value = value
    return apply


def _set_extension(path: str, oid: str, inner: bytes) -> Callable[[ASTNode], None]:
    return _set_leaf(path, _extension(oid, inner))


def _replace_children(path: str, children: list[ASTNode]) -> Callable[[ASTNode], None]:
    def apply(ast: ASTNode) -> None:
        node = ast.find(path)
        if node is None:
            raise SeedFactoryError(f"baseline AST lacks {path}")
        node.value = None
        node.children = [child.clone() for child in children]
    return apply


def _mft_entry(path: str, filename: str, hash_hex: str) -> Callable[[ASTNode], None]:
    """Point one manifest fileList entry at (filename, hash), adding it if absent."""
    list_path = path.rsplit("/", 2)[0]

    def apply(ast: ASTNode) -> None:
        file_list = ast.find(list_path)
        if file_list is None:
            raise SeedFactoryError(f"baseline AST lacks {list_path}")
        for entry in file_list.children:
            name = entry.child("filename")
            if name is not None and name.value == filename:
                target = entry
                break
        else:
            target = ASTNode("fileEntry", children=[
                ASTNode("filename", value=filename), ASTNode("hash", value=hash_hex),
            ])
            file_list.children.append(target)
        target.child("filename").value = filename
        target.child("hash").value = hash_hex
    return apply


def _crl_revoked_serial(serial: int) -> Callable[[ASTNode], None]:
    """Revoke one serial, inserting revokedCertificates in its DER position."""
    def apply(ast: ASTNode) -> None:
        tbs = ast.child("tbsCertList")
        if tbs is None:
            raise SeedFactoryError("baseline AST lacks tbsCertList")
        revoked = tbs.child("revokedCertificates")
        if revoked is None:
            revoked = ASTNode("revokedCertificates", der_tag=0x30, children=[])
            labels = [child.label for child in tbs.children]
            anchor = next((labels.index(l) + 1 for l in ("nextUpdate", "thisUpdate")
                           if l in labels), len(tbs.children))
            tbs.children.insert(anchor, revoked)
        for entry in revoked.children:
            if entry.child("serialNumber") is not None and entry.child("serialNumber").value == serial:
                return
        template = next((c for c in revoked.children if c.child("revocationDate")), None)
        date = template.child("revocationDate") if template is not None else tbs.child("thisUpdate")
        if date is None or date.der_tag is None:
            raise SeedFactoryError("CRL baseline has no time encoding for a revocationDate")
        revoked.children.append(ASTNode("revokedCertificate", der_tag=0x30, children=[
            ASTNode("serialNumber", value=serial, der_tag=0x02),
            ASTNode("revocationDate", value=date.value, der_tag=date.der_tag),
        ]))
    return apply


def _corrupt_signature(path: str) -> Callable[[ASTNode], None]:
    def apply(ast: ASTNode) -> None:
        node = ast.find(path)
        if node is None or not isinstance(node.value, (bytes, bytearray)):
            raise SeedFactoryError(f"{path}: no signature bytes to invalidate")
        raw = bytearray(node.value)
        raw[-1] ^= 0xFF
        node.value = bytes(raw)
    return apply


def _empty_signer_infos(path: str) -> Callable[[ASTNode], None]:
    def apply(ast: ASTNode) -> None:
        node = ast.find(path)
        if node is None:
            raise SeedFactoryError(f"baseline AST lacks {path}")
        node.children = []
        node.value = None
    return apply


# =====================================================================
# Per-assertion concretization plan
# =====================================================================

@dataclass(frozen=True)
class Assignment:
    field_id: str
    path: str
    reason: str
    apply: Callable[[ASTNode], None]
    postconditions: tuple[dict, ...] = ()
    flags: tuple[str, ...] = ()

    def record(self) -> dict:
        return {"field": self.field_id, "path": self.path, "reason": self.reason,
                "postconditions": list(self.postconditions)}


@dataclass
class SeedPlan:
    validator: str
    assertion: str
    object_type: str
    attacker_atom: str
    assignments: list[Assignment] = dc_field(default_factory=list)
    guidance: dict[str, float] = dc_field(default_factory=dict)
    notes: list[dict] = dc_field(default_factory=list)
    replay: PublishedObject | None = None

    @property
    def flags(self) -> dict[str, bool]:
        active = {flag for a in self.assignments for flag in a.flags}
        return {key: key in active for key in SERIALIZATION_KEYS}

    @property
    def postconditions(self) -> list[dict]:
        return [dict(c) for a in self.assignments for c in a.postconditions]


class Planner:
    """Turn one SAT witness into the field changes it actually binds."""

    def __init__(self, lab: Lab, witness: Witness, validator: str, assertion: str,
                 object_type: str, attacker_atom: str):
        self.lab = lab
        self.witness = witness
        self.validator = validator
        self.assertion = assertion
        self.object_type = object_type
        self.attacker_atom = attacker_atom
        self.registry = load_fields()
        self.topology = _topology_values(lab)
        self.victim_atoms = witness.objects_of("v")

    # --- witness reading -------------------------------------------------

    def atoms(self, field_id: str, atom: str | None = None) -> list[str]:
        return self.witness.field_values(atom or self.attacker_atom, field_id)

    def kinds(self, field_id: str, atom: str | None = None) -> list[str]:
        return [atom_kind(a) for a in self.atoms(field_id, atom)]

    def named(self, field_id: str) -> list[object]:
        """Concrete values for witness atoms that are named topology identities."""
        return [self.topology[kind] for kind in self.kinds(field_id)
                if kind in self.topology]

    def shared_with_victim(self, field_id: str) -> tuple[str, str] | None:
        """A victim object whose same field the witness binds to the same atom."""
        mine = set(self.atoms(field_id))
        for victim_atom in self.victim_atoms:
            if mine & set(self.atoms(field_id, victim_atom)):
                return victim_atom, self.witness.object_type(victim_atom)
        return None

    def victim_replay_source(self) -> PublishedObject | None:
        """A victim object the witness says shares this object's canonical bytes."""
        mine = set(self.atoms("RPKIObject.content_hash"))
        for victim_atom in self.victim_atoms:
            if mine & set(self.atoms("RPKIObject.content_hash", victim_atom)):
                return self.lab.victim_object(self.witness.object_type(victim_atom))
        return None

    # --- plan ------------------------------------------------------------

    def plan(self) -> SeedPlan:
        plan = SeedPlan(self.validator, self.assertion, self.object_type, self.attacker_atom)
        seen: set[str] = set()
        field_ids = fields_for(self.validator, self.assertion)
        for field_id in field_ids:
            entry = self.registry.get(field_id)
            if entry is None:
                raise SeedFactoryError(f"{field_id}: no field_registry.yaml entry")
            path = field_path(entry, self.object_type)
            handler = self._handlers().get(field_id)
            assignment = None
            if handler is not None and path is not None:
                assignment = handler(field_id, path)
            if assignment is None:
                reason = self._guidance_reason(field_id, path)
                paths = energy_paths(entry, self.object_type)
                for guidance_path in paths:
                    plan.guidance[guidance_path] = plan.guidance.get(guidance_path, 0.0) + 1.0
                plan.notes.append({"field": field_id, "paths": paths, "reason": reason})
            elif assignment.path not in seen:
                seen.add(assignment.path)
                plan.assignments.append(assignment)
        # A content-hash collision is only representable as the public bytes it
        # names; nothing else in the witness can be concretized for it.
        if not plan.assignments and "RPKIObject.content_hash" in field_ids:
            plan.replay = self.victim_replay_source()
        return plan

    def _guidance_reason(self, field_id: str, path: str | None) -> str:
        entry = self.registry[field_id]
        if path is None:
            return (f"{field_id} has no addressable node for {self.object_type}; "
                    "mutation energy only")
        if entry.get("alloy_type", "").endswith("ParseOutcome"):
            return (f"{field_id} is an abstract parse outcome "
                    f"({'/'.join(self.kinds(field_id)) or 'unbound'}); no byte value follows "
                    "from the witness, so the path is left as mutation energy")
        return (f"{field_id} is bound to {self.atoms(field_id) or ['nothing']} in the witness, "
                "which names no concrete lab value; mutation energy only")

    def _handlers(self) -> dict[str, Callable[[str, str], Assignment | None]]:
        return {
            "Certificate.subject_ski": self._key_id,
            "Certificate.issuer_ski": self._key_id,
            "Certificate.serial_number": self._serial_number,
            "Certificate.ip_resources": self._ip_resources,
            "Certificate.as_resources": self._as_resources,
            "Certificate.resources_inherit": self._resources_inherit,
            "Certificate.is_ca": self._is_ca,
            "Certificate.sia_notify_uri": self._sia_uri,
            "Certificate.sia_repo_uri": self._sia_uri,
            "Certificate.sia_mft_uri": self._sia_uri,
            "CMSSignedData.signer_infos": self._signer_infos,
            "CMSSignedData.signature_valid": self._signature_valid,
            "CMSSignedData.econtent_digest": self._cms_digest,
            "CMSSignedData.signed_attrs_digest": self._cms_digest,
            "MFTEntry.entry_uri": self._entry_uri,
            "MFTEntry.entry_hash": self._entry_hash,
            "ROAPayload.roa_prefixes": self._roa_prefixes,
            "ASPAPayload.customer_as": self._customer_as,
            "CRLPayload.revoked_serials": self._revoked_serials,
        }

    # --- field handlers --------------------------------------------------

    def _key_id(self, field_id: str, path: str) -> Assignment | None:
        is_subject = field_id.endswith("subject_ski")
        oid, inner_of = (_OID_SKI, _ski_inner) if is_subject else (_OID_AKI, _aki_inner)
        kinds = self.kinds(field_id)
        if "VictimSKI" in kinds:
            key_id, reason = self.lab.victim.ski, "witness binds it to the victim CA key"
        else:
            shared = self.shared_with_victim(field_id)
            if shared is None:
                return None
            victim_atom, victim_type = shared
            published = self.lab.victim_object(victim_type)
            if published is None:
                return None
            victim_path = field_path(self.registry[field_id], victim_type)
            node = published.ast().find(victim_path) if victim_path else None
            if node is None:
                return None
            key_id = _decode_key_id(node)
            reason = (f"witness binds it to the same KeyId as the victim {victim_type} "
                      f"{published.filename}")
        inner = inner_of(key_id)
        apply = _set_extension(path, oid, inner)
        if is_subject and self.object_type not in _RRDP_TYPES:
            apply = _with_matching_sid(apply, key_id)
        return Assignment(field_id, path, f"{field_id}: {reason}", apply, (
            {"kind": "extension_value", "path": path, "expected": json_value(inner)},
        ))

    def _serial_number(self, field_id: str, path: str) -> Assignment | None:
        values = [v for v in self.named(field_id) if isinstance(v, int)]
        if not values:
            return None
        serial = values[0]
        return Assignment(field_id, path, f"{field_id}: witness binds it to serial {serial}",
                          _set_leaf(path, serial),
                          ({"kind": "ast_value", "path": path, "expected": serial},))

    def _ip_resources(self, field_id: str, path: str) -> Assignment | None:
        if True in self.named("Certificate.resources_inherit"):
            return None
        prefixes = [v for v in self.named(field_id) if isinstance(v, str)]
        if not prefixes:
            return None
        inner = encode_ip_resources_explicit(
            [p for p in prefixes if ":" not in p] or None,
            [p for p in prefixes if ":" in p] or None)
        return Assignment(field_id, path,
                          f"{field_id}: witness claims {prefixes}",
                          _set_extension(path, _OID_IP_RESOURCES, inner),
                          ({"kind": "extension_value", "path": path,
                            "expected": json_value(inner)},))

    def _as_resources(self, field_id: str, path: str) -> Assignment | None:
        asns = [v for v in self.named(field_id) if isinstance(v, int)]
        if not asns:
            return None
        inner = encode_as_resources_explicit(asns[0])
        return Assignment(field_id, path, f"{field_id}: witness claims AS {asns[0]}",
                          _set_extension(path, _OID_AS_RESOURCES, inner),
                          ({"kind": "extension_value", "path": path,
                            "expected": json_value(inner)},))

    def _resources_inherit(self, field_id: str, path: str) -> Assignment | None:
        if True not in self.named(field_id):
            return None
        inner = encode_ip_resources_inherit()
        return Assignment(field_id, path, f"{field_id}: witness sets the inherit marker",
                          _set_extension(path, _OID_IP_RESOURCES, inner),
                          ({"kind": "extension_value", "path": path,
                            "expected": json_value(inner)},))

    def _is_ca(self, field_id: str, path: str) -> Assignment | None:
        values = [v for v in self.named(field_id) if isinstance(v, bool)]
        if not values:
            return None
        inner = _basic_constraints_inner(values[0])
        return Assignment(field_id, path, f"{field_id}: witness sets cA={values[0]}",
                          _set_extension(path, _OID_BASIC_CONSTRAINTS, inner),
                          ({"kind": "extension_value", "path": path,
                            "expected": json_value(inner)},))

    def _sia_uri(self, field_id: str, path: str) -> Assignment | None:
        hosts = {atom_kind(self.witness.one(uri, "host")) for uri in self.atoms(field_id)}
        if "VictimHost" not in hosts:
            return None
        config = self.lab.victim_config
        uri = {"Certificate.sia_notify_uri": config.ca_sia_notify_uri,
               "Certificate.sia_repo_uri": config.ca_sia_repo_uri,
               "Certificate.sia_mft_uri": config.ca_sia_manifest_uri}[field_id]
        return Assignment(field_id, path,
                          f"{field_id}: witness points it at the victim host",
                          _set_leaf(path, uri), (
                              {"kind": "ast_value", "path": path, "expected": uri},
                              {"kind": "uri_host", "path": path, "expected": self.lab.victim.host},
                          ))

    def _signer_infos(self, field_id: str, path: str) -> Assignment | None:
        if self.atoms(field_id):
            return None
        return Assignment(field_id, path, f"{field_id}: witness leaves signerInfos empty",
                          _empty_signer_infos(path),
                          ({"kind": "child_count", "path": path, "expected": 0},))

    def _signature_valid(self, field_id: str, path: str) -> Assignment | None:
        if False not in self.named(field_id):
            return None
        if self.object_type == "CRL":
            condition = {"kind": "object_signature_valid", "issuer": "attacker", "expected": False}
            flag = "preserve_object_signature"
        else:
            condition = {"kind": "cms_signature_valid", "expected": False}
            flag = "preserve_cms_signature"
        return Assignment(field_id, path,
                          f"{field_id}: witness accepts an invalid signature",
                          _corrupt_signature(path), (condition,), (flag,))

    def _cms_digest(self, field_id: str, path: str) -> Assignment | None:
        content, attrs = "CMSSignedData.econtent_digest", "CMSSignedData.signed_attrs_digest"
        if set(self.atoms(content)) == set(self.atoms(attrs)):
            return None
        digest_path = field_path(self.registry[attrs], self.object_type)
        if digest_path is None:
            return None
        source = self.lab.victim_object(self.object_type)
        if source is not None:
            digest = _econtent_digest(source.data)
            reason = (f"witness separates the two digests: reuse the victim {self.object_type} "
                      f"{source.filename} messageDigest over attacker eContent")
        else:
            digest = hashlib.sha256(b"").digest()
            reason = ("witness separates the two digests; no victim object of this type is "
                      "published, so the messageDigest is an explicit non-matching constant")
        return Assignment(attrs, digest_path, f"{attrs}: {reason}",
                          _set_leaf(digest_path, digest), (
                              {"kind": "ast_value", "path": digest_path,
                               "expected": json_value(digest)},
                              {"kind": "cms_digest_matches", "expected": False},
                              {"kind": "cms_signature_valid", "expected": True},
                          ), ("preserve_cms_digest",))

    def _entry_uri(self, field_id: str, path: str) -> Assignment | None:
        target = self._cross_pp_entry_target(field_id)
        if target is None:
            return None
        published, uri = target
        return Assignment(field_id, path,
                          f"{field_id}: witness names a victim-hosted file, {published.filename}",
                          _mft_entry(path, uri, published.sha256), (
                              {"kind": "ast_values", "match": "contains",
                               "path": path.rsplit("/", 1)[0] + "/filename", "expected": uri},
                          ))

    def _entry_hash(self, field_id: str, path: str) -> Assignment | None:
        target = self._cross_pp_entry_target("MFTEntry.entry_uri")
        if target is None:
            return None
        published, uri = target
        mine = self.lab.victim_object(published.object_type)
        own = _own_published_object(published.object_type)
        if own is not None:
            wrong = own.sha256
            reason = (f"witness binds the entry hash away from the victim object: use the "
                      f"attacker's own {published.object_type} {own.filename}")
        else:
            wrong = hashlib.sha256(published.data + b"\x00").hexdigest()
            reason = ("witness binds the entry hash away from the victim object; the attacker "
                      "publishes no object of this type, so the hash is an explicit mismatch")
        if mine is not None and wrong == mine.sha256:
            raise SeedFactoryError(f"{field_id}: substitute hash equals the victim's")
        return Assignment(field_id, path, f"{field_id}: {reason}",
                          _mft_entry(path, uri, wrong), (
                              {"kind": "ast_values", "match": "contains",
                               "path": path.rsplit("/", 1)[0] + "/filename", "expected": uri},
                              {"kind": "ast_values", "match": "contains",
                               "path": path.rsplit("/", 1)[0] + "/hash", "expected": wrong},
                          ))

    def _cross_pp_entry_target(self, field_id: str) -> tuple[PublishedObject, str] | None:
        for uri_atom in self.atoms(field_id):
            kind = atom_kind(uri_atom)
            object_type = {"VictimROAUri": "ROA", "VictimCRLUri": "CRL"}.get(kind)
            if object_type is None:
                if atom_kind(self.witness.one(uri_atom, "host")) != "VictimHost":
                    continue
                object_type = "ROA"
            published = self.lab.victim_object(object_type)
            uri = self.lab.victim_uri(object_type)
            if published is not None and uri is not None:
                return published, uri
        return None

    def _roa_prefixes(self, field_id: str, path: str) -> Assignment | None:
        prefixes = [v for v in self.named(field_id) if isinstance(v, str)]
        if not prefixes:
            return None
        return Assignment(field_id, path, f"{field_id}: witness claims {prefixes}",
                          _replace_children(path, _roa_families(prefixes)),
                          ({"kind": "roa_prefixes", "path": path, "expected": prefixes},))

    def _customer_as(self, field_id: str, path: str) -> Assignment | None:
        asns = [v for v in self.named(field_id) if isinstance(v, int)]
        if not asns:
            return None
        return Assignment(field_id, path, f"{field_id}: witness claims customer AS {asns[0]}",
                          _set_leaf(path, asns[0]),
                          ({"kind": "ast_value", "path": path, "expected": asns[0]},))

    def _revoked_serials(self, field_id: str, path: str) -> Assignment | None:
        serials = [v for v in self.named(field_id) if isinstance(v, int)]
        if not serials:
            return None
        return Assignment(field_id, path,
                          f"{field_id}: witness revokes serial {serials[0]}",
                          _crl_revoked_serial(serials[0]),
                          ({"kind": "ast_values", "path": path, "match": "contains",
                            "expected": serials[0]},))


def _with_matching_sid(apply: Callable[[ASTNode], None], key_id: bytes) -> Callable[[ASTNode], None]:
    """RFC 6488 §2.1.6.2: the CMS sid names the EE certificate's own SKI."""
    def wrapped(ast: ASTNode) -> None:
        apply(ast)
        sid = ast.find("SignedData/signerInfos/SignerInfo/sid")
        if sid is not None:
            sid.value = key_id
    return wrapped


def _econtent_digest(data: bytes) -> bytes:
    root = DERNode.parse(data)
    content = root.children[1].children[0].children[2].children[1].children[0].content
    return hashlib.sha256(content).digest()


def _own_published_object(object_type: str, build_dir: Path | None = None) -> PublishedObject | None:
    extension = _VICTIM_TYPE_EXT.get(object_type)
    repo = (build_dir or _BUILD_DIR) / "versions" / "attacker-pp" / "baseline"
    if not extension or not repo.is_dir():
        return None
    for candidate in sorted(repo.rglob(f"*{extension}")):
        if candidate.is_file():
            return PublishedObject(object_type, candidate.name, candidate.read_bytes())
    return None


# =====================================================================
# Realization
# =====================================================================

@dataclass
class Seed:
    stem: str
    object_type: str
    data: bytes
    metadata: dict


def _baseline(object_type: str, config: RPKIConfig) -> tuple[ASTNode, str | None, bool]:
    test_input = generate(object_type, config)
    ast_dict = test_input.metadata.get("ast")
    if not ast_dict:
        raise SeedFactoryError(f"{object_type}: generator produced no parsed AST baseline")
    return (ASTNode.from_dict(ast_dict), test_input.metadata.get("ee_key_pem"),
            bool(test_input.metadata.get("can_resign")))


def realize(plan: SeedPlan, lab: Lab, config: RPKIConfig, witness: Witness) -> Seed:
    stem = f"{plan.validator}-{plan.object_type.lower()}-{plan.assertion}"
    flags = plan.flags
    conditions = plan.postconditions
    concretization = "witness_assignments" if plan.assignments else "energy_guidance"
    ee_key_pem: str | None = None
    can_resign = False

    if plan.replay is not None:
        ast, data = plan.replay.ast(), plan.replay.data
        concretization = "public_replay"
        conditions = [{"kind": "byte_replay", "expected": plan.replay.sha256}]
    else:
        ast, ee_key_pem, can_resign = _baseline(plan.object_type, config)
        for assignment in plan.assignments:
            assignment.apply(ast)
        if plan.object_type in _RRDP_TYPES:
            from rpkiwi.input.rrdp_ast import serialize_rrdp_from_ast
            data = serialize_rrdp_from_ast(ast, plan.object_type, config)
        else:
            if plan.assignments and not can_resign:
                raise SeedFactoryError(
                    f"{plan.object_type}: baseline cannot be re-signed after modification")
            data = serialize(ast, config, can_resign=can_resign,
                             ee_key_pem=ee_key_pem, **flags)
            # Re-read the emitted bytes: the AST is the request, these are the facts.
            ast = ASTNode.from_der(data, plan.object_type)

    observations = []
    if plan.object_type not in _RRDP_TYPES:
        observations = check_postconditions(data, plan.object_type, conditions, config)

    missing = [path for path in plan.guidance if ast.find(path) is None]
    scaffold_mode = SCAFFOLD_MODES[plan.object_type]
    extension = EXT_MAP.get(plan.object_type, plan.object_type.lower())

    metadata = {
        "ir_name": stem,
        "source": "alloy-witness",
        "validator": plan.validator,
        "sat_assertions": [plan.assertion],
        "concretization": concretization,
        "ast": ast.to_dict(),
        "can_resign": can_resign and plan.object_type not in _RRDP_TYPES,
        "scaffold_mode": scaffold_mode,
        "data_sha256": hashlib.sha256(data).hexdigest(),
        "applied_assignments": [a.record() for a in plan.assignments],
        "energy_guidance": plan.notes,
        "unresolved_energy_paths": missing,
        "mutate_energy": dict(sorted(plan.guidance.items(), key=lambda item: -item[1])),
        "postconditions": conditions,
        "observations": observations,
        "witness": witness.metadata(plan.attacker_atom),
        **flags,
    }
    if scaffold_mode == "append":
        metadata["append_filename"] = (
            plan.replay.filename if plan.replay is not None
            else f"fuzz-{plan.object_type.lower()}-{plan.assertion}.{extension}")
    if ee_key_pem and plan.replay is None:
        metadata["ee_key_pem"] = ee_key_pem
    return Seed(stem, plan.object_type, data, metadata)


# =====================================================================
# Driver
# =====================================================================

def _targets(witness: Witness, assertion: str) -> list[tuple[str, str, str | None]]:
    """(object type, witness atom, note) for each input this candidate is seeded on."""
    eligible = assertion_object_types(assertion)
    atoms = witness.attack_objects(eligible)
    if atoms:
        return [(witness.object_type(atoms[0]), atoms[0], None)]
    if not set(eligible) <= _RRDP_TYPES:
        raise SeedFactoryError(
            f"witness binds no attacker-published {'/'.join(eligible)} object")
    # S2 models the fetch/cache surface over PP relations: the witness binds the
    # collision on PP URIs, not on an RRDP document atom. Seed each RRDP document
    # the registry maps those relations onto, and record that this is what happened.
    other = witness.attack_objects(None)
    carrier = witness.object_type(other[0]) if other else "no"
    return [(object_type, witness.role("a"),
             f"witness binds the S2 relation on PP URIs and an attacker {carrier} object, "
             f"not on an RRDP document; seeded as mutation energy on the {object_type} surface")
            for object_type in eligible]


def seeds_for_validator(
    validator: str, lab: Lab, config: RPKIConfig, results: dict[str, str],
    output_dir: Path | None = None,
) -> tuple[list[Seed], list[dict]]:
    stem = model_stem(validator)
    model = MODEL_DIR / f"{stem}.als"
    output = (output_dir or OUTPUT_DIR) / stem
    seeds: list[Seed] = []
    skipped: list[dict] = []
    for assertion in ASSERTION_FIELDS:
        if results.get(assertion) != "SAT":
            continue
        try:
            witness = load_witness(model, output, assertion)
            for object_type, atom, note in _targets(witness, assertion):
                plan = Planner(lab, witness, validator, assertion, object_type, atom).plan()
                if note:
                    plan.notes.append({"field": None, "paths": [], "reason": note})
                seeds.append(realize(plan, lab, config, witness))
        except (SeedFactoryError, SeedConditionError, InvalidRun, ValueError) as exc:
            skipped.append({"validator": validator, "assertion": assertion,
                            "error": f"{type(exc).__name__}: {exc}"})
    return seeds, skipped


def generate_all_seeds(
    output_dir: Path | None = None, build_dir: Path | None = None,
    alloy_output_dir: Path | None = None,
) -> int:
    out = output_dir or _CORPUS_DIR
    out.mkdir(parents=True, exist_ok=True)
    lab = Lab(build_dir)
    config = attacker_config()
    # Results are read now, not at import time: a stale or failed Alloy run must
    # raise here rather than silently read as UNSAT.
    all_results = load_all_results(alloy_output_dir)

    total, all_skipped = 0, []
    for validator in ALL_VALIDATORS:
        seeds, skipped = seeds_for_validator(
            validator, lab, config, all_results[validator], alloy_output_dir)
        all_skipped.extend(skipped)
        print(f"{validator}: {len(seeds)} seeds, {len(skipped)} skipped")
        for seed in seeds:
            (out / f"{seed.stem}.meta.json").write_text(json.dumps({
                "object_type": seed.object_type,
                "format": FORMAT_MAP[seed.object_type],
                "metadata": seed.metadata,
            }, indent=2) + "\n")
            (out / f"{seed.stem}.input").write_bytes(seed.data)
            total += 1
            print(f"  {seed.stem}: {seed.metadata['concretization']}, "
                  f"{len(seed.metadata['applied_assignments'])} assigned, "
                  f"{len(seed.metadata['mutate_energy'])} energy paths, {len(seed.data)} bytes")

    if all_skipped:
        print(f"\n{len(all_skipped)} SAT candidates not concretized:")
        for entry in all_skipped:
            print(f"  {entry['validator']} {entry['assertion']}: {entry['error']}")
    print(f"\nWrote {total} seeds to {out}")
    return total


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=_CORPUS_DIR,
                        help="seed output directory (default: corpus/initial)")
    parser.add_argument("--force", action="store_true",
                        help="allow overwriting an existing seed corpus")
    args = parser.parse_args()

    if (args.output.resolve() == _CORPUS_DIR.resolve()
            and any(args.output.glob("*.meta.json")) and not args.force):
        raise SystemExit(
            f"{args.output} holds an existing seed corpus; "
            "use --output DIR for a fresh candidate run or --force to overwrite it")
    generate_all_seeds(output_dir=args.output)


if __name__ == "__main__":
    main()
