"""Read roles and relations from a hash-validated, complete Alloy XML instance."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET

from .results import InvalidRun, digest, load_validated, model_sources


def atom_kind(atom: str) -> str:
    return atom.rsplit("/", 1)[-1].split("$", 1)[0]


OBJECT_TYPES = {
    "OT_ROA": "ROA", "OT_ASPA": "ASPA", "OT_MFT": "MFT", "OT_CRL": "CRL",
    "OT_CA_CERT": "CER", "OT_SNAPSHOT": "SNAPSHOT", "OT_DELTA": "DELTA",
    "OT_NOTIFICATION": "NOTIFICATION",
}


@dataclass
class Witness:
    command: str
    skolems: dict[str, list[list[str]]]
    values: dict[str, dict[str, list[list[str]]]]
    signatures: dict[str, set[str]]
    provenance: dict

    @classmethod
    def from_xml(cls, path: Path, command: str, provenance: dict | None = None) -> Witness:
        try:
            root = ET.parse(path).getroot()
            instances = root.findall("instance")
            if len(instances) != 1:
                raise InvalidRun("seed generation currently requires a single-state witness")
            instance = instances[0]
            sigs = {s.get("ID"): s for s in instance.findall("sig")}
            signatures = {}
            values: dict[str, dict] = {}
            for sig in sigs.values():
                atoms = {a.attrib["label"] for a in sig.findall("atom")}
                signatures[sig.attrib["label"]] = atoms
                for atom in atoms:
                    values.setdefault(atom, {})
            for field in instance.findall("field"):
                for item in field.findall("tuple"):
                    atoms = [a.attrib["label"] for a in item.findall("atom")]
                    if len(atoms) < 2:
                        raise InvalidRun("invalid field tuple in witness")
                    values.setdefault(atoms[0], {}).setdefault(field.attrib["label"], []).append(atoms[1:])
            skolems = {
                s.attrib["label"]: [[a.attrib["label"] for a in t.findall("atom")]
                                    for t in s.findall("tuple")]
                for s in instance.findall("skolem")
            }
            return cls(command, skolems, values, signatures, provenance or {})
        except (OSError, ET.ParseError, KeyError) as exc:
            raise InvalidRun(f"{path}: cannot read complete witness: {exc}") from exc

    def relation(self, atom: str, field: str) -> list[str]:
        tuples = self.values.get(atom, {}).get(field, [])
        if any(len(t) != 1 for t in tuples):
            raise InvalidRun(f"{atom}.{field}: expected unary range")
        return [t[0] for t in tuples]

    def one(self, atom: str, field: str) -> str:
        targets = self.relation(atom, field)
        if len(targets) != 1:
            raise InvalidRun(f"{atom}.{field}: expected one target, got {targets}")
        return targets[0]

    def role(self, role: str) -> str:
        tuples = self.skolems.get(f"${self.command}_{role}", [])
        if len(tuples) != 1 or len(tuples[0]) != 1:
            raise InvalidRun(f"{self.command}: missing witness role {role}")
        return tuples[0][0]

    def object_type(self, atom: str) -> str:
        return OBJECT_TYPES[atom_kind(self.one(atom, "obj_type"))]

    def attack_objects(self, eligible: list[str]) -> list[str]:
        return self.objects_of("a", eligible)

    def objects_of(self, role: str, eligible: list[str] | None = None) -> list[str]:
        """Objects published by the PP bound to this role, in witness binding order."""
        pp = self.role(role)
        # Prefer existential objects that establish the violation, then delivery roles.
        bound = [atom for tuples in self.skolems.values() for t in tuples for atom in t]
        candidates = list(dict.fromkeys(bound + sorted(self.values)))
        return [atom for atom in candidates
                if self.relation(atom, "origin") == [pp]
                and (eligible is None or self.object_type(atom) in eligible)]

    def field_values(self, object_atom: str, field_id: str, *, pp_role: str = "a") -> list[str]:
        owner, field = field_id.split(".")
        if owner == "RPKIObject":
            targets = [object_atom]
        elif owner == "PP":
            targets = [self.role(pp_role)]
        elif owner == "CA":
            targets = [self.one(self.role(pp_role), "owner")]
        elif owner == "CMSSignedData":
            targets = [self.one(object_atom, "cms")]
        elif owner == "Certificate":
            targets = [self.one(self.one(object_atom, "cms"), "ee_certificate")]
        else:
            relation = {"ROAPayload": "roa_payload", "ASPAPayload": "aspa_payload",
                        "MFTPayload": "mft_payload", "CRLPayload": "crl_payload",
                        "MFTEntry": "mft_payload"}.get(owner)
            if relation is None:
                return []
            targets = self.relation(object_atom, relation)
            if owner == "MFTEntry":
                targets = [e for m in targets for e in self.relation(m, "file_list")]
        return list(dict.fromkeys(v for target in targets for v in self.relation(target, field)))

    def metadata(self, object_atom: str | None = None) -> dict:
        return {**self.provenance, "command": self.command, "skolems": self.skolems,
                "object_atom": object_atom, "relations": self.values}


def load_witness(model: Path, output: Path, command: str, *, validated: dict | None = None) -> Witness:
    data = validated if validated is not None else load_validated(model, output)[0]
    result = data["commands"].get(command)
    if not result or result["type"] != "check" or not result.get("solution"):
        raise InvalidRun(f"{command}: no SAT check witness")
    path = output / f"{command}-solution-0.xml"
    return Witness.from_xml(path, command, {
        "receipt_sha256": digest(output / "receipt.json"), "model_sources": model_sources(model),
        "witness_sha256": digest(path), "witness_format": "alloy-xml",
    })
