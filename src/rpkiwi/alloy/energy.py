from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .results import MODEL_DIR, load_validated
from .fields import energy_paths, load_fields

_DIR = Path(__file__).resolve().parent
_REGISTRY = _DIR / "model" / "field_registry.yaml"
_OUTPUT_DIR = _DIR / "output"

ASSERTION_FIELDS: dict[str, list[str]] = {
    "s2_ni_fetch_scope": ["PP.siaBase", "RPKIObject.uri"],
    "s2_ni_cache_workspace": ["PP.notifyURI"],
    "s3_ni_store_key": ["Certificate.subject_ski"],
    "s3_ni_manifest_lookup": ["Certificate.issuer_ski"],
    "s3_ni_parse_signerinfos": ["CMSSignedData.signer_infos"],
    "s3_ni_parse_time": ["Certificate.time_field_parse"],
    "s3_ni_parse_mft_this_update": ["MFTPayload.mft_this_update_parse"],
    "s3_ni_parse_mft_next_update": ["MFTPayload.mft_next_update_parse"],
    "s3_ni_parse_pubkey": ["Certificate.pubkey_parse"],
    "s3_ni_parse_mft_filename": ["MFTEntry.entry_uri"],
    "s3_conf_cms_digest": ["CMSSignedData.econtent_digest", "CMSSignedData.signed_attrs_digest"],
    "s3_conf_cms_signature": ["CMSSignedData.signature_valid"],
    "s3_conf_mft_hash": ["MFTEntry.entry_uri", "MFTEntry.entry_hash", "RPKIObject.content_hash"],
    "s4_ni_crl_store_key": ["Certificate.issuer_ski"],
    "s4_ni_crl_scope": ["CRLPayload.revoked_serials", "Certificate.serial_number"],
    "s4_ni_parse_crl_this_update": ["CRLPayload.crl_this_update_parse"],
    "s4_ni_parse_crl_next_update": ["CRLPayload.crl_next_update_parse"],
    "s4_ni_parse_crl_revocation_date": ["CRLPayload.crl_revocation_date_parse"],
    "s4_ni_parse_pubkey": ["Certificate.pubkey_parse"],
    "s4_conf_crl_signature": ["CMSSignedData.signature_valid"],
    "s5_ni_store_key": ["Certificate.subject_ski"],
    "s5_ni_chain_walk": ["Certificate.issuer_ski"],
    "s5_ni_sia_scope": ["Certificate.sia_notify_uri"],
    "s5_ni_sia_repo_scope": ["Certificate.sia_repo_uri"],
    "s5_ni_sia_mft_scope": ["Certificate.sia_mft_uri"],
    "s5_conf_resource": [
        "Certificate.ip_resources", "Certificate.as_resources",
        "Certificate.resources_inherit", "Certificate.is_ca",
    ],
    "s6_ni_store_key": ["Certificate.subject_ski"],
    "s6_ni_parse_signerinfos": ["CMSSignedData.signer_infos"],
    "s6_ni_parse_time": ["Certificate.time_field_parse"],
    "s6_ni_parse_pubkey": ["Certificate.pubkey_parse"],
    "s6_ni_parse_ip_resources": ["Certificate.ip_resources"],
    "s6_conf_roa_cms_digest": ["CMSSignedData.econtent_digest", "CMSSignedData.signed_attrs_digest"],
    "s6_conf_aspa_cms_digest": ["CMSSignedData.econtent_digest", "CMSSignedData.signed_attrs_digest"],
    "s6_conf_roa_cms_signature": ["CMSSignedData.signature_valid"],
    "s6_conf_aspa_cms_signature": ["CMSSignedData.signature_valid"],
    "s6_conf_roa_resource": ["ROAPayload.roa_prefixes", "Certificate.ip_resources", "CA.delegated_prefixes"],
    "s6_conf_aspa_resource": ["ASPAPayload.customer_as", "Certificate.as_resources", "CA.delegated_asns"],
}

_VALIDATOR_DIR_NAMES: dict[str, str] = {
    "cfrpki": "cfrpki",
    "routinator": "routinator",
    "rpki-client": "rpki_client",
    "fort": "fort",
    "rpki-prover": "rpki_prover",
    "rpki-validator-3": "rpki_validator_3",
    "rpstir2": "rpstir2",
}

# A field assertion absent from a model is normally an incomplete-model error.
# These two are source-review findings, not omissions: RIPE Validator 3's CRL
# path does not parse a public key (the registry scopes pubkey_parse to
# ROA/ASPA/MFT/CER) and it has no field for a malformed resource encoding
# (rpki-commons reports one as a validation error).  The model records the
# decisions that do apply; the seed factory simply has no field to seed here.
VALIDATOR_OPTIONAL_ASSERTIONS: dict[str, set[str]] = {
    "rpki-validator-3": {"s4_ni_parse_pubkey", "s6_ni_parse_ip_resources"},
    # The paper's OctoRPKI/rpstir2 audit model covers S5-NI through the
    # chain-walk and SIA scope decisions; the S5 store-key assertion is not
    # part of that model.
    "cfrpki": {"s5_ni_store_key"},
    "rpstir2": {"s5_ni_store_key", "s3_conf_cms_signature",
                "s6_conf_roa_cms_signature", "s6_conf_aspa_cms_signature"},
}

_STAGE_OBJECTS: dict[str, list[str]] = {
    "s2_": ["DELTA", "NOTIFICATION", "SNAPSHOT"],
    "s3_": ["MFT"],
    "s4_": ["CRL"],
    "s5_": ["CER"],
}

def assertion_object_types(name: str) -> list[str]:
    for prefix, types in _STAGE_OBJECTS.items():
        if name.startswith(prefix):
            return types
    if name.startswith("s6_") and "roa" in name:
        return ["ROA"]
    if name.startswith("s6_") and "aspa" in name:
        return ["ASPA"]
    if name.startswith("s6_"):
        return ["ROA", "ASPA"]
    return []

_assertion_object_types = assertion_object_types

def model_stem(validator: str) -> str:
    """The .als/output directory name for a validator."""
    return _VALIDATOR_DIR_NAMES[validator]

def missing_assertions(validator: str, checked: dict[str, str] | set[str]) -> list[str]:
    allowed_missing = VALIDATOR_OPTIONAL_ASSERTIONS.get(validator, set())
    return sorted(set(ASSERTION_FIELDS) - set(checked) - allowed_missing)


def load_results(
    validator: str,
    output_dir: Path | None = None,
) -> dict[str, str]:
    d = (output_dir or _OUTPUT_DIR) / model_stem(validator)
    _, results = load_validated(MODEL_DIR / f"{d.name}.als", d)
    checked = {r.command: "SAT" if r.satisfiable else "UNSAT"
               for r in results if r.kind == "check"}
    missing = missing_assertions(validator, checked)
    if missing:
        raise ValueError(f"{validator}: unchecked field assertions: {missing}")
    # Optional assertions are absent because the implementation does not have
    # that field/check; they are not UNSAT and carry no seed energy.
    return {a: checked[a] for a in ASSERTION_FIELDS if a in checked}

def load_all_results(
    output_dir: Path | None = None,
) -> dict[str, dict[str, str]]:
    return {v: load_results(v, output_dir) for v in _VALIDATOR_DIR_NAMES}

# No import-time I/O: results must be read after runner finishes this invocation.
ALL_VALIDATORS = tuple(_VALIDATOR_DIR_NAMES)


def fields_for(validator: str, assertion: str) -> list[str]:
    if validator == "rpki-prover" and assertion in {
        "s3_ni_store_key", "s4_ni_crl_store_key", "s5_ni_store_key", "s6_ni_store_key",
    }:
        return ["RPKIObject.content_hash"]
    if validator == "rpki-validator-3" and assertion == "s3_ni_store_key":
        return ["Certificate.issuer_ski"]
    return ASSERTION_FIELDS.get(assertion, [])

def load_registry() -> dict[str, str | None]:
    return {fid: entry.get("find_path") for fid, entry in load_fields().items()}

def derive_energy(
    results: dict[str, str],
    assertion_fields: dict[str, list[str]] | None = None,
    *, validator: str | None = None,
) -> dict[str, dict[str, float]]:
    registry = load_fields()

    energy: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    for assertion, result in results.items():
        if result != "SAT":
            continue
        fields = (assertion_fields.get(assertion, []) if assertion_fields is not None
                  else fields_for(validator or "", assertion))
        obj_types = _assertion_object_types(assertion)
        for field_id in fields:
            for ot in obj_types:
                for path in energy_paths(registry[field_id], ot):
                    energy[ot][path] += 1.0

    return {k: dict(sorted(v.items(), key=lambda x: -x[1])) for k, v in sorted(energy.items())}

def main() -> None:
    for validator, results in sorted(load_all_results().items()):
        energy = derive_energy(results, validator=validator)

        sat_count = sum(1 for v in results.values() if v == "SAT")
        unsat_count = sum(v == "UNSAT" for v in results.values())
        pending = sum(v == "PENDING" for v in results.values())
        print(f"{validator}: {sat_count} SAT / {unsat_count} UNSAT / {pending} PENDING")

        if not energy:
            print("  (no energy — all UNSAT)\n")
            continue

        for obj_type, paths in energy.items():
            print(f"  {obj_type}:")
            for path, score in paths.items():
                print(f"    {score:4.1f}  {path}")
        print()

if __name__ == "__main__":
    main()
