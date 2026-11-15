// topo.als — rpkiwi experimental topology.
//
// Binds Alloy abstract atoms to the scaffold PKI identities.
// Each validator .als opens topo (which opens base) instead of base directly.
// Counterexamples directly reference named atoms (VictimCA, AttackerPP, etc.),
// making concretization a trivial name→file lookup.
//
// Scaffold layout:
//   build/identity/ta/ta.cer              — TA (SKI: +apJxRIm+UczA41joVrcG0FHf7E=)
//   build/identity/ca/victim-ca/          — Victim CA cert, key, CRL, MFT, ROAs
//   build/identity/ca/attacker-ca/        — Attacker CA cert, key, CRL, MFT, ROAs
//   build/publication/victim-pp.com/      — Victim publication point
//   build/publication/attacker-pp.com/    — Attacker publication point
//
// Alloy 6 — bounded relational model checking.
module topo

open base
open util/boolean

// =====================================================================
// Named atoms — one-to-one with scaffold identities
// =====================================================================

// CAs
one sig VictimCA, AttackerCA extends CA {}

// Publication Points
one sig VictimPP, AttackerPP extends PP {}

// CA key identifiers (distinct by construction)
one sig VictimSKI, AttackerSKI, TaSKI extends KeyId {}

// IP prefix delegations
one sig VictimPrefix, AttackerPrefix extends Prefix {}

// AS number delegations
one sig VictimASN, AttackerASN extends ASN {}

// Certificate serial numbers
one sig VictimSerial, AttackerSerial extends SerialNumber {}

// Distinguished names
one sig VictimDN, AttackerDN extends Name {}

// URI hosts
one sig VictimHost, AttackerHost extends Host {}

// Manifest filenames in victim baseline
one sig VictimROAUri, VictimCRLUri extends URI {}

// Content hashes for victim baseline objects
one sig VictimROAHash, VictimCRLHash extends Hash {}

// =====================================================================
// Scaffold topology facts
// =====================================================================

fact topology {
    // PP ownership
    VictimPP.owner = VictimCA
    AttackerPP.owner = AttackerCA

    // Attacker identity
    Attacker.controlled_pp = AttackerPP

    // CA keys (from scaffold certs)
    // victim-ca SKI: qcaJA38nsxw9U9rvVOd6ej4xMlQ=
    // attacker-ca SKI: npX/pkc+vz9dCfYzcngJ+WjHRiQ=
    VictimCA.ca_ski = VictimSKI
    AttackerCA.ca_ski = AttackerSKI

    // Resource delegations
    // victim-ca: 4.0.0.0/8, ASNs 1001-2000
    // attacker-ca: 3.0.0.0/8, ASN 1000
    VictimCA.delegated_prefixes = VictimPrefix
    AttackerCA.delegated_prefixes = AttackerPrefix
    VictimCA.delegated_asns = VictimASN
    AttackerCA.delegated_asns = AttackerASN

    // No overlap between delegations
    VictimPrefix != AttackerPrefix
    VictimASN != AttackerASN

    // PP hosts
    VictimPP.siaBase.host = VictimHost
    AttackerPP.siaBase.host = AttackerHost
    VictimPP.notifyURI.host = VictimHost
    AttackerPP.notifyURI.host = AttackerHost

    // Distinguished names
    // (used for CRL issuer DN matching)
    VictimDN != AttackerDN

    // Victim baseline objects — MFT fileList references
    VictimROAUri.host = VictimHost
    VictimCRLUri.host = VictimHost
}

// =====================================================================
// Ground truth: build/public_constants.json
// =====================================================================
//
// All concrete values (SKI, prefix, ASN, serial, filenames, hashes,
// RRDP session/serial) are exported by bootstrap_lab() into
// build/public_constants.json. seed_factory.py reads that file at
// seed generation time — no hardcoded values, no cert parsing.
//
// The named atoms above (VictimSKI, AttackerPrefix, etc.) correspond
// to entries in public_constants.json → identity.{victim-ca,attacker-ca}.

// Dedicated PPs are the paper's bounded audit scenario; these are topology
// assumptions, not RFC guarantees about every real shared publication service.
fact dedicated_publication_points {
    all disj a, b: PP | a.siaBase.host != b.siaBase.host
    all disj a, b: PP | a.notifyURI != b.notifyURI
}

// Every invocation also checks that a valid public replay is representable.
// An UNSAT result here invalidates the assertion results as vacuous.
pred model_satisfiable {
    some a, v: RPKIObject |
        a.origin = AttackerPP and v.origin = VictimPP and
        a.obj_type = OT_ROA and a.content_hash = v.content_hash and
        a.cms.signature_valid = True and aki[a] = VictimSKI
}
