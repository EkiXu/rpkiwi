// base.als — RPKI domain vocabulary and structural constraints.
//
// Defines domain signatures and structural facts that hold across
// all RPKI validators. No validation logic, no RFC requirements —
// those are per-validator concerns modeled in cfrpki.als, routinator.als, etc.
//
// Alloy 6 — bounded relational model checking.
module base

open util/boolean

// =====================================================================
// Domain signatures
// =====================================================================

sig KeyId {}
sig Hash {}
sig Host {}
sig Prefix {}
sig ASN {}
// B3: Distinguished Name for issuer/subject matching (S4 auth)
sig Name {}
// C3: Certificate/CRL serial number (S4)
sig SerialNumber {}
// C8: RRDP session identifier (S2)
sig RRDPSessionId {}
// C8: RRDP serial number (S2)
sig RRDPSerial {}

sig URI { host: one Host }

abstract sig ObjectType {}
one sig OT_ROA, OT_MFT, OT_CRL, OT_ASPA, OT_CA_CERT,
        OT_SNAPSHOT, OT_DELTA, OT_NOTIFICATION extends ObjectType {}

// Parse outcome for certificate field parsing.
// Each validator constrains which outcomes are reachable based on its
// language-specific error handling (errx in C, panic in Go, Result in Rust).
// ParseOK: field parsed successfully.
// ParseFatal: parsing triggers a fatal error (errx/panic/abort) that may
//             terminate the process depending on the non-interference boundary.
abstract sig ParseOutcome {}
one sig ParseOK, ParseFatal extends ParseOutcome {}

sig SignerInfo {}

sig Certificate {
    issuer_ski: one KeyId,
    subject_ski: one KeyId,
    ip_resources: set Prefix,
    as_resources: set ASN,
    // X.509 validity period (notBefore/notAfter) parse safety.
    // Parsing time fields can trigger fatal errors in some implementations:
    //   C/rpki-client: timegm() returns -1 → errx(1, "timegm failed")
    //   C/FORT: pr_crit() on malformed time values
    //   Go: time.Parse returns error (recoverable)
    //   Rust/Haskell/Java: type-safe error propagation (recoverable)
    time_field_parse: one ParseOutcome,
    // B1: Inherit flag — True means ip/as_resources copy from parent (S5/S6 auth)
    resources_inherit: one Bool,
    // B2: Whether the validator enforces validity period rejection (all stages)
    validity_period_enforced: one Bool,
    // B3: Issuer and subject Distinguished Names (S4 auth)
    issuer_name: one Name,
    subject_name: one Name,
    // C3: Certificate serial number (S4)
    serial_number: one SerialNumber,
    // C4b: SIA rpkiNotify URI for RRDP notification (S5 cross-stage NI)
    // RFC 8182 §3.5.1: CA cert SIA may include rpkiNotify pointing to
    // RRDP notification endpoint. If not scoped to the issuing CA's
    // repository, attacker's child CA can redirect validator to victim's
    // RRDP endpoint, causing cache poisoning.
    sia_notify_uri: lone URI,
    // C4c: SIA caRepository URI for rsync repository scope (S5 cross-stage NI)
    // RFC 6487 §4.8.8: CA cert SIA caRepository points to rsync directory.
    // If not scoped to parent's repository, attacker's child CA redirects
    // rsync fetching to victim's directory.
    sia_repo_uri: lone URI,
    // C4d: SIA rpkiManifest URI scope (S5 cross-stage NI)
    // RFC 6487 §4.8.8: CA cert SIA rpkiManifest points to manifest object.
    // Must be under caRepository. If pointing elsewhere, attacker's manifest
    // could be fetched under victim's validation context.
    sia_mft_uri: lone URI,
    // C5: basicConstraints cA flag
    is_ca: one Bool,
    // C6: Public key parse safety
    pubkey_parse: one ParseOutcome
}

sig CMSSignedData {
    signer_infos: set SignerInfo,
    econtent_digest: one Hash,
    signed_attrs_digest: one Hash,
    signature_valid: one Bool,
    ee_certificate: one Certificate,
    // B4: CMS SignerIdentifier matches EE certificate
    sid_matches_ee: one Bool,
    // C7: eContentType OID matches expected type
    econtent_type_matches: one Bool
}

// A1: ROA eContent payload (S6 auth).
// Auth chain: roa_prefixes ⊆ EE.ip_resources ⊆ CA.delegated_prefixes.
sig ROAPayload {
    roa_prefixes: set Prefix
}

// A2: ASPA eContent payload (S6 auth).
// Auth check: customer_as ∈ EE.as_resources.
sig ASPAPayload {
    customer_as: one ASN,
    provider_asns: set ASN
}

// A4: Single entry in a manifest's fileList (filename→hash binding).
// Real manifests bind (filename, hash) pairs; validators look up child objects
// by filename and verify content_hash = entry_hash. Both fields are needed
// to model the pass-condition: validator accepts iff entry_uri matches child
// URI and entry_hash matches child content_hash.
sig MFTEntry {
    // A4: Filename URI from manifest fileList (S3 auth)
    entry_uri: one URI,
    // A4: Hash from manifest fileList (S3 auth)
    entry_hash: one Hash
}

// A4, C1: Manifest eContent payload (S3 auth).
// file_list binds child filenames to expected hashes; validators should
// verify that each child object's content_hash matches its MFT entry.
sig MFTPayload {
    // A4: Manifest fileList entries (S3 auth)
    file_list: set MFTEntry,
    // C1: MFT eContent thisUpdate parse safety (separate from cert time fields)
    mft_this_update_parse: one ParseOutcome,
    // C1: MFT eContent nextUpdate parse safety
    mft_next_update_parse: one ParseOutcome
}

// B3, C2, C3: CRL-specific fields (S4 auth/non-interference).
// C9: Real CRLs are X.509 CRLs, not CMS-wrapped. The model routes all
// objects through RPKIObject.cms for uniformity; CRL auth predicates
// should ignore CMS fields and use crl_payload instead.
sig CRLPayload {
    // C2: CRL thisUpdate parse safety
    crl_this_update_parse: one ParseOutcome,
    // C2: CRL nextUpdate parse safety
    crl_next_update_parse: one ParseOutcome,
    // C2: CRL revocationDate parse safety
    crl_revocation_date_parse: one ParseOutcome,
    // C3: Set of revoked certificate serial numbers
    revoked_serials: set SerialNumber,
    // B3: CRL issuer DN for cross-check against CA cert subject DN (S4 auth)
    crl_issuer: one Name
}

// C8: RRDP notification document (S2).
sig RRDPNotification {
    session_id: one RRDPSessionId,
    rrdp_serial: one RRDPSerial
}

sig CA {
    delegated_prefixes: set Prefix,
    // A3: AS number delegation (S5/S6 auth)
    delegated_asns: set ASN,
    // CA's own Subject Key Identifier — used for key ownership constraint.
    // Attacker cannot forge signatures against keys they do not possess.
    ca_ski: one KeyId
}

sig PP {
    owner: one CA,
    notifyURI: one URI,
    siaBase: one URI,
    objects: set RPKIObject,
    // C8: RRDP notification document served at notifyURI (S2)
    rrdp_notification: lone RRDPNotification
}

sig RPKIObject {
    origin: one PP,
    obj_type: one ObjectType,
    uri: one URI,
    content_hash: one Hash,
    cms: one CMSSignedData,
    // A1: ROA payload (present iff obj_type = OT_ROA)
    roa_payload: lone ROAPayload,
    // A2: ASPA payload (present iff obj_type = OT_ASPA)
    aspa_payload: lone ASPAPayload,
    // A4, C1: Manifest payload (present iff obj_type = OT_MFT)
    mft_payload: lone MFTPayload,
    // B3, C2, C3: CRL payload (present iff obj_type = OT_CRL)
    crl_payload: lone CRLPayload
}

one sig Attacker { controlled_pp: one PP }

// =====================================================================
// Derived accessors
// =====================================================================

fun aki[obj: RPKIObject]: KeyId { obj.cms.ee_certificate.issuer_ski }
fun ski[obj: RPKIObject]: KeyId { obj.cms.ee_certificate.subject_ski }

// =====================================================================
// Structural constraints (invariant across all validators)
// =====================================================================

fact pp_membership {
    all o: RPKIObject | o in o.origin.objects
    all p: PP | p.objects = { o: RPKIObject | o.origin = p }
}

fact minimum_pps { #PP >= 2 }

fact attacker_distinct {
    Attacker.controlled_pp.owner not in (PP - Attacker.controlled_pp).owner
}





fact legitimate_publication {
    all o: RPKIObject |
        o.origin != Attacker.controlled_pp implies
            o.uri.host = o.origin.siaBase.host
}



// --- Payload type consistency (A1, A2, A4, B3) ---
// Each payload type is present iff the object type matches.

fact payload_type_consistency {
    all o: RPKIObject {
        some o.roa_payload iff o.obj_type = OT_ROA
        some o.aspa_payload iff o.obj_type = OT_ASPA
        some o.mft_payload iff o.obj_type = OT_MFT
        some o.crl_payload iff o.obj_type = OT_CRL
    }
}

// Delivery occurrences may share a CMS object and payload (public replay).
// Entries belong to their canonical manifest payload.



fact mft_entry_ownership {
    all e: MFTEntry | one p: MFTPayload | e in p.file_list
}

// RFC 6486 §4.2.1: each manifest has at most one entry per filename.
// Prevents solver from creating two entries with same URI but different hashes,
// which would let both hash-match and hash-mismatch hold on the same child.
fact unique_mft_entry_uri {
    all p: MFTPayload, disj e1, e2: p.file_list | e1.entry_uri != e2.entry_uri
}

fact unique_rrdp_notifications {
    all disj p1, p2: PP |
        (some p1.rrdp_notification and some p2.rrdp_notification) implies
            p1.rrdp_notification != p2.rrdp_notification
}

// RFC 6487 §4.8.10: inherit marker replaces explicit resources.
// Prevents solver from assigning both inherit=True and non-empty ip/as_resources,
// which would cause spurious SAT in auth_s5/auth_s6 (C4 FP elimination).
fact inherit_implies_no_explicit_resources {
    all c: Certificate | c.resources_inherit = True implies
        (no c.ip_resources and no c.as_resources)
}

// Distinct CAs have distinct SKIs (no key collision between honest CAs).
fact distinct_ca_ski {
    all disj c1, c2: CA | c1.ca_ski != c2.ca_ski
}


// A content hash names canonical bytes, independently of delivery location.
// This abstracts collision resistance; the same bytes may be replayed by any PP.
fact content_hash_binding {
    all a, b: RPKIObject | a.content_hash = b.content_hash implies {
        a.obj_type = b.obj_type
        a.cms = b.cms
        a.roa_payload = b.roa_payload
        a.aspa_payload = b.aspa_payload
        a.mft_payload = b.mft_payload
        a.crl_payload = b.crl_payload
    }
}

// Collision resistance of the CMS eContent digest.  Equal eContent digests
// denote equal eContent, so the solver cannot pair a copied (matching)
// messageDigest with different payload bytes.  This is the same abstraction as
// content_hash_binding and is required for a validator's digest gate to be
// meaningful: without it, omitting the digest comparison and including it are
// indistinguishable in the model.  Byte-identical replay and modified content
// whose digest no longer matches remain representable.
fact econtent_digest_binding {
    all a, b: RPKIObject | a.cms.econtent_digest = b.cms.econtent_digest implies {
        a.roa_payload = b.roa_payload
        a.aspa_payload = b.aspa_payload
        a.mft_payload = b.mft_payload
    }
}

// The adversary may sign with its own CA, copy public signatures/certificates,
// and change unsigned eContent. It cannot invent a signature under a victim key.
// CMS signs signedAttrs, not eContent: a copied signature can remain valid while
// econtent_digest differs. The per-validator digest gate must catch that case.
fact attacker_signature_capability {
    all a: RPKIObject |
        a.origin = Attacker.controlled_pp and a.cms.signature_valid = True implies {
            aki[a] = Attacker.controlled_pp.owner.ca_ski or
            (some public: RPKIObject |
                public.origin != Attacker.controlled_pp and
                public.obj_type = a.obj_type and
                public.cms.signature_valid = True and
                public.cms.ee_certificate = a.cms.ee_certificate and
                public.cms.signed_attrs_digest = a.cms.signed_attrs_digest and
                public.cms.sid_matches_ee = a.cms.sid_matches_ee and
                public.cms.econtent_type_matches = a.cms.econtent_type_matches and
                (a.obj_type in (OT_CRL + OT_CA_CERT) implies
                    a.content_hash = public.content_hash))
        }
}

// Honest publication inputs are fixed, authenticated baselines. Their issuer
// identity does not come from an attacker's chosen AKI/SKI value.
fact honest_baseline {
    all o: RPKIObject | o.origin != Attacker.controlled_pp implies {
        o.cms.signature_valid = True
        o.cms.econtent_digest = o.cms.signed_attrs_digest
        o.cms.sid_matches_ee = True
        o.cms.econtent_type_matches = True
        one o.cms.signer_infos
        aki[o] = o.origin.owner.ca_ski
        o.cms.ee_certificate.time_field_parse = ParseOK
        o.cms.ee_certificate.pubkey_parse = ParseOK
        o.cms.ee_certificate.ip_resources in o.origin.owner.delegated_prefixes
        o.cms.ee_certificate.as_resources in o.origin.owner.delegated_asns
        o.roa_payload.roa_prefixes in o.origin.owner.delegated_prefixes
        o.aspa_payload.customer_as in o.origin.owner.delegated_asns
        o.obj_type = OT_CA_CERT implies ski[o] = o.origin.owner.ca_ski
    }
}

pred attack_context[attacker_pp, victim_pp: PP] {
    attacker_pp = Attacker.controlled_pp
    attacker_pp != victim_pp
    some attacker_pp.objects
}
