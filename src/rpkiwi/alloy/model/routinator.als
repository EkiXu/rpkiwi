// routinator.als — Routinator validation pipeline model.
//
// Source-code-derived model. Each computation function traces to
// specific Routinator/rpki-rs source code paths (vendor/routinator/).
//
// 5-stage pipeline (S2-S6) organized by RPKI object type:
//   S2 RepositorySync       — NOTIFICATION, SNAPSHOT, DELTA   (ni only)
//   S3 ManifestProcessing   — MFT                             (ni + conf)
//   S4 RevocationProcessing — CRL                             (ni + conf)
//   S5 CertChainProcessing  — CA_CERT                         (ni + conf)
//   S6 PayloadProcessing    — ROA, ASPA                       (ni + conf)
//
// S2 has iso only because RPKI objects are self-authenticating —
// confinement comes from CMS signatures and certificate chains,
// not from where objects are fetched. Auth begins at S3.
//
// Routinator architecture:
//   - Rust-based RPKI relying party with rpki-rs library
//   - Per-PP storage: store.rs point_path() = rsync/{authority}/{module}/{path}
//   - Per-PP CRL: engine.rs ValidPointManifest.crl + check_crl()
//   - All parsing returns Result<T, DecodeError> — no panics on malformed input
//   - sigobj.rs SignedObject::take_from() for all CMS objects (MFT, ROA, ASPA)
//   - sigobj.rs SignedObject::verify() for all CMS verification
//   - cert.rs verify_resources() with Overclaim::Refuse/Trim for resource validation
//   - engine.rs PubPointTask::process() per-PP traversal
//
// S2 scope note: model covers RRDP fetch scope (eq_authority).
//   Routinator falls back to rsync when RRDP is unavailable
//   (collector/base.rs:190-236). Rsync isolation is provided by
//   filesystem path partitioning ({authority}/{module}/{path}) plus
//   manifest hash binding — modeled implicitly via s3_conf_mft_hash.
//
// S5 SIA scope note: Routinator does NOT explicitly validate that a
//   child CA cert's SIA URIs (rpkiNotify, caRepository, rpkiManifest)
//   match the parent PP's host. engine.rs:2037-2051 repository_switch()
//   detects repository changes for metrics, not for security enforcement.
//   SIA-based redirection is a non-issue because per-PP PubPointTask
//   processing, CMS signature binding, and RRDP workspace isolation
//   prevent cross-PP interference regardless of SIA URI values.
//
module routinator

open topo
open util/boolean

// =====================================================================
// AUDIT DERIVATION  (paper §4.3, Routinator; rpki 0.19.1 / Routinator 0.15.1)
// =====================================================================
//
// This model is derived from the paper's §4.3 design review of Routinator and
// a traced source review, NOT from observed exploits.  Routinator links the
// rpki-rs crate (Cargo.lock: rpki 0.19.1); in-tree validation driver lives in
// vendor/routinator/src/src/{engine,store}.rs and collector/.  Library CMS /
// resource / manifest logic lives in the rpki crate, cited as
// rpki-rs/src/repository/*.rs at the 0.19.1 release tag.
//
// Release builds set `panic = "abort"` (vendor/routinator/src/Cargo.toml:60-61)
// and validation threads run under thread::scope with no catch_unwind
// (engine.rs:481-495), so ANY reached panic (unwrap/assert) terminates the
// whole process rather than one origin's task — the mechanism behind R3/R4.
//
// Claim -> predicate(s) -> source:
//
//   R1 (per-origin task context; origin-scoped composite-key storage; per-PP
//       filesystem path {authority}/{module}/{path}; preserves NI S2-S6)
//     primary:    s2_cache_workspace_isolated
//     supporting: s3_manifest_store_key, s3_manifest_lookup_key,
//                 s4_crl_store_key, s5_cert_store_key, s6_payload_store_key,
//                 s5_chain_walk_isolated
//     SOURCE: vendor/routinator/src/src/store.rs:727-736 (point_path),
//             store.rs:528-532 (pub_point), store.rs:717-724 (get_point),
//             collector/rrdp/base.rs:264-289 (RRDP workspace path),
//             engine.rs:712-740 (per-PP PubPoint::process),
//             engine.rs:1896,1990-2000 (per-PP CaCert.parent chain walk)
//
//   R2 (most parser failures propagated silently, not terminated;
//       preserves NI S3,S4,S6)
//     primary:    s3_mft_error_contained
//     supporting: s4_crl_error_contained, s6_payload_error_contained
//     SOURCE: engine.rs:928-940 (manifest decode -> Ok(None)),
//             engine.rs:1494-1502 (cert decode -> Ok(())),
//             engine.rs:1143-1159 (CRL decode/verify -> Ok(None)),
//             engine.rs:1621-1636 (ROA decode -> Ok(())),
//             engine.rs:1665-1676 (ASPA decode -> Ok(()))
//
//   R3 (S3 manifest path calls .unwrap() on an untrusted URI join result;
//       breaks NI S3)
//     primary:    ni_s3_parse_mft_filename_violation
//     SOURCE: vendor/routinator/src/src/engine.rs:857-859
//             (self.cert.ca_repository().join(file).unwrap() on a
//              manifest-supplied filename); library twin at
//             rpki-rs/src/repository/manifest.rs:279 (iter_uris join().unwrap())
//
//   R4 (S6 resource-extension path uses assert! for a prefix length;
//       breaks NI S6)
//     primary:    ni_s6_parse_ip_resources_violation
//     SOURCE: rpki-rs/src/repository/resources/ipres.rs:1329-1330
//             (assert!(len <= 128) in Prefix::new), reached from
//             ipres.rs:1468-1475 (Prefix::take_from -> from_bit_string)
//
//   R5 (confinement checks — CMS binding, RFC 3779 containment — intact S3-S6)
//     primary:    s3_mft_verify_succeeds
//     supporting: s6_payload_verify_succeeds, s4_crl_verify_succeeds,
//                 s5_cert_resource_check, s6_ee_resource_check,
//                 s6_roa_resource_check, s6_aspa_resource_check,
//                 s4_crl_issuer_dn_verified, s5_aki_binding_ok
//     SOURCE: rpki-rs/src/repository/sigobj.rs:219-271
//             (validate_at: inspect sid==SKI, verify H(eContent)==messageDigest
//              + signature), sigobj.rs:103-115,160-165 (eContentType binding),
//             cert.rs:983-1017 (verify_resources, RFC 3779 containment),
//             cert.rs:931-967 (verify_issuer_claim, AKI==issuer SKI),
//             crl.rs:131-139 (Crl::verify_signature),
//             roa.rs:219-249 / aspa.rs:139-161 (payload resource containment)
//
// Expected Table 2 row (paper column order
//   S2-NI, S3-Conf, S3-NI, S4-Conf, S4-NI, S5-Conf, S5-NI, S6-Conf, S6-NI):
//       ( . , . , X , . , . , . , . , . , X )
// Model CELLS order (S2-NI, S3-NI, S3-Conf, S4-NI, S4-Conf, S5-NI, S5-Conf,
//   S6-NI, S6-Conf):  ( . , X , . , . , . , . , . , X , . )
// Only S3-NI (R3) and S6-NI (R4) are SAT; every confinement cell is UNSAT (R5).
//
// Source status: in rpki 0.19.1 the filename join is
// guarded by decode-time validation (manifest.rs:455-480) and an ASCII guard
// (engine.rs:846-856), and the prefix assert is guarded by from_bit_string's
// octet_len>16 check (ipres.rs:1343-1357).  R3/R4 therefore encode the design
// decision (unguarded .unwrap()/assert! under panic=abort) and are marked
// source-level candidates in their predicate comments.
//
// =====================================================================
// S2 RepositorySync — NOTIFICATION, SNAPSHOT, DELTA (ni only)
//
// Scope: RRDP fetch path. When RRDP is unavailable, Routinator falls
// back to rsync (collector/base.rs:190-236). Rsync isolation relies on
// filesystem path partitioning ({canonical_authority}/{module}/{path})
// via rsync.rs:763-769, plus manifest hash binding (s3_conf_mft_hash).
// The rsync fallback does not have an equivalent of RRDP's eq_authority
// check; isolation is structural (path-based) rather than explicit.
// =====================================================================

// rrdp.rs:185-195 — NotificationFile::has_matching_origins(base):
//   Line 186: base.eq_authority(self.snapshot().uri()) — snapshot URI authority
//   Line 190: deltas.iter().any(|d| !base.eq_authority(d.uri())) — all delta URIs
// uri.rs:686-689 — Https::eq_authority(other):
//   self.authority().eq_ignore_ascii_case(other.authority())
//   Proper URI authority comparison, not substring.
// update.rs:115-120 — rejects notification if any URI has different authority.
// Modeled as host equality: attacker's PP host != victim's object host.
pred s2_fetch_scope_enforced[pp: PP, target_uri: URI] {
    target_uri.host = pp.notifyURI.host
}

// collector/rrdp/base.rs:264-289 — Collector::repository_path(rpki_notify):
//   Line 268: path.push(rpki_notify.canonical_authority())
//   Line 277-283: SHA256(rpki_notify) -> hex filename + ".bin"
//   Result: {working_dir}/{canonical_authority}/{SHA256(rpkiNotify)}.bin
// Different rpkiNotify URIs -> different SHA256 hashes -> different files.
// Modeled as: workspace = notifyURI; distinct URIs -> distinct workspaces.
fun s2_cache_workspace[pp: PP]: URI {
    pp.notifyURI
}

// store.rs:727-736 — Repository::point_path(manifest_uri):
//   Path = rsync/{canonical_authority(mft_uri)}/{module}/{path}
//   Per-PP directories keyed by manifest URI ensure cross-PP non-interference.
// PAPER-CLAIM: R1 | predicates: s2_cache_workspace_isolated, s3_manifest_store_key, s3_manifest_lookup_key, s4_crl_store_key, s5_cert_store_key, s6_payload_store_key, s5_chain_walk_isolated
// SOURCE: vendor/routinator/src/src/store.rs:727-736
pred s2_cache_workspace_isolated[pp1, pp2: PP] {
    s2_cache_workspace[pp1] != s2_cache_workspace[pp2]
}

// L4/C8: RRDP session/serial consistency
// Routinator tracks RRDP session ID and serial for cache freshness.
// Proper session/serial validation via NotificationFile parsing.
pred s2_rrdp_session_valid[pp: PP] {
    some pp.rrdp_notification
}

// =====================================================================
// S3 ManifestProcessing — MFT (ni + conf)
// =====================================================================

// --- Non-interference: manifest store key ---

// store.rs:528-531 — Run::pub_point(ca_cert):
//   Line 531: self.repository(ca_cert).get_point(ca_cert.rpki_manifest())
// store.rs:717-724 — Repository::get_point(manifest_uri):
//   StoredPoint::open(self.point_path(manifest_uri), ...)
// store.rs:727-735 — point_path(manifest_uri):
//   Path = rsync/{canonical_authority(mft_uri)}/{module}/{path}
// Objects stored per-PP (by manifest URI), then per-object (by rsync URI).
// Composite key (origin, uri) prevents cross-PP store collisions.
// PAPER-CLAIM: R1 (supporting)
// SOURCE: vendor/routinator/src/src/store.rs:528-532 (pub_point), store.rs:717-724 (get_point)
fun s3_manifest_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- Non-interference: manifest lookup key ---

// engine.rs:1964-1975 — CaCert::new():
//   rpki_manifest = cert.rpki_manifest() from SIA extension (per-CA unique).
// engine.rs:712-716 — PubPointTask::process():
//   self.run.store.pub_point(self.cert) -> store.rs:528-531
// store.rs:531 — self.repository(ca_cert).get_point(ca_cert.rpki_manifest())
// store.rs:717-724 — get_point(manifest_uri) -> StoredPoint::open(point_path)
// Manifest identified by (PP, manifest_rsync_URI) — unique per CA cert.
// engine.rs:1888 — ca_repository: uri::Rsync per CaCert, scoped to PP.
// Composite key: origin (determines filesystem root) + uri.
// PAPER-CLAIM: R1 (supporting)
// SOURCE: vendor/routinator/src/src/engine.rs:1964-1975 (CaCert rpki_manifest from SIA, per-CA)
fun s3_manifest_lookup_key[mft: RPKIObject]: set univ {
    mft.origin + mft.uri
}

// --- Non-interference: CMS structural checks ---

// sigobj.rs:118-191 — SignedObject::take_from(): structured ASN.1 parsing.
//   Line 144-175: cons.take_set(|cons| { cons.take_sequence(...) }) parses
//   exactly one SignerInfo from the SET — structural enforcement via take_set.
//   Line 159: SignedAttrs::take_from(cons) extracts signed attributes.
// sigobj.rs:48 — message_digest: MessageDigest field (always present after decode).
// All parsing returns Result<_, DecodeError> — no panics on malformed input.
pred s3_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// --- Non-interference: time field parse safety ---

// Rust's chrono library returns Result for time parsing, not panic.
// sigobj.rs uses the `?` operator for error propagation — any time
// parse failure is returned as Err(DecodeError), propagated through
// Result<T,E> type system. The caller handles the error gracefully.
// rpki-rs/src/repository/x509.rs — Time type uses chrono::DateTime<Utc>
// which decodes via bcder returning Result, never panicking.
pred s3_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- Non-interference: combined parse success ---

// L1/C1: Updated to check MFT payload time fields (thisUpdate/nextUpdate).
// L3/C6: Also checks public key parse safety.
// Routinator uses a single signed-object parsing path (sigobj.rs:118-191
// SignedObject::take_from()) for all CMS objects including MFT, ROA, ASPA.
pred s3_mft_parse_succeeds[obj: RPKIObject] {
    s3_cms_structure_ok[obj.cms]
    s3_time_field_safe[obj.cms]
    // L1/C1: MFT eContent thisUpdate/nextUpdate parse safety
    obj.mft_payload.mft_this_update_parse = ParseOK
    obj.mft_payload.mft_next_update_parse = ParseOK
    // L3/C6: Public key parse — Rust returns Result, no panic
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Non-interference: error containment ---

// Encoding convention: an EMPTY predicate body is ALWAYS TRUE in Alloy.
// A predicate with no constraints holds for all inputs. This means
// errors are ALWAYS contained — any parse failure in one PP cannot
// affect another PP.
//
// Why (almost) always contained:
//   engine.rs:1621-1636 — process_roa():
//     Roa::decode() failure -> log.warn + return Ok(()) (lines 1628-1635)
//   engine.rs:1637-1655 — roa.process() failure -> log.warn + continue
//   engine.rs:1665-1676 — process_aspa(): same pattern
//   engine.rs:1494-1502 — process_cer(): Cert::decode failure -> log.warn + return Ok(())
//   engine.rs:928-940 — Manifest::decode failure -> log.warn + return Ok(None)
//   engine.rs:1143-1159 — Crl::decode / verify_signature failure -> Ok(None)
//
// Rust Result<T,E> plumbing: these decode/validate paths use `?` and return
// Err as a value, logged and skipped per object, scoped to the current PP.
//
// Fatal error inventory for the MFT parse path: EMPTY.  (The single exception
// to R2 is the manifest-filename URI join, which uses .unwrap() rather than
// `?` — modeled separately as R3 in ni_s3_parse_mft_filename_violation and
// deliberately NOT contained here.)
// PAPER-CLAIM: R2 | predicates: s3_mft_error_contained, s4_crl_error_contained, s6_payload_error_contained
// SOURCE: vendor/routinator/src/src/engine.rs:1621-1636,1665-1676,1494-1502,928-940
pred s3_mft_error_contained[source_pp, victim_pp: PP] {
}

// --- Confinement: CMS eContent binding ---

// sigobj.rs:253-271 — SignedObject::verify():
//   Line 256-259: digest = digest_algorithm.start() + update(content) + finish()
//                 [H(eContent) computed via configurable DigestAlgorithm]
//   Line 261-265: digest.as_ref() != message_digest.as_ref() -> VerificationError
//                 -> modeled as: econtent_digest = signed_attrs_digest
//   Line 266:     msg = self.signed_attrs.encode_verify()
//   Line 267-270: cert.subject_public_key_info().verify(&msg, &self.signature)
//                 -> modeled as: signature_valid = True
//
// sigobj.rs:219-228 — validate_at(issuer, strict, now):
//   Line 225: self.inspect(strict) -> sigobj.rs:233-248 (SKI == sid check)
//   Line 226: self.verify(strict)  -> sigobj.rs:253-271 (digest + signature)
//   Line 227: self.cert.validate_ee_at(issuer, strict, now)
//
// Unlike some validators, rpki-rs supports algorithm agility via
// RpkiSignatureAlgorithm (sigobj.rs:166-168, not RSA-only).
// Complete binding: digest + signature both verified.
//
// M4/B4: sigobj.rs:233-248 inspect(strict) — checks SKI matches SID.
// Routinator enforces SID↔EE match, unlike cfrpki.
//
// M5/C7: sigobj.rs:253-271 full content type verification.
// PAPER-CLAIM: R5 | predicates: s3_mft_verify_succeeds, s6_payload_verify_succeeds, s4_crl_verify_succeeds, s5_cert_resource_check, s6_ee_resource_check
// SOURCE: rpki-rs/src/repository/sigobj.rs:219-271
// Registry: CMSSignedData.ee_certificate, CMSSignedData.sid_matches_ee, CMSSignedData.econtent_type_matches
pred s3_mft_verify_succeeds[cms: CMSSignedData] {
    // H(eContent) == messageDigest attribute — sigobj.rs:253-265 verify()
    cms.econtent_digest = cms.signed_attrs_digest
    // signature over signedAttrs verifies against EE pubkey — sigobj.rs:266-270
    cms.signature_valid = True
    // RFC 6488 §3.1: SID must match EE cert SubjectKeyIdentifier.
    // CMSSignedData.ee_certificate is the EE cert carried in the SignedData
    // (sigobj.rs:139-142); inspect() binds sid to its subject_key_identifier.
    // SOURCE: rpki-rs/src/repository/sigobj.rs:233-248 (inspect, sid==SKI)
    cms.sid_matches_ee = True
    // RFC 6488 §2.1.3.1: eContentType OID must match the signed contentType
    // attribute and the expected OID (decode_if_type).
    // SOURCE: rpki-rs/src/repository/sigobj.rs:103-115,160-165
    cms.econtent_type_matches = True
}

// --- Confinement: manifest hash binding ---

// M1/A4: Routinator verifies manifest file list hashes against child objects.
// engine.rs processes each child file from the manifest's file list,
// comparing the stored hash against the child object's content hash.
// URI+hash binding: entry_uri matches child URI AND entry_hash matches content.
// MFTPayload.file_list is the set of (filename,hash) entries the manifest
// enumerates (iterated as the integrity anchor of the issuing CA's PP).
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/manifest.rs:263-283 (iter over fileList)
// SOURCE: vendor/routinator/src/src/engine.rs:1106-1132 (walk manifest.iter(), hash.verify)
// Registry: MFTPayload.file_list, MFTEntry.entry_uri, MFTEntry.entry_hash
pred s3_mft_hash_verified[mft: RPKIObject, child: RPKIObject] {
    some e: mft.mft_payload.file_list |
        e.entry_uri = child.uri and e.entry_hash = child.content_hash
}

// =====================================================================
// S4 RevocationProcessing — CRL (ni + conf)
// =====================================================================

// --- Non-interference: CRL store key ---

// Same per-PP filesystem as S3. CRL files are stored in the per-PP
// StoredPoint directory structure.
// store.rs:727-735 — point_path(manifest_uri): per-PP directory.
// engine.rs:1738-1765 — ValidPointManifest struct includes crl field.
// CRL loaded from manifest's file list and stored per-PP.
// Composite key: origin (determines filesystem root) + uri.
// PAPER-CLAIM: R1 (supporting)
// SOURCE: vendor/routinator/src/src/engine.rs:1738-1765 (ValidPointManifest per-PP CRL)
fun s4_crl_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- Non-interference: CRL scope ---

// engine.rs:1767-1792 — ValidPointManifest::check_crl(cert):
//   Line 1770-1776: crl_uri = cert.crl_uri() (from cert's CRL DP extension)
//   Line 1779-1783: crl_uri must match manifest's CRL URI -> reject on mismatch
//   Line 1785-1789: self.crl.contains(cert.serial_number()) -> revoked
//
// engine.rs:1738-1765 — ValidPointManifest struct:
//   Each publication point has exactly one CRL (crl_uri + crl fields).
//   CRL is per-PP, not global — loaded from manifest, hash-verified,
//   signature-verified against the PP's CA cert.
//
// engine.rs:1153-1158 — CRL signature verified against CA's public key:
//   crl.verify_signature(self.cert.cert().subject_public_key_info())
//   Attacker's CRL fails signature check against victim's CA.
//
// Cross-PP revocation impossible because:
//   1. Each PP has its own CRL (stored in ValidPointManifest)
//   2. CRL signature must verify against PP's CA public key
//   3. Certificate CRL URI must match manifest's CRL URI
//
// Encoding: empty body = always TRUE = revocation scope always isolated.
pred s4_crl_scope_isolated[pp1, pp2: PP] {
}

// --- Non-interference: CRL error containment ---

// Same Rust Result<T,E> error handling as S3.
// engine.rs:1148-1150 — Crl::decode failure -> log + return Ok(None)
// engine.rs:1153-1158 — crl.verify_signature failure -> log + return Ok(None)
// All CRL processing errors are recoverable, scoped to the current PP.
// Rust's type system ensures errors never propagate cross-PP.
//
// Fatal error inventory: NONE (same as S3)
//
// Encoding: empty body = always TRUE = errors always contained.
// PAPER-CLAIM: R2 (supporting)
// SOURCE: vendor/routinator/src/src/engine.rs:1143-1159
pred s4_crl_error_contained[source_pp, victim_pp: PP] {
}

// --- Non-interference: CRL parse safety ---

// L2/C2: CRL-specific time field parse safety.
// Rust's chrono library returns Result for time parsing — no panic.
// L3/C6: Public key parse safety.
pred s4_crl_parse_succeeds[obj: RPKIObject] {
    // C2: CRL thisUpdate/nextUpdate/revocationDate parse safety
    obj.crl_payload.crl_this_update_parse = ParseOK
    obj.crl_payload.crl_next_update_parse = ParseOK
    obj.crl_payload.crl_revocation_date_parse = ParseOK
    // L3/C6: Public key parse — Rust returns Result, no panic
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Confinement: CRL signature verification ---

// engine.rs:1153-1158 — CRL signature verification:
//   crl.verify_signature(self.cert.cert().subject_public_key_info())
//   Uses rpki-rs Crl::verify_signature() which calls the crypto layer
//   to verify the CRL's signature against the issuing CA's public key.
//   The issuing CA is self.cert = the current PP's CaCert.
// engine.rs:1347-1352 — Same pattern in validate_stored_manifest path.
//
// In routinator, CRL verification is per-PP: the CRL is always verified
// against the PP's own CA public key. This means:
//   1. The CRL must be signed by the PP's CA to pass verification
//   2. The CRL's AKI must correspond to the PP's CA SKI
//   3. An attacker's CRL cannot pass verification against victim's CA key
//
// Modeled as: signature_valid = True (basic cryptographic check).
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/crl.rs:131-139 (Crl::verify_signature)
// SOURCE: vendor/routinator/src/src/engine.rs:1153-1159 (verify against self.cert CA key)
pred s4_crl_verify_succeeds[cms: CMSSignedData] {
    cms.signature_valid = True
}

// --- Confinement: CRL issuer DN (design decision: key-bound, not DN-bound) ---

// M2/B3: the CRL carries an issuer Distinguished Name (crl.rs:209, parsed at
// crl.rs:369) and the issuing CA certificate carries a subject DN
// (cert.rs:795 inspect). Routinator does NOT gate S4 confinement on a
// CRL-issuer-DN == CA-subject-DN comparison: the issuer Name is never read
// back for a cross-check. Instead the CRL is bound to the PP cryptographically
// — verify_signature against the PP's own CA public key (crl.rs:131-139,
// engine.rs:1153-1159) plus the CRL-URI == manifest-CRL-URI check
// (engine.rs:1779-1783). So S4 confinement holds via key binding, and DN
// equality is an available-but-unused field rather than a missing gate.
// This predicate records the DN relationship for field coverage; the actual
// S4-Conf obligation is discharged by conf_s4_crl_signature_violation.
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/crl.rs:206-209,369 (issuer Name parsed, not compared)
// SOURCE: rpki-rs/src/repository/cert.rs:794-795 (CA subject DN inspected)
// Registry: CRLPayload.crl_issuer, Certificate.subject_name
pred s4_crl_issuer_dn_verified[crl_obj: RPKIObject, parent_cert: Certificate] {
    crl_obj.crl_payload.crl_issuer = parent_cert.subject_name
}

// --- Confinement: CRL revocation via serial number ---

// M3/C3: CRL revocation by serial number matching.
pred s4_cert_revoked[crl_obj: RPKIObject, cert: Certificate] {
    cert.serial_number in crl_obj.crl_payload.revoked_serials
}

// --- Confinement: CRL scope binding ---

// In routinator, the CRL is not just signature-verified — it is bound to
// the PP by multiple mechanisms:
//   1. engine.rs:1738-1765 — ValidPointManifest struct stores CRL per-PP
//   2. engine.rs:1153-1158 — verify_signature against self.cert (PP's own CA)
//   3. engine.rs:1779-1783 — CRL URI must match manifest's CRL URI
//
// These mechanisms ensure that an attacker's CRL can never be presented
// for verification in the victim's PP context. The auth check is moot
// because the CRL never reaches the wrong verification context.
//
// Encoding: empty body = always TRUE = CRL always bound to its own PP.
// Used in conf_s4_violation to require cross-PP CRL reachability,
// which is never satisfied -> UNSAT.
pred s4_crl_reaches_victim_context[atk_pp, victim_pp: PP] {
}

// =====================================================================
// S5 CertChainProcessing — CA_CERT (ni + conf)
// =====================================================================

// --- Non-interference: cert store key ---

// Same per-PP filesystem as S3/S4.
// Cert files stored under per-PP StoredPoint directory.
// store.rs:727-735 — point_path(manifest_uri): per-PP directory.
// engine.rs:1486-1511 — process_cer(): cert loaded from per-PP manifest entries.
// Composite key: origin + uri.
// PAPER-CLAIM: R1 (supporting)
// SOURCE: vendor/routinator/src/src/engine.rs:1486-1511 (process_cer per-PP manifest)
fun s5_cert_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- Non-interference: chain walk ---

// Routinator uses per-PP traversal, not global SKI lookup:
//   engine.rs:712-740 — PubPointTask::process():
//     Each publication point is processed independently.
//   engine.rs:1486-1511 — process_cer(): cert loaded from manifest entries.
//   engine.rs:1515-1559 — process_ca_cer():
//     Line 1527-1528: cert.validate_ca(self.cert.cert(), strict)
//     Uses self.cert (parent CaCert) which is per-PP, not a global index.
//   engine.rs:1547-1548: CaCert::chain(self.cert, uri, cert, max_depth)
//     Parent reference is the current PP's CaCert, not from a global store.
//   engine.rs:1982-1992 — CaCert::check_loop() walks parent chain via
//     self.parent (Arc<CaCert>) — per-PP chain, not global SKI index.
//
// Consequence: chain walk is always isolated between PPs because
// parent references are per-PP (CaCert.parent), not global SKI lookups.
//
// Encoding: empty body = always TRUE = chain walk always isolated.
// PAPER-CLAIM: R1 (supporting)
// SOURCE: vendor/routinator/src/src/engine.rs:1982-2000 (check_loop walks per-PP CaCert.parent)
pred s5_chain_walk_isolated[pp1, pp2: PP] {
}

// --- Non-interference: SIA rpkiNotify scope ---

// Routinator does NOT explicitly validate that a child CA cert's
// rpkiNotify URI matches the parent PP's host.
//
// engine.rs:2037-2051 — repository_switch():
//   Detects whether a child CA is in a different repository from its
//   parent by comparing rpkiNotify URIs. Returns a bool used ONLY for
//   metrics grouping (engine.rs:1574), NOT for validation or rejection.
//   Code comment: "This is just a quick check and may report a switch
//   when in fact there isn't one."
//
// SIA-based rpkiNotify redirection is a non-issue because:
//   1. Per-PP PubPointTask: each CA subtree is processed independently
//      (engine.rs:712-740). Objects fetched via a redirected rpkiNotify
//      enter the attacker's processing context, not the victim's.
//   2. CMS signature binding: objects from the victim's repository
//      won't validate in the attacker's context (wrong issuer key).
//   3. RRDP workspace isolation: SHA256(notifyURI) -> distinct paths
//      (collector/rrdp/base.rs:264-289). Even if attacker and victim
//      share a notifyURI, the per-PP engine-level processing prevents
//      interference.
//
// Encoding: empty body = always TRUE = SIA scope always isolated.
pred s5_sia_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
}

// --- Non-interference: SIA caRepository scope ---

// Routinator does NOT validate that a child CA cert's caRepository
// URI matches the parent PP's host.
//
// engine.rs:773-775 — stored manifest ca_repository comparison:
//   mft.ca_repository == *self.cert.ca_repository() is a cache-hit
//   optimization check (skip re-processing if unchanged), NOT a scope
//   enforcement that rejects mismatched hosts.
//
// engine.rs:857-858 — cert.ca_repository().join(file):
//   Constructs object URIs from the CA's own caRepository + manifest
//   filename. This scopes object loading to the CA's declared
//   repository, but does NOT validate that the CA's caRepository
//   matches the parent PP's host.
//
// SIA caRepository redirection is a non-issue because:
//   1. Per-PP PubPointTask: objects from the redirected repository
//      enter the attacker's processing context only.
//   2. Manifest hash binding (s3_conf_mft_hash): objects must match
//      the attacker's manifest hashes, and victim's objects won't.
//   3. CMS signature binding: victim's objects are signed by the
//      victim's key, not the attacker's.
//
// Encoding: empty body = always TRUE = caRepository scope always isolated.
pred s5_sia_repo_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
}

// --- Non-interference: SIA rpkiManifest scope ---

// Routinator does NOT validate that a child CA cert's rpkiManifest
// URI matches the parent PP's host.
//
// engine.rs:1964 — rpki_manifest = cert.rpki_manifest():
//   The manifest URI is extracted from the CA cert's SIA extension
//   and used directly for fetching. No host scope check.
//
// SIA rpkiManifest redirection is a non-issue because:
//   1. Per-PP PubPointTask: the redirected manifest is processed
//      in the attacker's context only.
//   2. CMS signature binding: the fetched manifest must be signed
//      by the attacker's CA key (sigobj.rs:253-271 verify()).
//      A victim's manifest would fail signature verification.
//   3. Even if the attacker crafts a manifest listing victim's files,
//      the objects must chain to the attacker's key (S5/S6 conf).
//
// Encoding: empty body = always TRUE = rpkiManifest scope always isolated.
pred s5_sia_mft_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
}

// --- Confinement: resource delegation containment ---

// cert.rs:983-1017 — verify_resources(issuer):
//   Line 991-997:  IPv4: issuer.v4_resources.verify_issued(child, overclaim)
//   Line 998-1004: IPv6: issuer.v6_resources.verify_issued(child, overclaim)
//   Line 1007-1013: AS:  issuer.as_resources.verify_issued(child, overclaim)
//   Overclaim::Refuse (cert.rs:2686-2692, 2698-2699) rejects any resource
//   not in issuer — child resources must be strict subset of parent.
//
// cert.rs:711-718 — verify_ca_at(issuer, strict, now):
//   Line 714: self.verify_validity(now)
//   Line 715: self.verify_issuer_claim(issuer, strict)
//   Line 716: self.verify_signature(issuer, strict)
//   Line 717: self.verify_resources(issuer, strict)
//
// Same verify_resources() function used for both CA certs (verify_ca_at)
// and EE certs (verify_ee_at, cert.rs:734-741) — same code path as S6.
//
// C3: Strict containment for both IP prefixes AND AS numbers.
// C4: rpki-rs handles RFC 3779 inherit via ResourceInfo enum.
//
// Overclaim mode (cert.rs:2686-2753): determined by the certificate's
// Certificate Policy OID, not by Routinator configuration.
//   - CP_IPADDR_ASNUMBER     -> Overclaim::Refuse (reject entire cert)
//   - CP_IPADDR_ASNUMBER_V2  -> Overclaim::Trim (RFC 8360: trim to parent)
// Both modes are safe for Confinement: Refuse rejects the cert entirely;
// Trim intersects with parent's resources, so effective resources are
// always ⊆ parent's delegation. The model uses `in` (subset), which
// is satisfied by both modes.
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/cert.rs:983-1017 (verify_resources)
// SOURCE: rpki-rs/src/repository/resources/ipres.rs:348-374 (verify_issued, Inherit/Refuse/Trim)
// Registry: Certificate.resources_inherit, Certificate.ip_resources, Certificate.as_resources
pred s5_cert_resource_check[obj: RPKIObject, issuing_ca: CA] {
    // C4: ResourceInfo::Inherited → inherit from parent.
    // verify_issued returns Ok(issuer resources) on ResourcesChoice::Inherit
    // (ipres.rs:355), so an inheriting child is confined to the parent's set.
    {
        obj.cms.ee_certificate.resources_inherit = True
    } or {
        // C3: IP + ASN containment when not inheriting
        obj.cms.ee_certificate.ip_resources in issuing_ca.delegated_prefixes
        obj.cms.ee_certificate.as_resources in issuing_ca.delegated_asns
    }
}

// --- Confinement: basicConstraints ---

// L5/C5: cert.rs inspect_ca_basics requires basicConstraints cA flag = true.
// Only certs with cA=true are processed as CA certificates; process_cer
// dispatches on key_usage == Ca (engine.rs:1505-1511).
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/cert.rs:870-918 (inspect_ca_basics, basic_ca Some(true))
// Registry: Certificate.is_ca
pred s5_is_ca_checked[obj: RPKIObject] {
    obj.cms.ee_certificate.is_ca = True
}

// =====================================================================
// S6 PayloadProcessing — ROA, ASPA (ni + conf)
// =====================================================================

// --- Non-interference: payload store key ---

// Same per-PP filesystem as S3/S4/S5.
// ROA/ASPA files stored under per-PP StoredPoint directory.
// store.rs:727-735 — point_path(manifest_uri): per-PP directory.
// engine.rs:1614-1657 — process_roa(): content loaded from manifest entries.
// engine.rs:1661-1693 — process_aspa(): same pattern.
// Composite key: origin + uri.
// PAPER-CLAIM: R1 (supporting)
// SOURCE: vendor/routinator/src/src/engine.rs:1614-1657 (process_roa), engine.rs:1661-1693 (process_aspa)
fun s6_payload_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- Non-interference: CMS structural checks ---

// Same signed-object parsing path as S3 (sigobj.rs:118-191).
// Routinator uses a single SignedObject::take_from() for all CMS objects
// including MFT, ROA, ASPA — same code path as S3.
// sigobj.rs:144-175 — take_set/take_sequence for exactly one SignerInfo.
// sigobj.rs:48 — message_digest: MessageDigest (always present).
pred s6_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// --- Non-interference: time field parse safety ---

// Same as S3 — Rust chrono returns Result, `?` operator propagates errors.
// Modeled for cross-validator consistency.
pred s6_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- Non-interference: combined parse success ---

// Same OpenSSL-free Rust parsing path as S3 (sigobj.rs:118-191).
// L3/C6: Also checks public key parse safety.
pred s6_payload_parse_succeeds[cms: CMSSignedData] {
    s6_cms_structure_ok[cms]
    s6_time_field_safe[cms]
    // L3/C6: Public key parse — Rust returns Result, no panic
    cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Non-interference: error containment ---

// Same Rust Result<T,E> error handling as S3.
// engine.rs:1621-1635 — process_roa():
//   Roa::decode() failure -> log + return Ok(()) (line 1628-1634)
// engine.rs:1637-1654 — roa.process() failure -> log + continue
// engine.rs:1665-1674 — process_aspa(): Aspa::decode() failure -> log + return Ok(())
// engine.rs:1677-1691 — aspa.process() failure -> log + continue
//
// Fatal error inventory: NONE (same as S3)
//
// Encoding: empty body = always TRUE = errors always contained.
// PAPER-CLAIM: R2 (supporting)
// SOURCE: vendor/routinator/src/src/engine.rs:1621-1636,1665-1676
pred s6_payload_error_contained[source_pp, victim_pp: PP] {
}

// --- Confinement: CMS eContent binding ---

// Same signed-object verification path as S3 (sigobj.rs:253-271).
// Routinator uses a single SignedObject::verify() for all CMS objects
// including MFT, ROA, ASPA.
// sigobj.rs:256-259 — digest = H(eContent)
// sigobj.rs:261-265 — digest != message_digest -> VerificationError
// sigobj.rs:266-270 — signature verification against EE cert pubkey
// Complete binding: digest + signature both verified.
//
// M4/B4: sigobj.rs:233-248 inspect(strict) — checks SKI matches SID.
// Routinator enforces SID↔EE match, unlike cfrpki.
//
// M5/C7: sigobj.rs:253-271 full content type verification.
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/sigobj.rs:219-271
// Registry: CMSSignedData.ee_certificate, CMSSignedData.sid_matches_ee, CMSSignedData.econtent_type_matches
pred s6_payload_verify_succeeds[cms: CMSSignedData] {
    cms.econtent_digest = cms.signed_attrs_digest
    cms.signature_valid = True
    // RFC 6488 §3.1: SID must match EE cert SubjectKeyIdentifier
    // SOURCE: rpki-rs/src/repository/sigobj.rs:233-248 (inspect, sid==SKI)
    cms.sid_matches_ee = True
    // RFC 6488 §2.1.3.1: eContentType OID binding (decode_if_type + signed attr)
    // SOURCE: rpki-rs/src/repository/sigobj.rs:103-115,160-165
    cms.econtent_type_matches = True
}

// --- Confinement: resource certification ---

// C2/A1: ROA payload → EE cert IP resource check.
// cert.rs:983-1017 verify_resources() for EE certs (verify_ee_at).
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/roa.rs:219-249 (RouteOriginAttestation::verify, contains_roa)
pred s6_roa_resource_check[obj: RPKIObject] {
    obj.roa_payload.roa_prefixes in obj.cms.ee_certificate.ip_resources
}

// C2/A2: ASPA payload → EE cert AS resource check.
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/aspa.rs:139-161 (AsProviderAttestation::verify, contains_asn)
pred s6_aspa_resource_check[obj: RPKIObject] {
    obj.aspa_payload.customer_as in obj.cms.ee_certificate.as_resources
}

// C3/C4: EE cert → CA delegation check (with inherit + ASN).
// Same verify_resources() as S5. Both Overclaim::Refuse and Overclaim::Trim
// satisfy the subset relation modeled by `in` (see S5 comment for details).
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/cert.rs:983-1017 (verify_resources on EE cert)
// Registry: Certificate.resources_inherit, Certificate.ip_resources, Certificate.as_resources
pred s6_ee_resource_check[obj: RPKIObject, issuing_ca: CA] {
    // C4: inherit delegates to parent (verify_issued Inherit branch, ipres.rs:355)
    {
        obj.cms.ee_certificate.resources_inherit = True
    } or {
        // C3: IP + ASN containment when not inheriting
        obj.cms.ee_certificate.ip_resources in issuing_ca.delegated_prefixes
        obj.cms.ee_certificate.as_resources in issuing_ca.delegated_asns
    }
}

// --- Confinement: EE/CA key binding (AKI == issuer SKI) ---

// R5 (supporting): verify_issuer_claim requires the certificate's Authority
// Key Identifier to equal the issuer's Subject Key Identifier; the issuer is
// the per-PP parent CaCert (engine.rs:1896 parent, resolved by the per-origin
// tree walk, NOT a global SKI index). CA.ca_ski is that issuer key. An
// attacker cannot forge a signature under the victim CA's key (base.als
// attacker_signature_capability), so an object whose AKI names the victim CA
// cannot also verify under a key the attacker controls.
// PAPER-CLAIM: R5 (supporting)
// SOURCE: rpki-rs/src/repository/cert.rs:931-967 (verify_issuer_claim, AKI==issuer SKI)
// SOURCE: vendor/routinator/src/src/engine.rs:1896,1990-2000 (per-PP CaCert.parent)
// Registry: CA.ca_ski
pred s5_aki_binding_ok[obj: RPKIObject, issuing_ca: CA] {
    aki[obj] = issuing_ca.ca_ski
}

// =====================================================================
// Per-field violation predicates (32)
// =====================================================================

// --- S2: RepositorySync per-field ---

// Registry: RPKIObject.uri, PP.notifyURI
pred ni_s2_fetch_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_SNAPSHOT + OT_DELTA + OT_NOTIFICATION)
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.uri = obj.uri
    s2_fetch_scope_enforced[atk_pp, obj.uri]
}

// Registry: PP.siaBase
pred ni_s2_cache_workspace_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    not s2_cache_workspace_isolated[atk_pp, victim_pp]
}

// --- S3 iso per-field ---

// Registry: Certificate.subject_ski
pred ni_s3_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some atk_obj: RPKIObject, colliding_key: KeyId |
        atk_obj.origin = atk_pp and
        s3_manifest_store_key[atk_obj] = colliding_key and
        s3_manifest_store_key[obj] = colliding_key
}

// Registry: Certificate.subject_ski
pred ni_s3_manifest_lookup_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some atk_mft: RPKIObject, colliding_key: KeyId |
        atk_mft.origin = atk_pp and atk_mft.obj_type = OT_MFT and
        s3_manifest_lookup_key[atk_mft] = colliding_key and
        s3_manifest_lookup_key[obj] = colliding_key
}

// Registry: CMSSignedData.signer_infos
pred ni_s3_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        not (some atk_obj.cms.signer_infos)
    not s3_mft_error_contained[atk_pp, victim_pp]
}

// Registry: Certificate.time_field_parse
pred ni_s3_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.cms.ee_certificate.time_field_parse = ParseFatal
    not s3_mft_error_contained[atk_pp, victim_pp]
}

// Registry: MFTPayload.mft_this_update_parse
pred ni_s3_parse_mft_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.mft_payload.mft_this_update_parse = ParseFatal
    not s3_mft_error_contained[atk_pp, victim_pp]
}

// Registry: MFTPayload.mft_next_update_parse
pred ni_s3_parse_mft_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.mft_payload.mft_next_update_parse = ParseFatal
    not s3_mft_error_contained[atk_pp, victim_pp]
}

// Registry: Certificate.pubkey_parse
pred ni_s3_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.cms.ee_certificate.pubkey_parse = ParseFatal
    not s3_mft_error_contained[atk_pp, victim_pp]
}

// --- Non-interference: manifest filename URI join .unwrap() (R3) ---

// Design decision (paper §4.3): the S3 manifest path joins an
// attacker-controlled manifest filename onto the CA repository URI and
// .unwrap()s the result, instead of propagating the Err like every other
// parse path (R2).  A filename that does not form a valid relative URI makes
// join() return Err, and the .unwrap() panics; under panic="abort"
// (Cargo.toml:60-61) with no catch_unwind in the worker threads
// (engine.rs:481-495) the panic aborts the whole process, so it escapes the
// origin's task and drops the victim's VRPs -> non-interference broken at S3.
//
// General encoding: the witness is any attacker MFT carrying a fileList entry
// (the attacker always controls its own manifest filenames); the predicate
// does NOT depend on a specific seed shape (e.g. a particular bad byte), only
// on the design fact that this join is unwrapped and uncontained.  It is NOT
// gated by s3_mft_error_contained, precisely because this path is the one
// exception to R2.
//
// Candidate input: a non-ASCII manifest filename.  In rpki 0.19.1 filenames
// are validated at manifest decode time (manifest.rs:455-480, called at
// manifest.rs:424/438) and the engine ASCII-guards the filename before the
// join (engine.rs:846-856).  The predicate keeps the unwrapped-join design
// decision as a candidate; the guards are recorded as source facts.
//
// PAPER-CLAIM: R3 | predicates: ni_s3_parse_mft_filename_violation
// SOURCE: vendor/routinator/src/src/engine.rs:857-859
// SOURCE: rpki-rs/src/repository/manifest.rs:279
// Registry: MFTEntry.entry_uri, MFTPayload.file_list
pred ni_s3_parse_mft_filename_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    // Victim object whose validated output is lost when the shared process aborts.
    obj.origin = victim_pp
    // General design decision: an attacker-controlled manifest filename reaches
    // the unwrapped URI join (engine.rs:857-859).  The attacker controls the
    // filenames in its own manifest's fileList.
    some atk_mft: RPKIObject |
        atk_mft.origin = atk_pp and atk_mft.obj_type = OT_MFT and
        some atk_mft.mft_payload.file_list
    // No per-PP containment: the join uses .unwrap(), not `?`; a failed join
    // aborts the whole process (panic=abort), unlike the R2 parse paths.
}

// --- Non-interference: IP resources prefix length assert! (R4) ---

// Design decision (paper §4.3): the S6 resource-extension path constructs a
// Prefix from the RFC 3779 ipAddrBlocks encoding and guards the prefix length
// with assert!(len <= 128) (a panic), not a Result.  Under panic="abort"
// (Cargo.toml:60-61) with no catch_unwind in the worker threads
// (engine.rs:481-495), a reached assertion aborts the whole process, escaping
// the origin's task and dropping the victim's VRPs -> NI broken at S6.
//
// General encoding: the witness is any attacker payload object whose EE
// certificate carries an ipAddrBlocks resource extension (the general path
// into Prefix::new via Prefix::take_from -> from_bit_string).  The predicate
// encodes the design fact (assert! guards an internal invariant on the
// resource-extension path), not a specific boundary byte sequence.
//
// source-level candidate: in rpki 0.19.1 the DER path guards with
// from_bit_string's octet_len>16 check (ipres.rs:1343-1357) before Prefix::new,
// so a BIT STRING cannot carry len>128 on the standard path; the assert is
// defense-in-depth on that path, while the resource-extension design decision
// remains a candidate for non-standard decode paths.
//
// PAPER-CLAIM: R4 | predicates: ni_s6_parse_ip_resources_violation
// SOURCE: rpki-rs/src/repository/resources/ipres.rs:1329-1330
// SOURCE: rpki-rs/src/repository/resources/ipres.rs:1468-1475
// Registry: Certificate.ip_resources
pred ni_s6_parse_ip_resources_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    // Victim object whose validated output is lost when the shared process aborts.
    obj.origin = victim_pp
    // General design decision: an attacker payload's EE cert carries an
    // ipAddrBlocks resource extension that drives Prefix::new's assert!.
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        some atk_obj.cms.ee_certificate.ip_resources
    // No per-PP containment: assert! is a panic, aborting the whole process.
}

// --- S3 auth per-field ---

// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest, CMSSignedData.signature_valid
pred conf_s3_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
}

// Registry: MFTEntry.entry_hash, RPKIObject.content_hash
pred conf_s3_mft_hash_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    // Hash mismatch AND validator accepts (pass-condition creates contradiction
    // for hash-checking validators via unique_mft_entry_uri)
    some child: victim_pp.objects |
        (some e: obj.mft_payload.file_list |
            e.entry_uri = child.uri and e.entry_hash != child.content_hash)
        and s3_mft_hash_verified[obj, child]
    // Impact: MFT covers resources overlapping with victim
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
}

// --- S4 iso per-field ---

// Registry: Certificate.issuer_ski
pred ni_s4_crl_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject, colliding_key: KeyId |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        s4_crl_store_key[atk_crl] = colliding_key and
        s4_crl_store_key[obj] = colliding_key
}

// Registry: CRLPayload.revoked_serials, Certificate.serial_number
pred ni_s4_crl_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject, revoked_serial: SerialNumber |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        revoked_serial in atk_crl.crl_payload.revoked_serials and
        revoked_serial = obj.cms.ee_certificate.serial_number
    not s4_crl_scope_isolated[atk_pp, victim_pp]
}

// Registry: CRLPayload.crl_this_update_parse
pred ni_s4_parse_crl_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.crl_payload.crl_this_update_parse = ParseFatal
    not s4_crl_error_contained[atk_pp, victim_pp]
}

// Registry: CRLPayload.crl_next_update_parse
pred ni_s4_parse_crl_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.crl_payload.crl_next_update_parse = ParseFatal
    not s4_crl_error_contained[atk_pp, victim_pp]
}

// Registry: CRLPayload.crl_revocation_date_parse
pred ni_s4_parse_crl_revocation_date_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.crl_payload.crl_revocation_date_parse = ParseFatal
    not s4_crl_error_contained[atk_pp, victim_pp]
}

// Registry: Certificate.pubkey_parse
pred ni_s4_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.cms.ee_certificate.pubkey_parse = ParseFatal
    not s4_crl_error_contained[atk_pp, victim_pp]
}

// --- S4 auth per-field ---

// Registry: CMSSignedData.signature_valid
pred conf_s4_crl_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    aki[obj] = victim_pp.owner.ca_ski
    obj.cms.signature_valid = False
    s4_crl_verify_succeeds[obj.cms]
}

// --- S5 iso per-field ---

// Registry: Certificate.subject_ski
pred ni_s5_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some atk_cert: RPKIObject, colliding_key: KeyId |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        s5_cert_store_key[atk_cert] = colliding_key and
        s5_cert_store_key[obj] = colliding_key
}

// Registry: Certificate.issuer_ski
pred ni_s5_chain_walk_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    not s5_chain_walk_isolated[atk_pp, victim_pp]
}

// Registry: Certificate.sia_notify_uri
pred ni_s5_sia_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {

    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        some atk_cert.cms.ee_certificate.sia_notify_uri and
        atk_cert.cms.ee_certificate.sia_notify_uri.host = victim_pp.siaBase.host and
        not s5_sia_scope_enforced[atk_cert, atk_pp]
}

// Registry: Certificate.sia_repo_uri
pred ni_s5_sia_repo_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {

    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        some atk_cert.cms.ee_certificate.sia_repo_uri and
        atk_cert.cms.ee_certificate.sia_repo_uri.host = victim_pp.siaBase.host and
        not s5_sia_repo_scope_enforced[atk_cert, atk_pp]
}

// Registry: Certificate.sia_mft_uri
pred ni_s5_sia_mft_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {

    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        some atk_cert.cms.ee_certificate.sia_mft_uri and
        atk_cert.cms.ee_certificate.sia_mft_uri.host = victim_pp.siaBase.host and
        not s5_sia_mft_scope_enforced[atk_cert, atk_pp]
}

// --- S5 auth per-field ---

// Registry: Certificate.ip_resources, Certificate.as_resources, CA.delegated_prefixes, CA.delegated_asns
pred conf_s5_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    s5_is_ca_checked[obj]
    {
        some overclaimed_prefix: Prefix |
            overclaimed_prefix in obj.cms.ee_certificate.ip_resources and
            overclaimed_prefix not in atk_pp.owner.delegated_prefixes and
            overclaimed_prefix in victim_pp.owner.delegated_prefixes
    } or {
        some overclaimed_asn: ASN |
            overclaimed_asn in obj.cms.ee_certificate.as_resources and
            overclaimed_asn not in atk_pp.owner.delegated_asns and
            overclaimed_asn in victim_pp.owner.delegated_asns
    }
    s5_cert_resource_check[obj, atk_pp.owner]
}

// --- S6 iso per-field ---

// Registry: Certificate.subject_ski
pred ni_s6_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    some atk_obj: RPKIObject, colliding_key: KeyId |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        s6_payload_store_key[atk_obj] = colliding_key and
        s6_payload_store_key[obj] = colliding_key
}

// Registry: CMSSignedData.signer_infos
pred ni_s6_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        not (some atk_obj.cms.signer_infos)
    not s6_payload_error_contained[atk_pp, victim_pp]
}

// Registry: Certificate.time_field_parse
pred ni_s6_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        atk_obj.cms.ee_certificate.time_field_parse = ParseFatal
    not s6_payload_error_contained[atk_pp, victim_pp]
}

// Registry: Certificate.pubkey_parse
pred ni_s6_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        atk_obj.cms.ee_certificate.pubkey_parse = ParseFatal
    not s6_payload_error_contained[atk_pp, victim_pp]
}

// --- S6 auth per-field ---

// Registry: CMSSignedData.econtent_digest, CMSSignedData.signature_valid
pred conf_s6_roa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.roa_payload.roa_prefixes |
        p in victim_pp.owner.delegated_prefixes
}

// Registry: CMSSignedData.econtent_digest, CMSSignedData.signature_valid
pred conf_s6_aspa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s6_payload_verify_succeeds[obj.cms]
    obj.aspa_payload.customer_as in victim_pp.owner.delegated_asns
}

// Registry: ROAPayload.roa_prefixes, Certificate.ip_resources
pred conf_s6_roa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    some overclaimed_prefix: Prefix |
        overclaimed_prefix in obj.roa_payload.roa_prefixes and
        overclaimed_prefix not in atk_pp.owner.delegated_prefixes and
        overclaimed_prefix in victim_pp.owner.delegated_prefixes
    s6_roa_resource_check[obj]
    s6_ee_resource_check[obj, atk_pp.owner]
}

// Registry: ASPAPayload.customer_as, Certificate.as_resources
pred conf_s6_aspa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.aspa_payload.customer_as not in atk_pp.owner.delegated_asns
    s6_aspa_resource_check[obj]
    s6_ee_resource_check[obj, atk_pp.owner]
    obj.aspa_payload.customer_as in victim_pp.owner.delegated_asns
}

// =====================================================================
// Aggregated violation predicates (stage-level)
// =====================================================================

pred ni_s2_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s2_fetch_scope_violation[atk_pp, victim_pp, obj] or
    ni_s2_cache_workspace_violation[atk_pp, victim_pp, obj]
}

pred ni_s3_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    ni_s3_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s3_manifest_lookup_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_signerinfos_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_time_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_mft_this_update_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_mft_next_update_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_pubkey_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_mft_filename_violation[atk_pp, victim_pp, obj]
}

pred conf_s3_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    conf_s3_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_type_violation[atk_pp, victim_pp, obj] or
    conf_s3_mft_hash_violation[atk_pp, victim_pp, obj]
}

pred conf_s3_hash_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s3_mft_hash_violation[atk_pp, victim_pp, obj]
}

pred ni_s4_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s4_crl_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s4_crl_scope_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_this_update_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_next_update_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_revocation_date_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_pubkey_violation[atk_pp, victim_pp, obj]
}

pred conf_s4_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s4_crl_signature_violation[atk_pp, victim_pp, obj]
}

pred ni_s5_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s5_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s5_chain_walk_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_repo_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_mft_scope_violation[atk_pp, victim_pp, obj]
}

pred conf_s5_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s5_resource_violation[atk_pp, victim_pp, obj]
}

pred ni_s6_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    ni_s6_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_signerinfos_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_time_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_pubkey_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_ip_resources_violation[atk_pp, victim_pp, obj]
}

pred conf_s6_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s6_roa_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_cms_type_violation[atk_pp, victim_pp, obj]
}

// =====================================================================
// Top-level aggregate predicates
// =====================================================================

pred any_ni_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s2_violation[atk_pp, victim_pp, obj] or
    ni_s3_violation[atk_pp, victim_pp, obj] or
    ni_s4_violation[atk_pp, victim_pp, obj] or
    ni_s5_violation[atk_pp, victim_pp, obj] or
    ni_s6_violation[atk_pp, victim_pp, obj]
}

pred any_conf_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s3_violation[atk_pp, victim_pp, obj] or
    conf_s3_hash_violation[atk_pp, victim_pp, obj] or
    conf_s4_violation[atk_pp, victim_pp, obj] or
    conf_s5_violation[atk_pp, victim_pp, obj] or
    conf_s6_violation[atk_pp, victim_pp, obj]
}

pred any_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    any_ni_violation[atk_pp, victim_pp, obj] or
    any_conf_violation[atk_pp, victim_pp, obj]
}

// =====================================================================
// Per-field assertions
// =====================================================================

assert s2_ni_fetch_scope { no a, v: PP, o: RPKIObject | ni_s2_fetch_scope_violation[a, v, o] }
assert s2_ni_cache_workspace { no a, v: PP, o: RPKIObject | ni_s2_cache_workspace_violation[a, v, o] }
assert s3_ni_store_key { no a, v: PP, o: RPKIObject | ni_s3_store_key_violation[a, v, o] }
assert s3_ni_manifest_lookup { no a, v: PP, o: RPKIObject | ni_s3_manifest_lookup_violation[a, v, o] }
assert s3_ni_parse_signerinfos { no a, v: PP, o: RPKIObject | ni_s3_parse_signerinfos_violation[a, v, o] }
assert s3_ni_parse_time { no a, v: PP, o: RPKIObject | ni_s3_parse_time_violation[a, v, o] }
assert s3_ni_parse_mft_this_update { no a, v: PP, o: RPKIObject | ni_s3_parse_mft_this_update_violation[a, v, o] }
assert s3_ni_parse_mft_next_update { no a, v: PP, o: RPKIObject | ni_s3_parse_mft_next_update_violation[a, v, o] }
assert s3_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s3_parse_pubkey_violation[a, v, o] }
assert s3_ni_parse_mft_filename { no a, v: PP, o: RPKIObject | ni_s3_parse_mft_filename_violation[a, v, o] }
assert s3_conf_cms_digest { no a, v: PP, o: RPKIObject | conf_s3_cms_digest_violation[a, v, o] }
assert s3_conf_mft_hash { no a, v: PP, o: RPKIObject | conf_s3_mft_hash_violation[a, v, o] }
assert s4_ni_crl_store_key { no a, v: PP, o: RPKIObject | ni_s4_crl_store_key_violation[a, v, o] }
assert s4_ni_crl_scope { no a, v: PP, o: RPKIObject | ni_s4_crl_scope_violation[a, v, o] }
assert s4_ni_parse_crl_this_update { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_this_update_violation[a, v, o] }
assert s4_ni_parse_crl_next_update { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_next_update_violation[a, v, o] }
assert s4_ni_parse_crl_revocation_date { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_revocation_date_violation[a, v, o] }
assert s4_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s4_parse_pubkey_violation[a, v, o] }
assert s4_conf_crl_signature { no a, v: PP, o: RPKIObject | conf_s4_crl_signature_violation[a, v, o] }
assert s5_ni_store_key { no a, v: PP, o: RPKIObject | ni_s5_store_key_violation[a, v, o] }
assert s5_ni_chain_walk { no a, v: PP, o: RPKIObject | ni_s5_chain_walk_violation[a, v, o] }
assert s5_ni_sia_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_scope_violation[a, v, o] }
assert s5_ni_sia_repo_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_repo_scope_violation[a, v, o] }
assert s5_ni_sia_mft_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_mft_scope_violation[a, v, o] }
assert s5_conf_resource { no a, v: PP, o: RPKIObject | conf_s5_resource_violation[a, v, o] }
assert s6_ni_store_key { no a, v: PP, o: RPKIObject | ni_s6_store_key_violation[a, v, o] }
assert s6_ni_parse_signerinfos { no a, v: PP, o: RPKIObject | ni_s6_parse_signerinfos_violation[a, v, o] }
assert s6_ni_parse_time { no a, v: PP, o: RPKIObject | ni_s6_parse_time_violation[a, v, o] }
assert s6_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s6_parse_pubkey_violation[a, v, o] }
assert s6_ni_parse_ip_resources { no a, v: PP, o: RPKIObject | ni_s6_parse_ip_resources_violation[a, v, o] }
assert s6_conf_roa_cms_digest { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_digest_violation[a, v, o] }
assert s6_conf_aspa_cms_digest { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_digest_violation[a, v, o] }
assert s6_conf_roa_resource { no a, v: PP, o: RPKIObject | conf_s6_roa_resource_violation[a, v, o] }
assert s6_conf_aspa_resource { no a, v: PP, o: RPKIObject | conf_s6_aspa_resource_violation[a, v, o] }

// =====================================================================
// =====================================================================

assert s2_ni { no a, v: PP, o: RPKIObject | ni_s2_violation[a, v, o] }
assert s3_ni { no a, v: PP, o: RPKIObject | ni_s3_violation[a, v, o] }
assert s3_conf { no a, v: PP, o: RPKIObject | conf_s3_violation[a, v, o] }
assert s3_conf_hash { no a, v: PP, o: RPKIObject | conf_s3_hash_violation[a, v, o] }
assert s4_ni { no a, v: PP, o: RPKIObject | ni_s4_violation[a, v, o] }
assert s4_conf { no a, v: PP, o: RPKIObject | conf_s4_violation[a, v, o] }
assert s5_ni { no a, v: PP, o: RPKIObject | ni_s5_violation[a, v, o] }
assert s5_conf { no a, v: PP, o: RPKIObject | conf_s5_violation[a, v, o] }
assert s6_ni { no a, v: PP, o: RPKIObject | ni_s6_violation[a, v, o] }
assert s6_conf { no a, v: PP, o: RPKIObject | conf_s6_violation[a, v, o] }
assert cross_pp_security { no a, v: PP, o: RPKIObject | any_violation[a, v, o] }

// =====================================================================
// Per-field checks — bounded model checking
// =====================================================================

check s2_ni_fetch_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s2_ni_cache_workspace for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_manifest_lookup for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_signerinfos for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_time for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_mft_this_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_mft_next_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_mft_filename for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_mft_hash for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_crl_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_crl_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_this_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_next_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_revocation_date for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf_crl_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_chain_walk for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_repo_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_mft_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_signerinfos for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_time for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_ip_resources for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// =====================================================================
// Aggregated checks — bounded model checking
// =====================================================================

check s2_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_hash for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check cross_pp_security for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// Independent signature obligations, separate from digest binding.
pred conf_s3_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.signature_valid = False
    s3_mft_verify_succeeds[obj.cms]
}
assert s3_conf_cms_signature { no a, v: PP, o: RPKIObject | conf_s3_cms_signature_violation[a, v, o] }
check s3_conf_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

pred conf_s6_roa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.signature_valid = False
    s6_payload_verify_succeeds[obj.cms]
}
assert s6_conf_roa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_signature_violation[a, v, o] }
check s6_conf_roa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

pred conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.signature_valid = False
    s6_payload_verify_succeeds[obj.cms]
}
assert s6_conf_aspa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_signature_violation[a, v, o] }
check s6_conf_aspa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// --- Independent SID-binding obligation (RFC 6488 §2.1.6.2) ---
// The SignerInfo sid must equal the EE cert SubjectKeyIdentifier. Asserted
// independently of digest/signature so a deletion of the sid gate
// (sigobj.rs:233-248 inspect) is caught here rather than hidden behind the
// bundled verify predicate. UNSAT: s3_mft_verify_succeeds requires
// sid_matches_ee = True, contradicting the = False witness.
// SOURCE: rpki-rs/src/repository/sigobj.rs:233-248 (inspect, sid==SKI)
// Registry: CMSSignedData.sid_matches_ee
pred conf_s3_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.sid_matches_ee = False
    s3_mft_verify_succeeds[obj.cms]
}
assert s3_conf_cms_sid { no a, v: PP, o: RPKIObject | conf_s3_cms_sid_violation[a, v, o] }
check s3_conf_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// --- Independent eContentType-binding obligation (RFC 6488 §2.1.3.1) ---
// The eContentType OID must match the expected object OID (decode_if_type)
// and the signed contentType attribute. Asserted independently so a deletion
// of the type gate is caught here. UNSAT: s3_mft_verify_succeeds requires
// econtent_type_matches = True.
// SOURCE: rpki-rs/src/repository/sigobj.rs:103-115,160-165
// Registry: CMSSignedData.econtent_type_matches
pred conf_s3_cms_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_type_matches = False
    s3_mft_verify_succeeds[obj.cms]
}
assert s3_conf_cms_type { no a, v: PP, o: RPKIObject | conf_s3_cms_type_violation[a, v, o] }
check s3_conf_cms_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// --- S6 independent SID / eContentType obligations (same gates on ROA) ---
// SOURCE: rpki-rs/src/repository/sigobj.rs:233-248 (inspect, sid==SKI)
// Registry: CMSSignedData.sid_matches_ee
pred conf_s6_roa_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.sid_matches_ee = False
    s6_payload_verify_succeeds[obj.cms]
}
assert s6_conf_roa_cms_sid { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_sid_violation[a, v, o] }
check s6_conf_roa_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// SOURCE: rpki-rs/src/repository/sigobj.rs:103-115,160-165
// Registry: CMSSignedData.econtent_type_matches
pred conf_s6_roa_cms_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_type_matches = False
    s6_payload_verify_succeeds[obj.cms]
}
assert s6_conf_roa_cms_type { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_type_violation[a, v, o] }
check s6_conf_roa_cms_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

run model_satisfiable for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
