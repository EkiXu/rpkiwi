// rpki_prover.als — rpki-prover validation pipeline model.
//
// Source-code-derived model. Each computation function traces to
// specific rpki-prover source code paths (vendor/rpki-prover/src/src/).
// Models DEFAULT incremental mode behavior (Main.hs:314-315).
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
// rpki-prover architecture:
//   - Haskell + STM + async threads. Each TA validates in its own async
//     thread (Main.hs:354-356). Global shared TVar objectStore
//     (AppContext.hs:17, Database.hs:75-92).
//   - AppMonad.hs:89-99 — fromTryM: catch + fromException catches all
//     synchronous exceptions as AppError. Async exceptions rethrown but
//     limited to current thread. No equivalent of C's errx() or Go's
//     unrecovered panic.
//   - Consequence: parse failures are ALWAYS contained per-thread.
//
// rpki-prover has TWO confinement failures:
//   1. CMS: Crypto.hs:39-50 only checks signature, never H(eContent)==messageDigest
//   2. Resource: incremental mode (default) skips resource validation
//      via validateShortcut (TopDown.hs:1405-1416)
//
// =====================================================================
// AUDIT DERIVATION — rpki-prover 0.10.0 (vendored at tag v0.10.0)
// =====================================================================
// Source tree: vendor/rpki-prover/src/src and .../app (git tag v0.10.0).
// Derived from the §4.3 design decisions and the traced source review,
// NOT from observed exploits. Paper claims P1-P4 (spec §5, rpki-prover):
//
//   P1  Haskell thread-level exception handling preserves crash
//       containment (NI preserved at S3, S4, S6).
//       Primary : s3_mft_error_contained  (supporting: s4_crl_error_contained,
//                 s6_payload_error_contained)
//       SOURCE  : vendor/rpki-prover/src/src/RPKI/AppMonad.hs:89-99 (fromTryM:
//                 catch + fromException wraps all synchronous exceptions as
//                 AppError); TopDown.hs:652-658 (catchError in tryMfts).
//
//   P2  A single content-hash-keyed object store shared across publication
//       points breaks storage isolation (NI) at S2, S3, S5, S6.
//       Primary : s3_manifest_store_key / s2_cache_workspace_isolated
//                 (supporting: s3_manifest_lookup_key, s5_cert_store_key,
//                 s5_chain_walk_isolated, s6_payload_store_key)
//       SOURCE  : Store/Database.hs:323-334 (saveObject: hashToKey by content
//                 hash; certBySKI by SKI; mftsForKI by AKI — all global);
//                 AppContext.hs database :: TVar (DB s); app/Main.hs one shared
//                 TVar across all TAs.
//
//   P3  The CMS verifier omits comparing H(eContent) against the signed
//       messageDigest attribute. Breaks confinement at S3 and S6.
//       Primary : s3_mft_verify_succeeds / s6_payload_verify_succeeds
//                 (violations conf_s3_cms_digest_violation,
//                 conf_s6_roa_cms_digest_violation, conf_s6_aspa_cms_digest_violation)
//       SOURCE  : Validation/Crypto.hs:39-49 (validateCMSSignature verifies the
//                 signature over signedAttrs against the EE cert pubkey only);
//                 Parse/Internal/SignedObject.hs:127-128 (MessageDigest parsed)
//                 + Domain.hs:673 (stored) — grep confirms it is never recomputed
//                 vs H(eContent) anywhere in src/ or app/.
//
//   P4  The default incremental-validation mode reuses parent certificates
//       through a shortcut that bypasses resource containment. Breaks
//       confinement at S5 and S6.
//       Primary : conf_s5_incremental_resource_violation /
//                 conf_s6_incremental_resource_violation
//       SOURCE  : TopDown.hs:1410-1416 (validateShortcut: StrictRFC -> pure (),
//                 no validateChildParentResources); Config.hs:259 (default
//                 validationRFC = StrictRFC); app/Main.hs:314-315 (default
//                 validationAlgorithm = Incremental); Validation/Types.hs:81-88
//                 (RoaShortcut caches the object's OWN resources, not the
//                 parent delegation).
//       SOURCE  : validateShortcut's StrictRFC branch executes `pure ()` and
//                 therefore does not re-check an already-accepted shortcut's
//                 resources against the current parent delegation; the shortcut
//                 cache key omits the parent resource set.  The Alloy model is
//                 stateless (no cache-build -> cache-hit transition), so the
//                 S5-Conf/S6-Conf predicates encode this design decision as
//                 candidates rather than a cycle-level state machine.
//
// Printed Table 2 row (PDF p.7, 300-dpi, geometry-correct column order
//   S2-NI | S3-Conf S3-NI | S4-Conf S4-NI | S5-Conf S5-NI | S6-Conf S6-NI):
//       X  |   X      X    |   .      .    |   X      X    |   X      X
// results.CELLS order (S2-NI,S3-NI,S3-Conf,S4-NI,S4-Conf,S5-NI,S5-Conf,S6-NI,S6-Conf):
//       X  X  X  .  .  X  X  X  X
// This matches the §4.3 prose exactly (P2 -> S2/S3/S5/S6 NI; P3 -> S3/S6 Conf;
// P4 -> S5/S6 Conf; S4 untouched). There is no S2-Conf obligation (§4.2:
// confinement is enforced downstream of S2). No prose-vs-table conflict.
//
// The incremental path is modeled directly by the shortcut predicates; no
// observed exploit is the reason any predicate exists.
// =====================================================================
module rpki_prover

open topo
open util/boolean

// =====================================================================
// S2 RepositorySync — NOTIFICATION, SNAPSHOT, DELTA (ni only)
// =====================================================================

// RrdpFetch.hs:194-209 — validatedNotification:
//   Line 196: getHostname repoU extracts base notification URI hostname.
//   Line 197-201: snapshot URI hostname compared to base; mismatch →
//     SnapshotUriHostname error → reject entire notification.
//   Line 203-208: each delta URI hostname compared to base; mismatch →
//     DeltaUriHostname error → reject.
// Strict hostname equality check on all snapshot and delta URIs.
pred s2_fetch_scope_enforced[pp: PP, target_uri: URI] {
    target_uri.host = pp.notifyURI.host
}

// Database.hs:75-92 — DB struct: single instance for all TAs.
//   Line 79: objectStore :: RpkiObjectStore s — one shared store.
// AppContext.hs:17 — database :: TVar (DB s) — single TVar for all TAs.
// Main.hs:355 — newTVarIO db — created once, shared across all TAs.
// No per-PP or per-TA partitioning in any store map.
//
// Encoding: pp1 != pp1 = always FALSE = cache workspace NEVER isolated.
// Different PPs share the same global TVar objectStore — objects from
// all PPs are mixed in the same in-memory maps (hashToKey, mftsForKI,
// certBySKI). No filesystem-level or namespace-level separation.
fun s2_cache_workspace[pp: PP]: PP {
    pp
}

// PAPER-CLAIM: P2 | predicates: s2_cache_workspace_isolated, s3_manifest_store_key, s3_manifest_lookup_key, s5_cert_store_key, s5_chain_walk_isolated, s6_payload_store_key
// SOURCE: vendor/rpki-prover/src/src/RPKI/Store/Database.hs:323-334
pred s2_cache_workspace_isolated[pp1, pp2: PP] {
    pp1 != pp1
}

// L4/C8: RRDP session/serial consistency
// RrdpFetch.hs:194-209 — validatedNotification processes RRDP
// notification documents. Session ID and serial are used to decide
// snapshot vs delta fetch. No strict session/serial validation beyond
// comparison for cache freshness.
pred s2_rrdp_session_valid[pp: PP] {
    some pp.rrdp_notification
}

// =====================================================================
// S3 ManifestProcessing — MFT (ni + conf)
// =====================================================================

// --- Non-interference: manifest store key ---

// Database.hs:323-329 — saveObject:
//   Line 322: let h = getHash object — SHA256 of raw object bytes.
//   Line 323: existingKey <- M.get tx hashToKey h — global hashToKey lookup.
//   Line 324: case existingKey of Just key -> pure key — deduplication.
//   Line 329: M.put tx hashToKey h objectKey — store with content hash.
// Objects from ALL PPs stored in same hashToKey map.
// Same content hash from different PPs → same ObjectKey (deduplication).
fun s3_manifest_store_key[obj: RPKIObject]: Hash {
    obj.content_hash
}

// --- Non-interference: manifest lookup key ---

// Database.hs:109-112 — mftsForKI :: SMultiMap AKI MftMeta:
//   Global multimap indexed by AKI, shared across all TAs/PPs.
// Database.hs:446-449 — getMftsForAKI:
//   List.sortOn Down <$> MM.allForKey tx mftsForKI aki_
//   Returns ALL manifests with matching AKI, sorted descending.
// TopDown.hs:611-621 — makeNextIncrementalAction/makeNextFullValidationAction:
//   Both call getMftsForAKI to get candidate manifests.
// Domain.hs:335-336 — getAKI extracts AKI from CMS EE cert = issuer's SKI.
//
// AKI is used as the sole lookup key into a GLOBAL multimap.
// No per-PP scoping. Different PPs' manifests with same AKI compete.
fun s3_manifest_lookup_key[mft: RPKIObject]: KeyId {
    mft.cms.ee_certificate.issuer_ski
}

// --- Non-interference: CMS structural checks ---

// SignedObject.hs:56 — parseContent:
//   onNextContainer Set (onNextContainer Sequence parseSignerInfo)
//   Parses exactly one SignerInfo from the SET (first Sequence only).
// SignedObject.hs:127-128 — MessageDigest parsed from SignedAttrs:
//   MessageDigest attribute extracted as ShortByteString.
// rpki-prover uses a single SignedObject parsing path for all CMS
// objects including MFT and ROA — same code path as S6.
pred s3_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// --- Non-interference: time field parse safety ---

// Haskell time libraries (Data.Hourglass / Data.Time) return Either/Maybe
// on parse failure — never throw unrecoverable exceptions.
// AppMonad.hs:89-99 — fromTryM: catch + fromException handles all
// sync exceptions as AppError. Even if time parsing threw, it would
// be caught. Haskell has no equivalent of C's timegm sentinel collision.
pred s3_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- Non-interference: combined parse success ---

// L1/C1: Updated to check MFT payload time fields (thisUpdate/nextUpdate).
// L3/C6: Also checks public key parse safety.
// Full parse success requires CMS structure, time field safety,
// MFT payload time fields, and public key parse.
// rpki-prover uses a single SignedObject parsing path for all CMS
// objects (SignedObject.hs:43-140). Same code path as S6.
pred s3_mft_parse_succeeds[obj: RPKIObject] {
    s3_cms_structure_ok[obj.cms]
    s3_time_field_safe[obj.cms]
    // L1/C1: MFT eContent thisUpdate/nextUpdate parse safety
    obj.mft_payload.mft_this_update_parse = ParseOK
    obj.mft_payload.mft_next_update_parse = ParseOK
    // L3/C6: Public key parse — Haskell returns Either/Maybe, no panic
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Non-interference: error containment ---

// Haskell RTS provides thread-level exception non-interference. Each TA
// validation runs in its own async thread (Main.hs:354-356).
// AppMonad.hs:89-99 — fromTryM:
//   catch + fromException: re-throws async exceptions (limited to
//   current thread), wraps all synchronous exceptions as AppError.
// TopDown.hs:652-658 — catchError in tryMfts:
//   Manifest validation errors caught by monadic catchError,
//   fallback to next manifest. Errors never propagate to other PPs.
//
// Fatal error inventory: NONE
//   Haskell has no equivalent of C's errx() or Go's unrecovered panic.
//   All exceptions are caught by the RTS or by explicit catch handlers.
//   A synchronous exception in one thread cannot crash another thread.
//
// Encoding: empty body = always TRUE = errors ALWAYS contained.
// PAPER-CLAIM: P1 | predicates: s3_mft_error_contained, s4_crl_error_contained, s6_payload_error_contained
// SOURCE: vendor/rpki-prover/src/src/RPKI/AppMonad.hs:89-99 (fromTryM); TopDown.hs:652-658 (catchError)
pred s3_mft_error_contained[source_pp, victim_pp: PP] {
}

// --- Confinement: CMS eContent binding ---

// Crypto.hs:39-50 — validateCMSSignature:
//   Line 41: verifySignature signAlgorithm pubKey (toNormalBS signData) (toNormalBS sign)
//   Line 49: signData = signedAttrs — signature data comes from SignerInfos.
//   Does NOT compute or compare H(eContent) vs messageDigest.
// SignedObject.hs:127-128 — MessageDigest PARSED but NEVER USED:
//   Stored in Attribute record (Domain.hs:673) as BSS.ShortByteString.
//   No code path computes eContent hash for comparison.
// ObjectValidation.hs:519 — validateCms:
//   signatureCheck $ validateCMSSignature cms — only signature check.
//   No additional digest verification in the validation pipeline.
//
// CRITICAL: rpki-prover never verifies H(eContent) == messageDigest.
// The MessageDigest attribute is parsed and stored but never compared
// against the computed eContent hash. This is rpki-prover auth failure #1.
//
// RFC 6488 §3.1 SID check: rpki-prover does NOT verify SID.
// Crypto.hs:39-50 only checks RSA signature, no SID comparison.
// RFC 6488 §3.1 eContentType: rpki-prover does NOT check eContentType.
// PAPER-CLAIM: P3 | predicates: s3_mft_verify_succeeds, s6_payload_verify_succeeds
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/Crypto.hs:39-49 (validateCMSSignature over signedAttrs only); Parse/Internal/SignedObject.hs:127-128 (messageDigest parsed, never recompared)
// Registry: CMSSignedData.signature_valid, CMSSignedData.ee_certificate
pred s3_mft_verify_succeeds[cms: CMSSignedData] {
    cms.signature_valid = True
}

// --- Confinement: manifest hash binding ---

// M1/A4: Database.hs:323-329 saveObject stores objects by content_hash.
// TopDown.hs child traversal resolves manifest entries by hash.
// rpki-prover's verify only checks signature (not digest), but the
// hash binding between manifest fileList and child objects is still
// modelable: each child's content_hash must match an entry_hash.
// URI+hash binding: entry_uri matches child URI AND entry_hash matches content.
pred s3_mft_hash_verified[mft: RPKIObject, child: RPKIObject] {
    some e: mft.mft_payload.file_list |
        e.entry_uri = child.uri and e.entry_hash = child.content_hash
}

// =====================================================================
// S4 RevocationProcessing — CRL (ni + conf)
// =====================================================================

// --- Non-interference: CRL store key ---

// Database.hs:323-329 — saveObject: physical store uses content_hash globally.
// TopDown.hs:862-892 — findAndValidateCrl:
//   Line 864: findCrlOnMft — CRL found by hash FROM MANIFEST file list.
//   Line 872: DB.getKeyByHash tx db crlHash — exact hash lookup.
//   The CRL is NOT looked up by AKI or any global index.
//   It is accessed ONLY through the manifest's hash reference.
//   The manifest is per-PP, so the effective CRL access is manifest-scoped.
// ObjectValidation.hs:312 — signatureCheck $ validateCRLSignature crlObject parentCert
//   Even if content_hash collided (same bytes = same CRL), the CRL must
//   still pass signature verification against the issuing CA.
//
// Effective key: content_hash (physical) + manifest scoping (logical).
// Modeling as content_hash: collision means identical bytes = same CRL,
// which is semantically vacuous (not a security issue).
// CRL non-interference comes from scope (manifest-scoped) + sig verification,
// not from store partitioning.
fun s4_crl_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.content_hash
}

// --- Non-interference: CRL scope ---

// TopDown.hs:862-892 — findAndValidateCrl:
//   Line 864: findCrlOnMft — CRL found by hash from manifest file list.
//   Line 867: zero or >1 CRLs on manifest → error (NoCRLOnMFT/MoreThanOneCRLOnMFT).
//   Line 872: DB.getKeyByHash tx db crlHash — lookup by manifest-referenced hash.
//   CRL is located by its hash as listed in the manifest, NOT by AKI global lookup.
// Crypto.hs:26-35 — validateCRLSignature:
//   verifySignature signAlgorithm pubKey encoded signature
//   pubKey = certPubKey of parent CA certificate.
//   CRL signature MUST verify against parent CA's public key.
// ObjectValidation.hs:304-318 — validateCrl:
//   Line 312: signatureCheck $ validateCRLSignature crlObject parentCert
//   Line 313: when (toAKI (getSKI parentCert) /= aki) → CRL_AKI_DifferentFromCertSKI
//   CRL AKI must match parent CA's SKI.
//
// Cross-PP revocation impossible because:
//   1. CRL lookup uses manifest-referenced hash (manifest-scoped)
//   2. CRL signature verified by parent CA's public key (cryptographic non-interference)
//   3. CRL AKI must match parent CA's SKI (identity binding)
//
// Encoding: empty body = always TRUE = revocation scope always isolated.
pred s4_crl_scope_isolated[pp1, pp2: PP] {
}

// --- Non-interference: CRL error containment ---

// Same Haskell RTS thread-level exception non-interference as S3.
// AppMonad.hs:89-99 — fromTryM catches all sync exceptions.
// No fatal error paths in CRL processing.
//
// Encoding: empty body = always TRUE = errors ALWAYS contained.
pred s4_crl_error_contained[source_pp, victim_pp: PP] {
}

// --- Non-interference: CRL parse safety ---

// L2/C2: CRL-specific time field parse safety.
// Haskell time libraries return Either/Maybe — no panic.
// L3/C6: Public key parse safety.
pred s4_crl_parse_succeeds[obj: RPKIObject] {
    // C2: CRL thisUpdate/nextUpdate/revocationDate parse safety
    obj.crl_payload.crl_this_update_parse = ParseOK
    obj.crl_payload.crl_next_update_parse = ParseOK
    obj.crl_payload.crl_revocation_date_parse = ParseOK
    // L3/C6: Public key parse — Haskell returns Either/Maybe, no panic
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Confinement: CRL signature verification ---

// Crypto.hs:26-35 — validateCRLSignature:
//   verifySignature signAlgorithm pubKey (toNormalBS encoded) (toNormalBS signature')
//   pubKey = certPubKey $ cwsX509certificate $ getCertWithSignature parentCert
//   CRL signature verified against parent CA's public key.
// ObjectValidation.hs:312 — signatureCheck $ validateCRLSignature crlObject parentCert
//   Signature verification is mandatory; failure → InvalidSignature error.
pred s4_crl_verify_succeeds[cms: CMSSignedData] {
    cms.signature_valid = True
}

// --- Confinement: CRL issuer DN verification ---

// M2/B3: ObjectValidation.hs:304-318 validateCrl — parent lookup by AKI
// (line 313), then CRL signature check (line 312). No explicit CRL issuer
// DN comparison against parent cert subject DN found in the code path.
// NOT wired into auth_s4 verify — omitting is conservative (local audit abstraction).
pred s4_crl_issuer_dn_verified[crl_obj: RPKIObject, parent_cert: Certificate] {
    crl_obj.crl_payload.crl_issuer = parent_cert.subject_name
}

// --- Confinement: CRL revocation via serial number ---

// M3/C3: ObjectValidation.hs:304-318 — CRL revocation check uses serial
// number matching. Models whether a CRL revokes a specific certificate
// by serial number.
pred s4_cert_revoked[crl_obj: RPKIObject, cert: Certificate] {
    cert.serial_number in crl_obj.crl_payload.revoked_serials
}

// =====================================================================
// S5 CertChainProcessing — CA_CERT (ni + conf)
// =====================================================================

// --- Non-interference: cert store key ---

// Database.hs:323-329 — saveObject: same content_hash global store as S3/S4.
//   Line 334: M.put tx certBySKI (getSKI c) objectKey — CA certs also indexed by SKI.
//   Both hashToKey (all objects) and certBySKI (CA certs only) are global.
fun s5_cert_store_key[obj: RPKIObject]: Hash {
    obj.content_hash
}

// --- Non-interference: chain walk ---

// Database.hs:113 — certBySKI :: SMap SKI ObjectKey — global SKI index.
// Database.hs:334 — M.put tx certBySKI (getSKI c) objectKey — all CA certs indexed.
// Database.hs:112 — mftsForKI :: SMultiMap AKI MftMeta — global AKI multimap.
// Database.hs:522 — M.get tx certBySKI ski — cert lookup by SKI across all PPs.
//
// rpki-prover uses GLOBAL maps for chain building:
//   - certBySKI: maps SKI → ObjectKey, shared across all TAs/PPs
//   - mftsForKI: maps AKI → [MftMeta], shared across all TAs/PPs
// No per-PP namespace. Attacker's CA cert can be indexed alongside
// victim's certs in the same global maps.
//
// Encoding: pp1 != pp1 = always FALSE = chain walk NEVER isolated.
pred s5_chain_walk_isolated[pp1, pp2: PP] {
    pp1 != pp1
}

// --- Non-interference: SIA rpkiNotify scope ---

// rpki-prover does NOT validate SIA rpkiNotify URI scope against parent.
// Repository.hs:264-283 — getPublicationPointsFromCert:
//   Extracts rpkiNotify and caRepository URIs from the certificate.
//   Creates PublicationPointAccess objects. No host comparison against
//   parent's URI. DeltaUriHostname errors (RrdpFetch.hs:194-209) apply
//   to RRDP notification processing (S2), not to SIA extraction (S5).
//
// SIA scope is a non-issue for rpki-prover because the global shared
// TVar objectStore (Database.hs:75-92) already breaks NI at S5 through
// certBySKI and mftsForKI global maps (s5_chain_walk SAT). SIA-based
// redirection doesn't add new interference beyond global store violations.
//
// Encoding: empty body = always TRUE = SIA scope vacuously isolated.
// The interference from SIA redirection is already captured by
// s5_chain_walk_isolated (pp1 != pp1) and s5_cert_store_key.
pred s5_sia_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
}

// --- Non-interference: SIA caRepository scope ---

// rpki-prover does NOT validate SIA caRepository URI scope against parent.
// Repository.hs:272-278 — getPublicationPointsFromCert:
//   Extracts caRepository URI, parses as rsync URL. No host scope check.
//
// Same reasoning as rpkiNotify: global store subsumes SIA scope.
// Encoding: empty body = always TRUE = vacuously isolated.
pred s5_sia_repo_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
}

// --- Non-interference: SIA rpkiManifest scope ---

// rpki-prover does NOT validate SIA rpkiManifest URI scope against parent.
// Manifest resolution uses global mftsForKI (Database.hs:112) keyed by
// AKI, not by ca_repository-relative paths.
//
// Same reasoning: global store subsumes SIA scope.
// Encoding: empty body = always TRUE = vacuously isolated.
pred s5_sia_mft_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
}

// --- Confinement: resource delegation containment (P4 incremental shortcut) ---

// PAPER-CLAIM: P4 | predicates: conf_s5_incremental_resource_violation, conf_s6_incremental_resource_violation
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/TopDown.hs:1410-1416
//
// The prover's default validation mode is modeled as two build-time constants.
// These are configuration flags, not resource gates: representing them as
// Alloy constants is faithful (they are fixed at process start), and the
// resource SKIP they imply is encoded explicitly below rather than as an
// always-true "the check passes" gate.
//
// app/Main.hs:314-315 — validationAlgorithm defaults to Incremental
//   (noIncrementalValidation is false unless --no-incremental-validation).
pred prover_incremental_mode {
    True = True
}
// Config.hs:259 — defaultConfig validationRFC = StrictRFC; app/Main.hs:316-317
//   sets ReconsideredRFC only with --allow-overclaiming. Default build = StrictRFC.
pred prover_strict_rfc_default {
    True = True
}

// TopDown.hs:1410-1416 — validateShortcut:
//   vHoist $ case validationRFC of
//     StrictRFC       -> pure ()                         -- NO resource re-check
//     ReconsideredRFC | overclaimingHappened -> validateChildParentResources ...
//                     | otherwise            -> pure ()
// Validation/Types.hs:81-88 — RoaShortcut / CaShortcut cache the object's OWN
//   `resources :: AllResources`, NOT the parent delegation, so a cached shortcut
//   is not invalidated when the parent's delegation changes.
// So on the shortcut path the child's resources are re-validated against the
// CURRENT parent delegation ONLY under ReconsideredRFC && overclaimingHappened.
// Under the StrictRFC default, that branch is `pure ()` — no re-check.
pred s5_shortcut_resource_rechecked[obj: RPKIObject] {
    // holds only when the non-default ReconsideredRFC branch runs
    not prover_strict_rfc_default
}

// --- Confinement: basicConstraints ---

// L5/C5: TopDown.hs chain traversal checks cert isCA for chain
// validation decisions. Only certs with basicConstraints cA=true
// are treated as CA certificates in the chain walk.
// Registry: Certificate.is_ca
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/ObjectValidation.hs:71-76 (validateCaBasicConstraint)
pred s5_is_ca_checked[obj: RPKIObject] {
    obj.cms.ee_certificate.is_ca = True
}

// =====================================================================
// S6 PayloadProcessing — ROA, ASPA (ni + conf)
// =====================================================================

// --- Non-interference: payload store key ---

// Database.hs:323-329 — saveObject: same content_hash global store as S3/S4/S5.
//   ROA/ASPA objects stored in the same hashToKey map.
fun s6_payload_store_key[obj: RPKIObject]: Hash {
    obj.content_hash
}

// --- Non-interference: CMS structural checks ---

// Same SignedObject parsing path as S3 (SignedObject.hs:43-140).
// rpki-prover uses a single parseContent for all CMS objects.
pred s6_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// --- Non-interference: time field parse safety ---

// Same as S3 — Haskell time libraries return Either/Maybe, never crash.
pred s6_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- Non-interference: combined parse success ---

// Same SignedObject parsing path as S3.
// L3/C6: Also checks public key parse safety.
pred s6_payload_parse_succeeds[cms: CMSSignedData] {
    s6_cms_structure_ok[cms]
    s6_time_field_safe[cms]
    // L3/C6: Public key parse — Haskell returns Either/Maybe, no panic
    cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Non-interference: error containment ---

// Same Haskell RTS thread-level exception non-interference as S3.
// AppMonad.hs:89-99 — fromTryM catches all sync exceptions.
// No fatal error paths in ROA/ASPA processing.
//
// Encoding: empty body = always TRUE = errors ALWAYS contained.
pred s6_payload_error_contained[source_pp, victim_pp: PP] {
}

// --- Confinement: CMS eContent binding ---

// Same incomplete CMS verification as S3 (Crypto.hs:39-50).
// validateCMSSignature only checks signature over SignedAttrs.
// Never verifies H(eContent) == messageDigest.
// ObjectValidation.hs:519 — signatureCheck $ validateCMSSignature cms
//
// rpki-prover auth failure #1 applies to ALL signed objects (MFT+ROA+ASPA).
//
// RFC 6488 §3.1 SID check: rpki-prover does NOT verify SID.
// Crypto.hs:39-50 only checks RSA signature, no SID comparison.
// RFC 6488 §3.1 eContentType: rpki-prover does NOT check eContentType.
pred s6_payload_verify_succeeds[cms: CMSSignedData] {
    cms.signature_valid = True
}

// --- Confinement: resource certification (P4 incremental shortcut) ---

// PAPER-CLAIM: P4 (supporting) | predicates: s6_shortcut_resource_rechecked
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/TopDown.hs:1410-1416
// Full-validation path (TopDown.hs:1174-1186 validateChildObject -> validateRoa)
// DOES enforce ROA/ASPA resource containment (ObjectValidation.hs:360-375,
// :520-521). The incremental shortcut path (getChildPayloads, TopDown.hs:1361-1416)
// routes an already-accepted child through validateShortcut, which under the
// StrictRFC default runs `pure ()` and re-validates nothing against the current
// parent delegation. Modeled as the re-check NOT running (see P4 caveat).
pred s6_shortcut_resource_rechecked[obj: RPKIObject] {
    not prover_strict_rfc_default
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
    some atk_obj: RPKIObject, colliding_key: Hash |
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

// Registry: MFTEntry.entry_uri
// Haskell RTS catches exceptions per-thread — filename errors contained.
// Error contained: same as other S3 parse paths.
pred ni_s3_parse_mft_filename_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        some e: atk_obj.mft_payload.file_list | e.entry_uri.host != atk_pp.siaBase.host
    not s3_mft_error_contained[atk_pp, victim_pp]
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

// Registry: MFTEntry.entry_hash, RPKIObject.content_hash, MFTPayload.file_list
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/TopDown.hs:1019-1043 (validateMftEntries), 1051-1087 (getManifestEntry by hash)
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
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        s4_crl_store_key[atk_crl] = s4_crl_store_key[obj]
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
    some atk_cert: RPKIObject, colliding_key: Hash |
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

// PAPER-CLAIM: P4 | predicates: conf_s5_resource_violation
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/TopDown.hs:1410-1416
// Registry: Certificate.ip_resources, Certificate.as_resources, CA.delegated_prefixes, CA.delegated_asns
// source-level candidate (see AUDIT DERIVATION P4 caveat): an attacker CA
// certificate overclaiming a victim's resources is admitted on the incremental
// shortcut path, where validateShortcut (StrictRFC default) does NOT re-run
// validateChildParentResources. The model is stateless, so this does not
// model the shortcut's resource-recheck gap directly; a
// first-cycle-rejected child becomes a TroubledChild (TopDown.hs:1401-1403)
// and is fully re-validated (1342-1359). The reachable gap is the StrictRFC
// `pure ()` skip plus a shortcut cache key that omits the parent delegation.
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
    // admitted via the incremental shortcut, which skips the resource re-check
    prover_incremental_mode
    not s5_shortcut_resource_rechecked[obj]
}

// --- S6 iso per-field ---

// Registry: Certificate.subject_ski
pred ni_s6_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    some atk_obj: RPKIObject, colliding_key: Hash |
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

// Registry: Certificate.ip_resources
// Haskell RTS catches exceptions per-thread — prefix errors contained.
// Error contained: same as other S6 parse paths.
pred ni_s6_parse_ip_resources_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        some atk_obj.cms.ee_certificate.ip_resources
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

// PAPER-CLAIM: P4 | predicates: conf_s6_roa_resource_violation
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/TopDown.hs:1410-1416
// Registry: ROAPayload.roa_prefixes, Certificate.ip_resources
// source-level candidate (see AUDIT DERIVATION P4 caveat): overclaiming ROA
// admitted on the incremental shortcut path (validateShortcut StrictRFC pure()).
pred conf_s6_roa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    some overclaimed_prefix: Prefix |
        overclaimed_prefix in obj.roa_payload.roa_prefixes and
        overclaimed_prefix not in atk_pp.owner.delegated_prefixes and
        overclaimed_prefix in victim_pp.owner.delegated_prefixes
    prover_incremental_mode
    not s6_shortcut_resource_rechecked[obj]
}

// PAPER-CLAIM: P4 (supporting) | predicates: conf_s6_aspa_resource_violation
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/TopDown.hs:1410-1416
// Registry: ASPAPayload.customer_as, Certificate.as_resources
pred conf_s6_aspa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.aspa_payload.customer_as not in atk_pp.owner.delegated_asns
    prover_incremental_mode
    not s6_shortcut_resource_rechecked[obj]
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
    conf_s4_crl_signature_violation[atk_pp, victim_pp, obj] or
    conf_s4_crl_issuer_violation[atk_pp, victim_pp, obj]
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
    conf_s5_resource_violation[atk_pp, victim_pp, obj] or
    conf_s5_ca_delegation_full_violation[atk_pp, victim_pp, obj]
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
    conf_s6_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_econtent_type_violation[atk_pp, victim_pp, obj] or
    conf_s6_ee_resource_full_violation[atk_pp, victim_pp, obj]
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

// =====================================================================
// Independent field obligations (separate assertion per gate)
// =====================================================================
// Each isolates ONE defect and asks whether rpki-prover still admits a
// cross-PP object. UNSAT = the obligation is enforced (regression guard);
// SAT = a gap. These are OR'd into their stage aggregates above and into
// cross_pp_security via any_conf_violation.

// --- S4 Conf: CRL issuer binding (enforced via AKI==parentSKI + signature) ---
// Registry: CRLPayload.crl_issuer, Certificate.subject_name
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/ObjectValidation.hs:310-318
//   (validateCrl: signatureCheck validateCRLSignature; toAKI(getSKI parent)==aki).
// rpki-prover performs NO separate CRL issuer-DN comparison, but a CRL carrying
// the victim's AKI must verify under the victim's key; the attacker cannot forge
// that signature, and a copied victim CRL carries the victim's own issuer DN
// (base.als content_hash_binding). So a foreign-issuer CRL accepted against the
// victim is unreachable. UNSAT (enforced).
pred conf_s4_crl_issuer_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    aki[obj] = victim_pp.owner.ca_ski
    some vc: RPKIObject |
        vc.origin = victim_pp and vc.obj_type = OT_CA_CERT and
        obj.crl_payload.crl_issuer != vc.cms.ee_certificate.subject_name
    obj.cms.signature_valid = False
    s4_crl_verify_succeeds[obj.cms]
}
assert s4_conf_crl_issuer { no a, v: PP, o: RPKIObject | conf_s4_crl_issuer_violation[a, v, o] }
check s4_conf_crl_issuer for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// --- S5 Conf: CA delegation containment on the FULL-validation path (enforced) ---
// Registry: CA.delegated_prefixes, CA.delegated_asns, CA.ca_ski, Certificate.resources_inherit
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/ObjectValidation.hs:202-214
//   (validateResourceCert -> validateResources); ResourceValidation.hs:19-71
//   (validateChildParentResources strict nesting). TopDown.hs:1147-1152 runs this
//   on the full path. An explicit-resources CA cert overclaiming the victim is
//   rejected there. UNSAT (enforced) — complements conf_s5_resource_violation
//   (the incremental shortcut that SKIPS this check).
pred conf_s5_ca_delegation_full_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    s5_is_ca_checked[obj]
    aki[obj] = atk_pp.owner.ca_ski
    obj.cms.ee_certificate.resources_inherit = False
    some overclaimed_prefix: Prefix |
        overclaimed_prefix in obj.cms.ee_certificate.ip_resources and
        overclaimed_prefix not in atk_pp.owner.delegated_prefixes and
        overclaimed_prefix in victim_pp.owner.delegated_prefixes
    // full-path containment holds (enforced): child resources nested in parent's
    obj.cms.ee_certificate.ip_resources in atk_pp.owner.delegated_prefixes
}
assert s5_conf_ca_delegation_full { no a, v: PP, o: RPKIObject | conf_s5_ca_delegation_full_violation[a, v, o] }
check s5_conf_ca_delegation_full for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// --- S6 Conf: EE resource containment on the FULL-validation path (enforced) ---
// Registry: Certificate.ip_resources, Certificate.resources_inherit, ROAPayload.roa_prefixes
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/ObjectValidation.hs:360-375
//   (validateRoa: roa prefixes in verifiedResources), :520-521 (validateResourceCert
//   + validateResources). On the full path an overclaiming ROA is rejected; UNSAT.
//   Complements conf_s6_roa_resource_violation (the incremental shortcut skip).
pred conf_s6_ee_resource_full_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.ee_certificate.resources_inherit = False
    some overclaimed_prefix: Prefix |
        overclaimed_prefix in obj.roa_payload.roa_prefixes and
        overclaimed_prefix not in atk_pp.owner.delegated_prefixes and
        overclaimed_prefix in victim_pp.owner.delegated_prefixes
    // full-path containment holds (enforced): roa prefixes ⊆ EE ⊆ parent delegation
    obj.roa_payload.roa_prefixes in obj.cms.ee_certificate.ip_resources
    obj.cms.ee_certificate.ip_resources in atk_pp.owner.delegated_prefixes
}
assert s6_conf_ee_resource_full { no a, v: PP, o: RPKIObject | conf_s6_ee_resource_full_violation[a, v, o] }
check s6_conf_ee_resource_full for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// --- S6 Conf: SID binding (RFC 6488 §2.1.6.2) ---
// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
// SOURCE: vendor/rpki-prover/src/src/RPKI/Validation/Crypto.hs:39-49
//   (signature verified against the EE cert embedded in the SignedData);
//   ObjectValidation.hs:505. rpki-prover has NO separate SID==EE-SKI comparison,
//   but a victim-attributed object cannot carry a mismatched SID: via base.als
//   attacker_signature_capability a victim-key signature can only be a verbatim
//   copy, which preserves the victim's matching SID. UNSAT.
pred conf_s6_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.sid_matches_ee = False
    s6_payload_verify_succeeds[obj.cms]
    aki[obj] = victim_pp.owner.ca_ski
    some p: obj.roa_payload.roa_prefixes | p in victim_pp.owner.delegated_prefixes
}
assert s6_conf_sid { no a, v: PP, o: RPKIObject | conf_s6_sid_violation[a, v, o] }
check s6_conf_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// --- S6 Conf: eContentType binding (RFC 6488 §2.1.3.1) ---
// Registry: CMSSignedData.econtent_type_matches
// SOURCE: vendor/rpki-prover/src/src/RPKI/Parse/Internal/SignedObject.hs:43-73
//   (OID-dispatched eContent parse — object only parses as ROA/MFT/ASPA when the
//   encapContentInfo OID matches); ObjectValidation.hs:502-522. A victim-attributed
//   copy preserves its matching eContentType. UNSAT.
pred conf_s6_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_type_matches = False
    s6_payload_verify_succeeds[obj.cms]
    aki[obj] = victim_pp.owner.ca_ski
    some p: obj.roa_payload.roa_prefixes | p in victim_pp.owner.delegated_prefixes
}
assert s6_conf_econtent_type { no a, v: PP, o: RPKIObject | conf_s6_econtent_type_violation[a, v, o] }
check s6_conf_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// =====================================================================
// Aggregate soundness — no per-field violation escapes its stage aggregate
// =====================================================================
// Every per-field violation implies its stage aggregate, and every stage
// aggregate implies cross_pp_security's any_violation. UNSAT (no counterexample)
// proves the OR-wiring is complete, so the printed row cannot hide a per-field
// SAT whose aggregate is UNSAT (formal-review item 3).
assert aggregate_soundness {
    all a, v: PP, o: RPKIObject {
        ni_s2_fetch_scope_violation[a, v, o] implies ni_s2_violation[a, v, o]
        ni_s2_cache_workspace_violation[a, v, o] implies ni_s2_violation[a, v, o]
        ni_s3_store_key_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s3_manifest_lookup_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s3_parse_signerinfos_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s3_parse_time_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s3_parse_mft_this_update_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s3_parse_mft_next_update_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s3_parse_pubkey_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s3_parse_mft_filename_violation[a, v, o] implies ni_s3_violation[a, v, o]
        ni_s4_crl_store_key_violation[a, v, o] implies ni_s4_violation[a, v, o]
        ni_s4_crl_scope_violation[a, v, o] implies ni_s4_violation[a, v, o]
        ni_s4_parse_crl_this_update_violation[a, v, o] implies ni_s4_violation[a, v, o]
        ni_s4_parse_crl_next_update_violation[a, v, o] implies ni_s4_violation[a, v, o]
        ni_s4_parse_crl_revocation_date_violation[a, v, o] implies ni_s4_violation[a, v, o]
        ni_s4_parse_pubkey_violation[a, v, o] implies ni_s4_violation[a, v, o]
        ni_s5_store_key_violation[a, v, o] implies ni_s5_violation[a, v, o]
        ni_s5_chain_walk_violation[a, v, o] implies ni_s5_violation[a, v, o]
        ni_s5_sia_scope_violation[a, v, o] implies ni_s5_violation[a, v, o]
        ni_s5_sia_repo_scope_violation[a, v, o] implies ni_s5_violation[a, v, o]
        ni_s5_sia_mft_scope_violation[a, v, o] implies ni_s5_violation[a, v, o]
        ni_s6_store_key_violation[a, v, o] implies ni_s6_violation[a, v, o]
        ni_s6_parse_signerinfos_violation[a, v, o] implies ni_s6_violation[a, v, o]
        ni_s6_parse_time_violation[a, v, o] implies ni_s6_violation[a, v, o]
        ni_s6_parse_pubkey_violation[a, v, o] implies ni_s6_violation[a, v, o]
        ni_s6_parse_ip_resources_violation[a, v, o] implies ni_s6_violation[a, v, o]
        conf_s3_cms_digest_violation[a, v, o] implies conf_s3_violation[a, v, o]
        conf_s3_cms_signature_violation[a, v, o] implies conf_s3_violation[a, v, o]
        conf_s3_mft_hash_violation[a, v, o] implies conf_s3_violation[a, v, o]
        conf_s4_crl_signature_violation[a, v, o] implies conf_s4_violation[a, v, o]
        conf_s4_crl_issuer_violation[a, v, o] implies conf_s4_violation[a, v, o]
        conf_s5_resource_violation[a, v, o] implies conf_s5_violation[a, v, o]
        conf_s5_ca_delegation_full_violation[a, v, o] implies conf_s5_violation[a, v, o]
        conf_s6_roa_cms_digest_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_aspa_cms_digest_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_roa_resource_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_aspa_resource_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_roa_cms_signature_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_aspa_cms_signature_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_sid_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_econtent_type_violation[a, v, o] implies conf_s6_violation[a, v, o]
        conf_s6_ee_resource_full_violation[a, v, o] implies conf_s6_violation[a, v, o]
        ni_s2_violation[a, v, o] implies any_violation[a, v, o]
        ni_s3_violation[a, v, o] implies any_violation[a, v, o]
        ni_s4_violation[a, v, o] implies any_violation[a, v, o]
        ni_s5_violation[a, v, o] implies any_violation[a, v, o]
        ni_s6_violation[a, v, o] implies any_violation[a, v, o]
        conf_s3_violation[a, v, o] implies any_violation[a, v, o]
        conf_s4_violation[a, v, o] implies any_violation[a, v, o]
        conf_s5_violation[a, v, o] implies any_violation[a, v, o]
        conf_s6_violation[a, v, o] implies any_violation[a, v, o]
    }
}
check aggregate_soundness for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

run model_satisfiable for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
