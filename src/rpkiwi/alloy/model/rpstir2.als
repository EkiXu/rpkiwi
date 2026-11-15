// rpstir2.als — rpstir2 validation pipeline model.
//
// Source-code-derived model. Each computation predicate traces to a specific
// rpstir2 source path under vendor/rpstir2/src/src/. Derived from the §4.3
// design decisions and a line-level source review, NOT from observed exploits.
// The CMS digest path is modeled directly; it is not a stand-in for
// predicates that already exist on design-decision grounds; they are not the
// reason any predicate exists.
//
// 5-stage pipeline (S2-S6) organized by RPKI object type:
//   S2 RepositorySync       — NOTIFICATION, SNAPSHOT, DELTA   (NI only)
//   S3 ManifestProcessing   — MFT                             (NI + Conf)
//   S4 RevocationProcessing — CRL                             (NI + Conf)
//   S5 CertChainProcessing  — CA_CERT                         (NI + Conf)
//   S6 PayloadProcessing    — ROA, ASPA                       (NI + Conf)
//
// S2 carries NI only: RPKI objects are self-authenticating, so confinement is
// enforced downstream (S3-S6), not at fetch time. There is no S2-Conf
// obligation (paper §4.2); this model does not declare one.
//
// =====================================================================
// AUDIT DERIVATION — paper §4.3 claims → predicates → source file:line
// =====================================================================
// All source paths are rooted at vendor/rpstir2/src/src/.
//
// T1. Global SKI/AKI-keyed Go maps and SQL tables break storage isolation
//     (NI) at S2-S6.
//     primary:    ni_s3_store_key_violation
//     supporting: ni_s2_cache_workspace_violation, ni_s3_manifest_lookup_violation,
//                 ni_s4_crl_store_key_violation, ni_s4_crl_scope_violation,
//                 ni_s5_chain_walk_violation,
//                 ni_s6_store_key_violation
//     source: rpstir2-chainvalidate/chains.go:26-47 (one Chains struct),
//             :37 AkiToFileTypeIds, :39 SkiToFileTypeId,
//             :90/:195/:245/:296 AddCer/AddMft/AddRoa/AddAsa SkiToFileTypeId[ski],
//             :140 AddCrl AkiToFileTypeIds[aki] (:143 "no ski in crl");
//             rpstir2-chainvalidate/chainvalidate.go:43 NewChains(80000) one-for-all;
//             rpstir2-sys/sysdb.go global tables/views (:278 lab_rpki_roa,
//             :54/:182 lab_rpki_crl_revoked_cert[_view]).
//
// T2. The CMS verifier omits the messageDigest comparison and the SignerInfo
//     signature check. Breaks Conf at S3 and S6.
//     primary:    conf_s3_cms_digest_violation
//     supporting: conf_s6_roa_cms_digest_violation, conf_s6_aspa_cms_digest_violation,
//                 conf_s6_roa_cms_sid_violation, conf_s6_aspa_cms_sid_violation,
//                 conf_s3_cms_econtent_type_violation,
//                 conf_s6_roa_econtent_type_violation, conf_s6_aspa_econtent_type_violation
//     source: rpstir2-parsevalidate/eesignerinfo.go:175-198
//             (ValidateSignerInfoModel checks only DigestAlgorithm name + SigningTime:
//             no H(eContent) vs messageDigest, no SignerInfo signature, no SID,
//             no eContentType binding);
//             rpstir2-parsevalidate-openssl/opensslans1.go:388 MessageDigest
//             extracted then never compared; :368 ContentType extracted, never
//             validated; rpstir2-chainvalidate/{roa.go:96,mft.go:109,asa.go:95}
//             VerifyEeCertByX509 verifies the X.509 cert chain only, not CMS content.
//
// T3. Absence of recover wrappers around the CGo parsing bridge propagates any
//     parser crash process-wide. Breaks NI at S3, S4, S6 (paper enumeration).
//     The uncaught-panic design is process-wide, so the CA-cert parse path at S5
//     is the same decision (S5 parse preds are marked T3 supporting); S5-NI is
//     independently broken by T1 regardless.
//     primary:    ni_s3_parse_signerinfos_violation
//     supporting: ni_s3_parse_{time,pubkey,mft_this_update,mft_next_update,mft_filename}_violation,
//                 ni_s4_parse_{crl_this_update,crl_next_update,crl_revocation_date,pubkey}_violation,
//                 ni_s5_parse_{time,pubkey}_violation,
//                 ni_s6_parse_{signerinfos,time,pubkey,ip_resources}_violation,
//                 s3_mft_error_contained, s4_crl_error_contained,
//                 s5_cert_error_contained, s6_payload_error_contained
//     source: rpstir2-chainvalidate/{cer.go:64,mft.go:80,roa.go:64,asa.go:64,crl.go:62}
//             defer func(){ wg.Done(); ... } with NO recover(); grep recover() over
//             the whole rpstir2 tree = 0 hits; OpenSSL CGo crash or Go-side
//             index/nil-deref → panic → process death affecting every PP.
//
module rpstir2

open topo
open util/boolean

// =====================================================================
// S2 RepositorySync — NOTIFICATION, SNAPSHOT, DELTA (ni only)
// =====================================================================

// rpstir2-sync-core/rrdp/rrdp.go:16-92 — RrdpByUrlImpl():
//   Line 23: GetRrdpNotification(rrdpByUrlModel.NotifyUrl) fetches notification XML.
// rpstir2-sync-core/rrdp/snapshot.go:35-93 — processRrdpSnapshot():
//   Line 52: urlutil.JoinPrefixPathAndUrlHost(destPath, Snapshot.Uri)
//   Downloads snapshot from notificationModel.Snapshot.Uri — no host validation.
// rpstir2-sync-core/rrdp/delta.go — processRrdpDelta(): same pattern, no host check.
// No equivalent of rpki-client's valid_origin() hostname comparison.
//
// Encoding: empty body = no constraint = always TRUE = any URI passes.
pred s2_fetch_scope_enforced[pp: PP, target_uri: URI] {
}

// chains.go:26-47 — Chains struct: single instance for all PPs.
//   Line 37: AkiToFileTypeIds map[string]FileTypeIds — global AKI index
//   Line 39: SkiToFileTypeId map[string]string — global SKI index
// chainvalidate.go:40-116 — chainValidate():
//   Line 43: chains := NewChains(80000) — ONE Chains for all PPs.
//   Lines 48-63: getChainMfts/Crls/Cers/Roas/Asas all share same chains.
// Database tables lab_rpki_cer, lab_rpki_roa, lab_rpki_mft are also shared,
// no per-PP partitioning.
//
// Encoding: pp1 != pp1 = always FALSE = cache never isolated.
pred s2_cache_workspace_isolated[pp1, pp2: PP] {
    pp1 != pp1
}

// L4/C8: RRDP session/serial consistency
// rpstir2-sync-core/rrdp/rrdp.go:16-92 — RrdpByUrlImpl() fetches
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

// chains.go:89-91 — AddCer():
//   Line 90: c.SkiToFileTypeId[chainCer.Ski] = fileTypeId
// chains.go:194-196 — AddMft():
//   Line 195: c.SkiToFileTypeId[chainMft.Ski] = fileTypeId
// chains.go:244-246 — AddRoa():
//   Line 245: c.SkiToFileTypeId[chainRoa.Ski] = fileTypeId
// All object types use SKI as the global unique key in SkiToFileTypeId.
// If two objects from different PPs share the same SKI, the last writer
// wins (Go map assignment semantics).
fun s3_manifest_store_key[obj: RPKIObject]: KeyId {
    obj.cms.ee_certificate.subject_ski
}

// --- Non-interference: manifest lookup key ---

// mft.go:432-462 — getMftParentChainCer(chains, mftId):
//   Line 446: aki := chainMft.Aki
//   Line 447: parentCerSki := aki
//   Line 448: fileTypeId, ok := chains.SkiToFileTypeId[parentCerSki]
//   Manifest's parent cert is found via AKI → global SkiToFileTypeId.
// mft.go:464-536 — getSameAkiCerRoaCrlFilesChainMfts():
//   Line 477: fileTypeIds, ok := chains.AkiToFileTypeIds[aki]
//   Groups all objects with same AKI across all PPs.
// chains.go:37 — AkiToFileTypeIds map[string]FileTypeIds: global map.
// Manifest lookup key is AKI (= issuer's SKI). Shared across all PPs.
fun s3_manifest_lookup_key[mft: RPKIObject]: KeyId {
    mft.cms.ee_certificate.issuer_ski
}

// --- Non-interference: CMS structural checks ---

// opensslans1.go:312-396 — ParseSignerInfoModelByOpensslResults():
//   Delegates ASN.1 parsing to OpenSSL subprocess.
//   Extracts version, digestAlgorithm, signingTime, messageDigest.
// eesignerinfo.go:175-197 — ValidateSignerInfoModel():
//   Line 177: checks DigestAlgorithm == "sha256", nothing else structural.
//   Does NOT enforce SignerInfo cardinality (unlike rpki-client's "one" check).
//
// rpstir2 uses OpenSSL for all CMS parsing — same code path for
// MFT, ROA, and ASPA. Go code accepts whatever SignerInfos OpenSSL
// returns without enforcing exactly one.
//
// Encoding: `some` (not `one`) because OpenSSL parses whatever
// SignerInfos exist — Go code does not enforce cardinality.
pred s3_cms_structure_ok[cms: CMSSignedData] {
    some cms.signer_infos
}

// --- Non-interference: time field parse safety ---

// rpstir2 delegates X.509 parsing to OpenSSL via CGo (opensslans1.go).
// OpenSSL's ASN1_TIME_to_tm() returns 0/1 (not a crash) for malformed
// time fields. The Go wrapper checks the return value as an error.
// Although time parsing itself is not fatal in rpstir2, since
// error_contained is already always-false (no recover()), the
// time field outcome does not change the containment result.
// Modeled for cross-validator consistency.
pred s3_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- Non-interference: combined parse success ---

// Full parse success requires both CMS structure and time field safety.
// rpstir2 uses OpenSSL for all CMS parsing — same code path for
// MFT and ROA — same code path as S6.
// L1/C1: Updated to check MFT payload time fields (thisUpdate/nextUpdate).
// L3/C6: Also checks public key parse safety.
pred s3_mft_parse_succeeds[obj: RPKIObject] {
    s3_cms_structure_ok[obj.cms]
    s3_time_field_safe[obj.cms]
    // L1/C1: MFT eContent thisUpdate/nextUpdate parse safety
    obj.mft_payload.mft_this_update_parse = ParseOK
    obj.mft_payload.mft_next_update_parse = ParseOK
    // L3/C6: Public key parse — OpenSSL via CGo
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Non-interference: error containment ---

// rpstir2 is written in Go with CGo/OpenSSL. Validation goroutines
// have NO recover() wrapper:
//   cer.go:63-67 — validateCer() defer: wg.Done() + channel drain, NO recover()
//   mft.go:79-83 — validateMft() defer: wg.Done() + channel drain, NO recover()
//   roa.go:63-67 — validateRoa() defer: wg.Done() + channel drain, NO recover()
//   asa.go:63-67 — validateAsa() defer: wg.Done() + channel drain, NO recover()
//   crl.go:61-65 — validateCrl() defer: wg.Done() + channel drain, NO recover()
//
// Error propagation path:
//   Malformed CMS → OpenSSL C crash (SIGSEGV/SIGABRT) via CGo
//   → Go runtime converts to panic → no recover()
//   → Go runtime kills entire process → ALL PPs affected.
//   OR: Go-side nil pointer / index-out-of-range → panic → same outcome.
//
// chainvalidate.go:40-116 — chainValidate():
//   All PPs processed in same Go process. No per-PP process non-interference.
//
// Encoding: source_pp != source_pp = always FALSE = errors never contained.
pred s3_mft_error_contained[source_pp, victim_pp: PP] {
    source_pp != source_pp
}

// --- Confinement: CMS eContent binding ---

// opensslans1.go:385-391 — ParseSignerInfoModelByOpensslResults():
//   Line 388: signerInfoModel.MessageDigest = strings.TrimSpace(split[...])
//   MessageDigest is EXTRACTED from SignedAttrs but NEVER COMPARED
//   against computed H(eContent). Stored in model, never used.
// eesignerinfo.go:175-197 — ValidateSignerInfoModel():
//   Only checks DigestAlgorithm == "sha256" (line 177).
//   Does NOT verify digest value against eContent.
// mft.go:109 — certutil.VerifyEeCertByX509(parentCer, mft, ...):
//   Verifies X.509 cert chain (parent signed EE cert) but does NOT
//   verify CMS content binding (H(eContent) == messageDigest).
//
// CRITICAL: rpstir2 never verifies CMS digest binding. An attacker
// can modify eContent (MFT file list, ROA prefixes) without detection
// as long as the EE certificate chain remains valid.
//
// Encoding: empty body = no constraint = any CMS passes verification.
// This makes s3_conf SAT because the violation pred requires
// econtent_digest != signed_attrs_digest AND verify succeeds —
// with empty verify, both conditions can be simultaneously satisfied.
//
// RFC 6488 §3.1 SID check: rpstir2 does NOT verify SID.
// RFC 6488 §3.1 eContentType: rpstir2 does NOT check eContentType.
pred s3_mft_verify_succeeds[cms: CMSSignedData] {
}

// --- Confinement: manifest hash binding ---

// M1/A4: mft.go:464-536 getSameAkiCerRoaCrlFilesChainMfts groups objects
// by AKI. Each child object's content_hash must match an entry_hash in
// the manifest's file_list for hash binding to hold.
// URI+hash binding: entry_uri matches child URI AND entry_hash matches content.
pred s3_mft_hash_verified[mft: RPKIObject, child: RPKIObject] {
    // rpstir2: AKI-grouped traversal does not verify manifest fileList hashes.
    // Objects are discovered by AKI grouping, not by manifest hash verification.
    // Empty body = always true = hash check not performed.
}

// =====================================================================
// S4 RevocationProcessing — CRL (ni + conf)
// =====================================================================

// --- Non-interference: CRL store key ---

// chains.go:89-91 — AddCer(): c.SkiToFileTypeId[chainCer.Ski] = fileTypeId
// chains.go:123-144 — AddCrl():
//   Line 130: c.FileTypeIdToCrl[fileTypeId] = *chainCrl
//   Line 133-140: c.AkiToFileTypeIds[chainCrl.Aki] = fileTypeIds
//   Line 143: // no ski in crl — CRLs use AKI only, stored in global map.
// CRL is indexed by AKI in global AkiToFileTypeIds. No per-PP namespace.
fun s4_crl_store_key[obj: RPKIObject]: KeyId {
    obj.cms.ee_certificate.subject_ski
}

// --- Non-interference: CRL scope ---

// sysdb.go:713-717 — lab_rpki_crl_revoked_cert_view:
//   CREATE VIEW lab_rpki_crl_revoked_cert_view AS
//     select l.id, l.fileName, l.aki, r.revocationTime, r.sn
//     from lab_rpki_crl l, lab_rpki_crl_revoked_cert r
//     where l.id = r.crlId order by l.id
//   Global JOIN across ALL CRLs — no PP partition.
// roadb.go:19-22 — SQL query for ROA chain validation:
//   left join lab_rpki_crl_revoked_cert_view v
//     on v.sn = c.jsonAll->>'$.eeCertModel.sn' and c.aki = v.aki
//   NO PP filter — revocation status checked against global view.
// cerdb.go:19-22 — same pattern for cer revocation check.
// mftdb.go:19-22 — same pattern for mft revocation check.
//
// Attack path: attacker publishes CRL with AKI = victim CA's SKI,
// listing victim cert serial numbers. Global SQL view makes it visible
// to all queries regardless of PP origin.
//
// Encoding: pp1 != pp1 = always FALSE = revocation scope never isolated.
pred s4_crl_scope_isolated[pp1, pp2: PP] {
    pp1 != pp1
}

// --- Non-interference: CRL error containment ---

// Same Go process / no recover() mechanism as S3.
// crl.go:61-65 — validateCrl() defer: wg.Done() + channel drain, NO recover().
// CRL parsing uses OpenSSL via CGo — same crash propagation path.
//
// Encoding: source_pp != source_pp = always FALSE = errors never contained.
pred s4_crl_error_contained[source_pp, victim_pp: PP] {
    source_pp != source_pp
}

// --- Non-interference: CRL parse safety ---

// L2/C2: CRL-specific time field parse safety.
// rpstir2 delegates CRL parsing to OpenSSL via CGo — returns error,
// no panic. Included for completeness.
// L3/C6: Public key parse safety.
pred s4_crl_parse_succeeds[obj: RPKIObject] {
    obj.crl_payload.crl_this_update_parse = ParseOK
    obj.crl_payload.crl_next_update_parse = ParseOK
    obj.crl_payload.crl_revocation_date_parse = ParseOK
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Confinement: CRL signature verification ---

// crl.go:91 — certutil.VerifyCrlByX509(parentCer, crl):
//   Delegates to OpenSSL `openssl crl -verify` equivalent.
//   OpenSSL verifies CRL signature against issuing CA's public key.
// crl.go:84-86 — parent cert looked up via getCrlParentChainCers().
// crl.go:241-271 — getCrlParentChainCer():
//   Line 254: aki := chainCrl.Aki; parentCerSki := aki
//   Line 256: fileTypeId, ok := chains.SkiToFileTypeId[parentCerSki]
//   Finds parent cert via global SKI lookup, then verifies CRL signature.
//
// CRL signature is verified by OpenSSL → forgery requires breaking
// the issuing CA's private key.
// Encoding: signature_valid = True required for verification to pass.
pred s4_crl_verify_succeeds[cms: CMSSignedData] {
    cms.signature_valid = True
}

// --- Confinement: CRL issuer DN verification ---

// M2/B3: rpstir2 CRL parent lookup by AKI (getCrlParentChainCer).
// No explicit CRL issuer DN comparison found.
// NOT wired into auth_s4 (conservative modeling).
pred s4_crl_issuer_dn_verified[crl_obj: RPKIObject, parent_cert: Certificate] {
    crl_obj.crl_payload.crl_issuer = parent_cert.subject_name
}

// --- Confinement: CRL revocation via serial number ---

// M3/C3: CRL revocation by serial number.
pred s4_cert_revoked[crl_obj: RPKIObject, cert: Certificate] {
    cert.serial_number in crl_obj.crl_payload.revoked_serials
}

// =====================================================================
// S5 CertChainProcessing — CA_CERT (ni + conf)
// =====================================================================

// --- Non-interference: cert store key ---

// chains.go:89-91 — AddCer():
//   Line 90: c.SkiToFileTypeId[chainCer.Ski] = fileTypeId
// Same global SkiToFileTypeId map as S3. All CA certs from all PPs
// share the same SKI namespace. Last-writer-wins on SKI collision.
fun s5_cert_store_key[obj: RPKIObject]: KeyId {
    obj.cms.ee_certificate.subject_ski
}

// --- Non-interference: chain walk ---

// cer.go:377-410 — getCerParentChainCer(chains, cerId):
//   Line 394: aki := chainCer.Aki; parentCerSki := aki
//   Line 396: fileTypeId, ok := chains.SkiToFileTypeId[parentCerSki]
//   Parent cert is found via AKI → global SkiToFileTypeId map.
// cer.go:335-376 — GetCerParentChainCers(chains, cerId):
//   Walks up the chain by repeatedly calling getCerParentChainCer().
//   Each step uses the global SkiToFileTypeId map.
// cer.go:412-501 — getChildChainCersCrlsMftsRoasAsas(chains, cerId):
//   Line 434: fileTypeIds, ok := chains.AkiToFileTypeIds[childsAki]
//   Children found via global AkiToFileTypeIds map.
//
// Chain walk uses global maps — attacker's CA cert with matching SKI
// can be inserted as parent/child in victim's chain.
//
// Encoding: pp1 != pp1 = always FALSE = chain walk never isolated.
pred s5_chain_walk_isolated[pp1, pp2: PP] {
    pp1 != pp1
}

// --- Non-interference: SIA rpkiNotify scope ---

// rrdp.go:238-258 — parseCerAndGetRpkiNotify():
//   Line 256: return parseCerSimple.RpkiNotify — direct return, no host check.
//   rrdp.go:275: go rrQueue.AddRrdpUrl(rpkiNotify, ...) — adds to global queue.
//   Attacker's child CA cert directs RRDP fetch to victim's notification.
//
// Cross-stage NI: S5 reads SIA, S2 uses rpkiNotify for RRDP fetch.
// Empty body: no scope enforcement.
pred s5_sia_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
    // rrdp.go:256 — no host validation
    parent_pp != parent_pp
}

// --- Non-interference: SIA caRepository scope ---

// chains.go — uses caRepository directly, no scope check.
// Cross-stage NI: S5 reads SIA, S2 uses caRepository for rsync fetch.
// Empty body: no scope enforcement.
pred s5_sia_repo_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
    // chains.go — no host validation
    parent_pp != parent_pp
}

// --- Non-interference: SIA rpkiManifest scope ---

// chains.go — uses manifest URI directly.
// Cross-stage NI: S5 reads SIA, S3 uses rpkiManifest for manifest fetch.
// Empty body: no scope enforcement.
pred s5_sia_mft_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
    // chains.go — no scope validation
    parent_pp != parent_pp
}

// --- Confinement: resource delegation containment ---

// cer.go:149 — IpAddressesIncludeInParents(parents, self):
//   Called with chainCer.ParentChainCerAlones and chainCer.ChainIpAddresses.
// cer.go:288-310 — IpAddressesIncludeInParents(): iterates parent chain.
// cer.go:312-333 — ipAddressesIncludeInParent():
//   Line 318: iputil.IpRangeIncludeInParentRange(p.RangeStart, p.RangeEnd, s.RangeStart, s.RangeEnd)
// cer.go:237-286 — asnsIncludeInParents(): structurally identical for ASNs.
//
// cer.go:149-167 records CA overclaim as a warning, so CA admission alone
// is permissive. However roa.go:119 calls IpAddressesIncludeInParents on the
// complete ancestor chain and adds an ERROR for an overclaimed ROA. Model the
// resources usable by descendants as the intersection, not as exported raw
// certificate resources. This does not claim the certificate bytes are trimmed.
pred s5_cert_resource_check[obj: RPKIObject, issuing_ca: CA] {
    obj.cms.ee_certificate.ip_resources in issuing_ca.delegated_prefixes
    obj.cms.ee_certificate.as_resources in issuing_ca.delegated_asns
}

// --- Confinement: basicConstraints ---

// L5/C5: cer.go validates cert chain walk using SKI/AKI matching.
// Only certs with basicConstraints cA=true are treated as CA
// certificates in the chain walk.
// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate/eesignerinfo.go:108-119 (IsCa/BasicConstraints checked); rpstir2-chainvalidate/cer.go (CA chain uses cA=true certs)
// Registry: Certificate.is_ca
pred s5_is_ca_checked[obj: RPKIObject] {
    obj.cms.ee_certificate.is_ca = True
}

// =====================================================================
// S6 PayloadProcessing — ROA, ASPA (ni + conf)
// =====================================================================

// --- Non-interference: payload store key ---

// Same global SkiToFileTypeId map as S3/S5.
// chains.go:244-246 — AddRoa():
//   Line 245: c.SkiToFileTypeId[chainRoa.Ski] = fileTypeId
// chains.go:275-298 — AddAsa():
//   Line 296: c.SkiToFileTypeId[chainAsa.Ski] = fileTypeId
fun s6_payload_store_key[obj: RPKIObject]: KeyId {
    obj.cms.ee_certificate.subject_ski
}

// --- Non-interference: CMS structural checks ---

// Same OpenSSL CMS parsing path as S3.
// opensslans1.go:312-396 — ParseSignerInfoModelByOpensslResults()
// eesignerinfo.go:175-197 — ValidateSignerInfoModel(): DigestAlgorithm check only.
pred s6_cms_structure_ok[cms: CMSSignedData] {
    some cms.signer_infos
}

// --- Non-interference: time field parse safety ---

// Same as S3 — OpenSSL's ASN1_TIME_to_tm() returns error, not crash.
pred s6_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- Non-interference: combined parse success ---

// Same OpenSSL CMS parsing path as S3.
// L3/C6: Also checks public key parse safety.
pred s6_payload_parse_succeeds[cms: CMSSignedData] {
    s6_cms_structure_ok[cms]
    s6_time_field_safe[cms]
    cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Non-interference: error containment ---

// Same Go process / no recover() mechanism as S3 and S4.
// roa.go:63-67 — validateRoa() defer: wg.Done() + channel drain, NO recover().
// asa.go:63-67 — validateAsa() defer: same pattern, NO recover().
// Same crash propagation path: panic → no recover() → process killed.
//
// Encoding: source_pp != source_pp = always FALSE = errors never contained.
pred s6_payload_error_contained[source_pp, victim_pp: PP] {
    source_pp != source_pp
}

// --- Confinement: CMS eContent binding ---

// Same (absent) CMS verification as S3 — rpstir2 never verifies
// H(eContent) == messageDigest for any signed object type.
// opensslans1.go:385-391 — extracts MessageDigest but never compares.
// eesignerinfo.go:175-197 — only checks algorithm name.
// roa.go:96 — certutil.VerifyEeCertByX509(): cert chain only, no CMS binding.
// asa.go:95 — certutil.VerifyEeCertByX509(): same incomplete path.
//
// Encoding: empty body = no constraint = any CMS passes verification.
//
// RFC 6488 §3.1 SID check: rpstir2 does NOT verify SID.
// RFC 6488 §3.1 eContentType: rpstir2 does NOT check eContentType.
pred s6_payload_verify_succeeds[cms: CMSSignedData] {
}

// --- Confinement: resource certification ---

// C2/A1: ROA payload → EE cert IP resource check.
// roa.go:119 — IpAddressesIncludeInParents() for ROA IP addresses.
//   Line 120-127: overclaim → AddError (reject). RFC 8360 strict for EE.
pred s6_roa_resource_check[obj: RPKIObject] {
    obj.roa_payload.roa_prefixes in obj.cms.ee_certificate.ip_resources
}

// C2/A2: ASPA payload → EE cert AS resource check.
// asa.go:107 — IpAddressesIncludeInParents() for ASPA (same pattern).
pred s6_aspa_resource_check[obj: RPKIObject] {
    obj.aspa_payload.customer_as in obj.cms.ee_certificate.as_resources
}

// C3/C4: EE cert → CA delegation check (with inherit + ASN).
// cer.go:289-333 — IpAddressesIncludeInParents()/ipAddressesIncludeInParent():
//   Line 291-294: self is inherit (len==0) → ok (inherited resources pass);
//   Line 318: iputil.IpRangeIncludeInParentRange(p.Start, p.End, s.Start, s.End).
// Same resource containment logic as S5.
// Registry: Certificate.resources_inherit, CA.ca_ski
// resources_inherit is consumed here: an EE/CA cert marked inherit copies the
// issuing CA's (ca_ski-identified) resources rather than asserting its own.
pred s6_ee_resource_check[obj: RPKIObject, issuing_ca: CA] {
    {
        obj.cms.ee_certificate.resources_inherit = True
    } or {
        obj.cms.ee_certificate.ip_resources in issuing_ca.delegated_prefixes
        obj.cms.ee_certificate.as_resources in issuing_ca.delegated_asns
    }
}

// =====================================================================
// Per-field violation predicates
// (one per registry field/obligation; T1-T3 markers above)
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

// PAPER-CLAIM: T1 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/chains.go:26-47 (one Chains for all PPs); chainvalidate.go:43 NewChains(80000)
// Registry: PP.siaBase
pred ni_s2_cache_workspace_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    not s2_cache_workspace_isolated[atk_pp, victim_pp]
}

// --- S2 RRDP delta path resolution (#6) ---

// cpusoft/goutil @9e717a93c37c rrdputil/rrdpdelta.go — getRrdpDeltaImpl():
//   The <withdraw>/<publish> URI is filtered by ONE non-recursive
//   strings.Replace(uri, "../", "/", -1). Overlapping dot sequences
//   (e.g. "....//") survive the filter; url.Parse does not clean them and
//   osutil.JoinPathFile() is plain string concatenation (no filepath.Clean).
//   The resolved local delete path can therefore escape the attacker PP's
//   RRDP directory and land under another PP's directory.
//   Source-review candidate (path-traversal design decision).
//   EXTENSION: the path-traversal candidate is modeled separately;
//   not part of the original Table 2 audit model, not a pre-discovery prediction.
// --- S3 iso per-field ---

// PAPER-CLAIM: T1 | predicates: ni_s3_store_key_violation, ni_s3_manifest_lookup_violation, ni_s4_crl_store_key_violation, ni_s4_crl_scope_violation, ni_s5_chain_walk_violation, ni_s6_store_key_violation, ni_s2_cache_workspace_violation
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/chains.go:39 (SkiToFileTypeId global map), :90/:195/:245/:296 (AddCer/AddMft/AddRoa/AddAsa write SkiToFileTypeId[ski])
// Registry: Certificate.subject_ski
// T1 primary: the per-object SKI store key is one global map shared by every
// PP, so two objects from different PPs that share a SKI collide (last writer
// wins). This is the store-isolation break the paper attributes to the global
// SKI/AKI Go maps and SQL tables.
pred ni_s3_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some atk_obj: RPKIObject, colliding_key: KeyId |
        atk_obj.origin = atk_pp and
        s3_manifest_store_key[atk_obj] = colliding_key and
        s3_manifest_store_key[obj] = colliding_key
}

// PAPER-CLAIM: T1 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/mft.go:448 (SkiToFileTypeId[aki]), :477 (AkiToFileTypeIds[aki]); chains.go:37 (AkiToFileTypeIds global)
// Registry: Certificate.issuer_ski, CA.ca_ski
// The manifest's parent is resolved by AKI (= issuer SKI = the issuing CA's
// ca_ski) through the same global index, across all PPs.
pred ni_s3_manifest_lookup_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some atk_mft: RPKIObject, colliding_key: KeyId |
        atk_mft.origin = atk_pp and atk_mft.obj_type = OT_MFT and
        s3_manifest_lookup_key[atk_mft] = colliding_key and
        s3_manifest_lookup_key[obj] = colliding_key
}

// PAPER-CLAIM: T3 | predicates: ni_s3_parse_signerinfos_violation, ni_s3_parse_time_violation, ni_s3_parse_pubkey_violation, ni_s3_parse_mft_this_update_violation, ni_s3_parse_mft_next_update_violation, ni_s4_parse_crl_this_update_violation, ni_s4_parse_crl_next_update_violation, ni_s4_parse_crl_revocation_date_violation, ni_s4_parse_pubkey_violation, ni_s5_parse_time_violation, ni_s5_parse_pubkey_violation, ni_s6_parse_signerinfos_violation, ni_s6_parse_time_violation, ni_s6_parse_pubkey_violation, ni_s6_parse_ip_resources_violation
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/mft.go:80 (defer func(){wg.Done()} with NO recover()); recover() grep over the whole tree = 0 hits
// Registry: CMSSignedData.signer_infos
// T3 primary: a parser crash (OpenSSL CGo SIGSEGV/SIGABRT, or Go-side
// index/nil-deref) in any validate* goroutine propagates process-wide because
// no goroutine installs a recover(); s3_mft_error_contained is unconditionally
// false, so a victim object is affected by a crash triggered on an attacker
// object at S3.
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
// Go error return from url.Parse — no panic on invalid filenames.
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

// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate/eesignerinfo.go:175-198 (ValidateSignerInfoModel checks only DigestAlgorithm name + SigningTime); rpstir2-parsevalidate-openssl/opensslans1.go:388 (MessageDigest extracted, never compared)
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest, CMSSignedData.signature_valid
// T2 primary: the CMS verifier omits the H(eContent) vs messageDigest
// comparison. s3_mft_verify_succeeds has an empty body (no gate), so an object
// whose econtent_digest != signed_attrs_digest is still admitted — the attacker
// tampers eContent while the copied EE cert chain stays valid.
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

// PAPER-CLAIM: T2 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate/eesignerinfo.go:175-198 (ValidateSignerInfoModel never compares the SignerIdentifier to the EE cert)
// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
// RFC 6488 §2.1.6.2 requires the CMS SignerIdentifier (sid) to designate the
// EE certificate. rpstir2 parses the sid but never checks sid == EE cert;
// VerifyEeCertByX509 (roa.go:96/mft.go:109) verifies the X.509 chain of the EE
// cert, not that the SignerInfo actually refers to it. Omitted gate: an object
// whose sid does not match its EE cert is admitted. Grounds CMSSignedData.sid_matches_ee
// and (the verified-but-not-bound) CMSSignedData.ee_certificate.
pred conf_s3_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.sid_matches_ee = False
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
}

// PAPER-CLAIM: T2 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate-openssl/opensslans1.go:368 (ContentType extracted); rpstir2-parsevalidate/mft.go:128 (ParseMftEContentTypeByOpensslResults) — never validated against the expected OID
// Registry: CMSSignedData.econtent_type_matches
// RFC 6488 §2.1.3.1 requires the eContentType OID to equal the object's type
// OID. rpstir2 extracts the eContentType / SignerInfo contentType but performs
// no equality check and emits no error on mismatch (no comparison exists in the
// tree). Omitted gate: an object with a mismatched eContentType is admitted.
pred conf_s3_cms_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_type_matches = False
    s3_mft_verify_succeeds[obj.cms]
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

// PAPER-CLAIM: T1 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/crl.go:84-91 (getCrlParentChainCers then VerifyCrlByX509); cer.go getCrlParentChainCer resolves parent by AKI, NOT by issuer DN
// Registry: CRLPayload.crl_issuer, Certificate.subject_name
// rpstir2 does NOT compare the CRL issuer DN against the parent CA cert subject
// DN (RFC 5280 §5.1.2.3): it resolves the parent by AKI through the global
// SkiToFileTypeId index and verifies the CRL signature with OpenSSL
// (crl.go:91 VerifyCrlByX509). The issuer DN and the parent subject DN are
// parsed but are not admission inputs, so this models the genuine source
// behaviour: the DN check is ABSENT, but the obligation is subsumed by the
// signature gate. A CRL forging the victim CA's revocation authority
// (aki = victim ca_ski, issuer DN = victim CA subject DN, revoking a victim
// serial) is rejected because the attacker cannot sign under the victim key
// (base.als attacker_signature_capability). Modeled UNSAT (S4-Conf stays '.').
pred conf_s4_crl_issuer_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    aki[obj] = victim_pp.owner.ca_ski
    some parent: RPKIObject, vobj: victim_pp.objects |
        parent.obj_type = OT_CA_CERT and
        obj.crl_payload.crl_issuer = parent.cms.ee_certificate.subject_name and
        vobj.cms.ee_certificate.serial_number in obj.crl_payload.revoked_serials
    // rpstir2 admits the CRL iff its signature verifies against the AKI-resolved
    // parent; the attacker cannot produce a valid victim-key signature.
    obj.cms.signature_valid = False
    s4_crl_verify_succeeds[obj.cms]
}

// --- S5 iso per-field ---

// PAPER-CLAIM: T1 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/chains.go:90 (AddCer SkiToFileTypeId[ski]); cer.go:377-410 getCerParentChainCer
// Registry: Certificate.subject_ski
// PAPER-CLAIM: T1 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/cer.go:394-396 (parentCerSki := aki; SkiToFileTypeId[parentCerSki]); :434 AkiToFileTypeIds[childsAki]
// Registry: Certificate.issuer_ski, CA.ca_ski
// The chain walk resolves the parent by AKI (= issuer_ski), matched through the
// global SkiToFileTypeId against a parent whose subject SKI, for an honest CA,
// is that CA's ca_ski. Attacker and victim CAs are distinct only by ca_ski, yet
// the index is shared, so a colliding attacker CA cert enters the victim chain.
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

// --- Non-interference: CA cert parse safety (S5) ---

// PAPER-CLAIM: T3 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/cer.go:64 (defer func(){wg.Done()} with NO recover())
// The CA certificate processed at S5 is parsed through the same OpenSSL CGo
// bridge (opensslx509.go ParseCerModel) inside validateCer, whose defer has no
// recover(). The uncaught-panic design is process-wide, so a crash while parsing
// an attacker CA cert at S5 kills the process and affects the victim too. The
// paper's T3 enumerates S3/S4/S6 (the crash sites in the paper's audit); the
// S5 CA-cert parse path is the same design decision. S5-NI is independently
// broken by T1 (store/chain) regardless of this path.
// Encoding: source_pp != source_pp = always FALSE = errors never contained.
pred s5_cert_error_contained[source_pp, victim_pp: PP] {
    source_pp != source_pp
}

// PAPER-CLAIM: T3 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/cer.go:64 (no recover())
// Registry: Certificate.time_field_parse
pred ni_s5_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        atk_cert.cms.ee_certificate.time_field_parse = ParseFatal
    not s5_cert_error_contained[atk_pp, victim_pp]
}

// PAPER-CLAIM: T3 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-chainvalidate/cer.go:64 (no recover())
// Registry: Certificate.pubkey_parse
pred ni_s5_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        atk_cert.cms.ee_certificate.pubkey_parse = ParseFatal
    not s5_cert_error_contained[atk_pp, victim_pp]
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
            overclaimed_prefix in s5_usable_prefixes[obj, atk_pp.owner] and
            overclaimed_prefix not in atk_pp.owner.delegated_prefixes and
            overclaimed_prefix in victim_pp.owner.delegated_prefixes
    } or {
        some overclaimed_asn: ASN |
            overclaimed_asn in s5_usable_asns[obj, atk_pp.owner] and
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

// Registry: Certificate.ip_resources
// Confirmed against the vendored source (2026-11-10 audit), not merely
// inferred: rpstir2-parsevalidate-openssl/opensslans1.go
// ParseRoaModelByOpensslResults() unmarshals ROA eContent via Go's
// encoding/asn1 (safe), but THEN indexes the decoded OCTET STRING with
// one.AddressFamily[1] with no length check. An addressFamily shorter
// than 2 bytes (ASN.1-valid, RFC 3779-invalid) panics with an
// index-out-of-range error outside any recover(), matching Root Cause 4
// (cross-origin error propagation) — the crash is process-wide, not
// per-origin. The ASN.1 library itself does not panic; rpstir2's own
// post-decode field access does. Error contained: same as other S6
// parse paths (s6_payload_error_contained is unconditionally false here).
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

// PAPER-CLAIM: T2 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate/eesignerinfo.go:175-198 (no sid == EE cert check); roa.go:394/asa.go ValidateSignerInfoModel
// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
// Same omitted SignerIdentifier binding as S3, for ROA payloads (S6).
pred conf_s6_roa_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.sid_matches_ee = False
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.roa_payload.roa_prefixes |
        p in victim_pp.owner.delegated_prefixes
}

// PAPER-CLAIM: T2 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate/eesignerinfo.go:175-198 (no sid == EE cert check)
// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
// Same omitted SignerIdentifier binding as S3, for ASPA payloads (S6).
pred conf_s6_aspa_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.sid_matches_ee = False
    s6_payload_verify_succeeds[obj.cms]
    obj.aspa_payload.customer_as in victim_pp.owner.delegated_asns
}

// PAPER-CLAIM: T2 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate-openssl/opensslans1.go:301-303 (ParseRoaEContentTypeByOpensslResults extracts OID, no gate)
// Registry: CMSSignedData.econtent_type_matches
// Same omitted eContentType binding as S3, for ROA payloads (S6).
pred conf_s6_roa_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_type_matches = False
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.roa_payload.roa_prefixes |
        p in victim_pp.owner.delegated_prefixes
}

// PAPER-CLAIM: T2 (supporting)
// SOURCE: vendor/rpstir2/src/src/rpstir2-parsevalidate-openssl/opensslans1.go:368 (ContentType extracted, no gate)
// Registry: CMSSignedData.econtent_type_matches
// Same omitted eContentType binding as S3, for ASPA payloads (S6).
pred conf_s6_aspa_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.econtent_type_matches = False
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
    conf_s3_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_econtent_type_violation[atk_pp, victim_pp, obj] or
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
    ni_s5_chain_walk_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_repo_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_mft_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_parse_time_violation[atk_pp, victim_pp, obj] or
    ni_s5_parse_pubkey_violation[atk_pp, victim_pp, obj]
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
    conf_s6_roa_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_econtent_type_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_econtent_type_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_resource_violation[atk_pp, victim_pp, obj]
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
// New per-field obligations (T2 CMS SID / eContentType; T3 S5 CA-cert parse;
// subsumed S4 CRL issuer). SID/eContentType are SAT (omitted gates, S3/S6-Conf);
// S5 parse crashes are SAT (no recover(), S5-NI); CRL issuer is UNSAT (signature
// subsumes the absent DN check, S4-Conf stays '.').
assert s3_conf_cms_sid { no a, v: PP, o: RPKIObject | conf_s3_cms_sid_violation[a, v, o] }
assert s3_conf_cms_econtent_type { no a, v: PP, o: RPKIObject | conf_s3_cms_econtent_type_violation[a, v, o] }
assert s4_conf_crl_issuer { no a, v: PP, o: RPKIObject | conf_s4_crl_issuer_violation[a, v, o] }
assert s5_ni_parse_time { no a, v: PP, o: RPKIObject | ni_s5_parse_time_violation[a, v, o] }
assert s5_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s5_parse_pubkey_violation[a, v, o] }
assert s6_conf_roa_cms_sid { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_sid_violation[a, v, o] }
assert s6_conf_aspa_cms_sid { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_sid_violation[a, v, o] }
assert s6_conf_roa_econtent_type { no a, v: PP, o: RPKIObject | conf_s6_roa_econtent_type_violation[a, v, o] }
assert s6_conf_aspa_econtent_type { no a, v: PP, o: RPKIObject | conf_s6_aspa_econtent_type_violation[a, v, o] }

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
// Aggregate soundness (coordinator req 1): every per-field violation must
// flow into its stage aggregate (ni_sX/conf_sX_violation) AND into the top
// aggregate any_violation (cross_pp_security). No per-field predicate may be
// SAT while its stage aggregate is UNSAT. A missing OR-wire produces a
// counterexample here. Expected UNSAT.
// =====================================================================
assert aggregate_soundness {
    all a, v: PP, o: RPKIObject | {
        // --- per-field -> stage aggregate ---
        ni_s2_fetch_scope_violation[a,v,o] implies ni_s2_violation[a,v,o]
        ni_s2_cache_workspace_violation[a,v,o] implies ni_s2_violation[a,v,o]
        ni_s3_store_key_violation[a,v,o] implies ni_s3_violation[a,v,o]
        ni_s3_manifest_lookup_violation[a,v,o] implies ni_s3_violation[a,v,o]
        ni_s3_parse_signerinfos_violation[a,v,o] implies ni_s3_violation[a,v,o]
        ni_s3_parse_time_violation[a,v,o] implies ni_s3_violation[a,v,o]
        ni_s3_parse_mft_this_update_violation[a,v,o] implies ni_s3_violation[a,v,o]
        ni_s3_parse_mft_next_update_violation[a,v,o] implies ni_s3_violation[a,v,o]
        ni_s3_parse_pubkey_violation[a,v,o] implies ni_s3_violation[a,v,o]
        ni_s3_parse_mft_filename_violation[a,v,o] implies ni_s3_violation[a,v,o]
        conf_s3_cms_digest_violation[a,v,o] implies conf_s3_violation[a,v,o]
        conf_s3_cms_sid_violation[a,v,o] implies conf_s3_violation[a,v,o]
        conf_s3_cms_econtent_type_violation[a,v,o] implies conf_s3_violation[a,v,o]
        conf_s3_mft_hash_violation[a,v,o] implies conf_s3_violation[a,v,o]
        ni_s4_crl_store_key_violation[a,v,o] implies ni_s4_violation[a,v,o]
        ni_s4_crl_scope_violation[a,v,o] implies ni_s4_violation[a,v,o]
        ni_s4_parse_crl_this_update_violation[a,v,o] implies ni_s4_violation[a,v,o]
        ni_s4_parse_crl_next_update_violation[a,v,o] implies ni_s4_violation[a,v,o]
        ni_s4_parse_crl_revocation_date_violation[a,v,o] implies ni_s4_violation[a,v,o]
        ni_s4_parse_pubkey_violation[a,v,o] implies ni_s4_violation[a,v,o]
        conf_s4_crl_signature_violation[a,v,o] implies conf_s4_violation[a,v,o]
        conf_s4_crl_issuer_violation[a,v,o] implies conf_s4_violation[a,v,o]
        ni_s5_chain_walk_violation[a,v,o] implies ni_s5_violation[a,v,o]
        ni_s5_sia_scope_violation[a,v,o] implies ni_s5_violation[a,v,o]
        ni_s5_sia_repo_scope_violation[a,v,o] implies ni_s5_violation[a,v,o]
        ni_s5_sia_mft_scope_violation[a,v,o] implies ni_s5_violation[a,v,o]
        ni_s5_parse_time_violation[a,v,o] implies ni_s5_violation[a,v,o]
        ni_s5_parse_pubkey_violation[a,v,o] implies ni_s5_violation[a,v,o]
        conf_s5_resource_violation[a,v,o] implies conf_s5_violation[a,v,o]
        ni_s6_store_key_violation[a,v,o] implies ni_s6_violation[a,v,o]
        ni_s6_parse_signerinfos_violation[a,v,o] implies ni_s6_violation[a,v,o]
        ni_s6_parse_time_violation[a,v,o] implies ni_s6_violation[a,v,o]
        ni_s6_parse_pubkey_violation[a,v,o] implies ni_s6_violation[a,v,o]
        ni_s6_parse_ip_resources_violation[a,v,o] implies ni_s6_violation[a,v,o]
        conf_s6_roa_cms_digest_violation[a,v,o] implies conf_s6_violation[a,v,o]
        conf_s6_aspa_cms_digest_violation[a,v,o] implies conf_s6_violation[a,v,o]
        conf_s6_roa_cms_sid_violation[a,v,o] implies conf_s6_violation[a,v,o]
        conf_s6_aspa_cms_sid_violation[a,v,o] implies conf_s6_violation[a,v,o]
        conf_s6_roa_econtent_type_violation[a,v,o] implies conf_s6_violation[a,v,o]
        conf_s6_aspa_econtent_type_violation[a,v,o] implies conf_s6_violation[a,v,o]
        conf_s6_roa_resource_violation[a,v,o] implies conf_s6_violation[a,v,o]
        conf_s6_aspa_resource_violation[a,v,o] implies conf_s6_violation[a,v,o]
        // --- stage aggregate -> top aggregate (cross_pp_security) ---
        ni_s2_violation[a,v,o] implies any_violation[a,v,o]
        ni_s3_violation[a,v,o] implies any_violation[a,v,o]
        ni_s4_violation[a,v,o] implies any_violation[a,v,o]
        ni_s5_violation[a,v,o] implies any_violation[a,v,o]
        ni_s6_violation[a,v,o] implies any_violation[a,v,o]
        conf_s3_violation[a,v,o] implies any_violation[a,v,o]
        conf_s3_hash_violation[a,v,o] implies any_violation[a,v,o]
        conf_s4_violation[a,v,o] implies any_violation[a,v,o]
        conf_s5_violation[a,v,o] implies any_violation[a,v,o]
        conf_s6_violation[a,v,o] implies any_violation[a,v,o]
    }
}

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

check s3_conf_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_cms_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf_crl_issuer for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_parse_time for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check aggregate_soundness for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// Independent signature obligations, separate from digest binding.



run model_satisfiable for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

fun s5_usable_prefixes[obj: RPKIObject, parent: CA]: set Prefix {
    obj.cms.ee_certificate.ip_resources & parent.delegated_prefixes
}
fun s5_usable_asns[obj: RPKIObject, parent: CA]: set ASN {
    obj.cms.ee_certificate.as_resources & parent.delegated_asns
}
