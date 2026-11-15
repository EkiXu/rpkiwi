// fort.als — Fort 1.6.7 validator: mechanized §4.3 audit model.
//
// Source-derived model of Fort (LACNIC/NIC.mx), version 1.6.7.
// Every predicate encodes one design decision recorded in the paper's
// §4.3 review at a traced location under vendor/FORT-validator/src/src/.
// A decision that PRESERVES an obligation is a predicate that is always
// true under the attacker model (its violation predicate is UNSAT); a
// decision that BREAKS one is a violation predicate that is SATisfiable.
//
// Source citations are the reason a predicate exists; reachability is a runtime question.
// The Fort RRDP cache/workspace design decision ("cross-origin RRDP cache/workspace
// isolation failure") is kept below as a source comment; the predicates
// encode the underlying design decisions (global URL-keyed fetch cache,
// per-PP workspace, unscoped SIA, fatal-exit containment).
//
// =====================================================================
// AUDIT DERIVATION — paper §4.3 claims -> predicates -> source
// =====================================================================
//
// Paper (§4.3, Fort): "Fort uses repository-specific workspaces and
// delegates CMS and resource checks to OpenSSL with RFC 3779 validation.
// Like rpki-client, fatal-exit calls in its shared thread pool break
// non-interference at S3, S4, and S6; its memoized RRDP download cache
// violates non-interference at S2; and CA certificate SIA extensions are
// consumed without validating that rpkiNotify, caRepository, and
// rpkiManifest URIs match the issuing CA's repository scope, breaking
// non-interference at S5."
//
// F1 (Conf preserved S3-S6: per-PP workspace; OpenSSL CMS + RFC3779):
//   s2_cache_workspace_isolated      — types/uri.c:320-367; object/manifest.c:11-23
//   s3_mft_verify_succeeds           — asn1/signed_data.c:137-158,246-379;
//                                      object/certificate.c:764-866;
//                                      object/signed_object.c:24-89
//   s3_mft_hash_verified             — object/manifest.c:216-310
//   s4_crl_verify_succeeds           — object/certificate.c:1052-1131
//   s4_crl_issuer_dn_verified        — object/crl.c:140-164; object/name.c:142-193
//   s5_cert_resource_check           — resource.c:119-201,423-460
//   s6_roa_resource_check / s6_ee_resource_check
//                                    — object/roa.c:65,124,288; resource.c:355-543
//   -> conf_s3_* / conf_s4_* / conf_s5_* / conf_s6_* violations all UNSAT.
//
// F2 (NI broken S3,S4,S6: fatal-exit with no per-origin containment):
//   s3_mft_error_contained / s4_crl_error_contained / s6_payload_error_contained
//                                    — log.c:659-664 pr_crit()=__dead->exit(-1);
//                                      log.c:620-656 enomem_panic()=__dead->exit;
//                                      object/tal.c:340-415,495-557 (one OS
//                                      process per TAL walks every PP; no
//                                      per-PP fork/recover boundary).
//   -> ni_s3_parse_* / ni_s4_parse_* / ni_s6_parse_* violations SAT.
//
// F3 (NI broken S2: memoized, global URL-keyed RRDP fetch cache):
//   s2_fetch_scope_enforced          — rrdp.c:496-528,673,782-784 (snapshot/
//                                      delta URIs get notif=NULL -> UT_HTTPS,
//                                      no notification-authority restriction).
//   s2_fetch_cache_key               — cache/local_cache.c:38-42 (single ht),
//                                      :303-318 (find_node/add_node keyed on
//                                      uri_get_local), :568-619 (cache_download
//                                      returns memoized attempt.result),
//                                      :538-542 (was_recently_downloaded);
//                                      rrdp.c:815-822,869-900 (delete_rpp then
//                                      cache-hit skip -> victim workspace not
//                                      rebuilt).
//   -> ni_s2_fetch_scope_violation, ni_s2_fetch_cache_violation SAT.
//
// F4 (NI broken S5: SIA URIs consumed without issuing-CA scope check):
//   s5_sia_scope_enforced            — object/certificate.c:1320-1328 handle_rpkiNotify
//   s5_sia_repo_scope_enforced       — object/certificate.c:1310-1318 handle_caRepository
//   s5_sia_mft_scope_enforced        — object/certificate.c:1302-1308 handle_rpkiManifest
//                                      + :1675-1698 handle_sia_ca,
//                                      :1917-1925 certificate_validate_aia
//                                      ("FIXME Compare the AIA to the parent's
//                                      URI ... currently not recording"),
//                                      :1935-1951 download_rpp (uses SIA
//                                      URIs directly, no host comparison).
//   -> ni_s5_sia_scope_violation, ni_s5_sia_repo_scope_violation,
//      ni_s5_sia_mft_scope_violation SAT.
//
// Expected Table 2 row for Fort (printed order
//   S2-NI, S3-Conf, S3-NI, S4-Conf, S4-NI, S5-Conf, S5-NI, S6-Conf, S6-NI):
//       (X, ., X, ., X, ., X, ., X)
//
// =====================================================================

module fort

open topo
open util/boolean

// =====================================================================
// S2 RepositorySync — NOTIFICATION, SNAPSHOT, DELTA (NI only)
// =====================================================================
// Paper §4.2 S2: confinement is enforced downstream (S3-S6); S2 carries
// only a non-interference obligation. Encodes F3.

// PAPER-CLAIM: F3 | predicates: ni_s2_fetch_cache_violation, ni_s2_fetch_scope_violation
// SOURCE: vendor/FORT-validator/src/src/cache/local_cache.c:303

// --- NI: snapshot/delta URI authority restriction (absent) ---
//
// rrdp.c:496-528 parse_file_metadata():
//   Line 508-511: uri_create(..., (notif != NULL) ? UT_CAGED : UT_HTTPS, ...).
// rrdp.c:782-784 xml_read_notif(): snapshot metadata parsed with notif=NULL.
// rrdp.c:673 parse_notification_delta(): delta metadata parsed with notif=NULL.
//   Notification-level snapshot and delta URIs receive NULL notif -> UT_HTTPS,
//   with NO restriction to the authority of the enclosing notification URI
//   (no equivalent of rpki-client's valid_origin() host check). Paper S2
//   requirement (a) — "snapshot and delta URIs restricted to the authority
//   of the notification URI" — is therefore not enforced.
// Empty body = no constraint = any attacker-chosen URI passes.
pred s2_fetch_scope_enforced[pp: PP, target_uri: URI] {
    // (intentionally empty — no authority check; see SOURCE above)
}

// --- NI: per-PP on-disk workspace (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/types/uri.c:343
//
// types/uri.c:320-367 map_cache()/map_caged():
//   UT_CAGED URIs map into "<local-repository>/rrdp/<notification-path>/
//   a.b.c/...": each notifyURI yields a DISTINCT workspace directory.
// object/manifest.c:11-23 cage(): notif != NULL -> uri_create_caged().
// topo.als dedicated_publication_points guarantees pp1.notifyURI != pp2.notifyURI,
// so the per-PP on-disk workspace is isolated — Fort DOES separate each PP's
// exploded files. (The F3 break is the fetch-status cache below, NOT this.)
fun s2_cache_workspace[pp: PP]: URI {
    pp.notifyURI
}
pred s2_cache_workspace_isolated[pp1, pp2: PP] {
    s2_cache_workspace[pp1] != s2_cache_workspace[pp2]
}

// --- NI: global URL-keyed fetch-status cache (BROKEN, F3 primary) ---
//
// PAPER-CLAIM: F3 (supporting)
// SOURCE: vendor/FORT-validator/src/src/cache/local_cache.c:568
//
// cache/local_cache.c:38-42 struct rpki_cache: a single `struct cache_node *ht`
//   hash table per TAL, shared by every PP under that TAL.
// cache/local_cache.c:303-318 find_node()/add_node(): keyed on
//   uri_get_local(url) — a URL-derived key with NO publication-origin
//   dimension (for UT_HTTPS notification/snapshot/delta URLs the local name
//   is a global function of the URL).
// cache/local_cache.c:568-619 cache_download(): on a find_node() hit, if
//   was_recently_downloaded() (:538-542) returns the memoized
//   node->attempt.result WITHOUT re-downloading.
// rrdp.c:869-900 handle_snapshot(): delete_rpp() (:815-822) wipes the
//   workspace before the replacement snapshot is confirmed downloaded, so a
//   later cache-hit on the victim's snapshot URL skips reconstruction.
// Fort's fetch status is thus keyed by URL globally: an attacker RRDP
// document that references the victim's snapshot/notification URL shares the
// victim's cache entry.
// Cache key: uri only (NO origin) — contrast the per-PP store keys at S3-S6.
fun s2_fetch_cache_key[obj: RPKIObject]: URI {
    obj.uri
}

// =====================================================================
// S3 ManifestProcessing — MFT (NI + Conf)
// =====================================================================

// --- NI: per-PP manifest store key (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/cache/local_cache.c:303
//
// cache/local_cache.c:303-318 find_node()/add_node() key = uri_get_local(uri).
// For UT_CAGED manifest URIs uri_get_local() returns
//   {workspace}/{rsync_path} with workspace = {cache}/rrdp/{notif-host}/...
//   (types/uri.c:343-367 map_caged). Distinct notifyURIs -> distinct
//   workspace prefixes -> local paths never collide across PPs.
// Composite key: origin (determines workspace) + uri.
fun s3_manifest_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- NI: per-PP manifest lookup (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/manifest.c:316
//
// object/certificate.c:1302-1308 handle_rpkiManifest() stores the SIA
//   rpkiManifest URI in sia_uris.mft.
// object/manifest.c:316-381 handle_manifest(): cage(&uri, notif) (:328)
//   applies per-PP caging; signed_object_decode() (:335) loads by the caged
//   local path. There is NO global SKI/AKI manifest index (contrast
//   OctoRPKI/RIPE-V3). Composite key: origin (workspace root) + uri.
fun s3_manifest_lookup_key[mft: RPKIObject]: set univ {
    mft.origin + mft.uri
}

// --- NI: CMS structural checks (recoverable in Fort) ---
//
// asn1/signed_data.c:246-379 signed_data_validate():
//   :256-259 signerInfos.list.count != 1 -> pr_val_err() (RECOVERABLE:
//     returns -EINVAL, does NOT exit). An empty/overlong SignerInfos set is
//     rejected without terminating the process.
//   :160-244 validate_signed_attrs(): exactly one contentType/messageDigest/
//     signingTime; :187-188 pr_crit() ONLY on the asn1c invariant
//     "count==1 but array==NULL" (a decoder-internal impossibility, not a
//     normal input).
pred s3_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// --- NI: EE time field parse (recoverable in Fort) ---
//
// Certificate validity is checked by libcrypto inside X509_verify_cert
// (object/certificate.c:1092); object/certificate.c:946-958
// pr_debug_x509_dates() only formats dates for debug and tolerates NULL.
// Fort has NO timegm() sentinel bug (that is rpki-client's C2); its EE
// time parse is RECOVERABLE. Modeled as the fatal-candidate surface for F2
// (see s3_mft_error_contained) rather than a Fort-specific crash site.
pred s3_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- NI: combined parse success ---
//
// Single signed-object path for every CMS object:
//   object/signed_object.c:69-89 signed_object_validate() ->
//   asn1/signed_data.c:246-379 signed_data_validate(). Same for MFT
//   (manifest.c:354) and ROA (roa.c:288 eecert_init + signed_object_validate).
pred s3_mft_parse_succeeds[obj: RPKIObject] {
    s3_cms_structure_ok[obj.cms]
    s3_time_field_safe[obj.cms]
    // MFT eContent thisUpdate/nextUpdate (manifest.c:60-113 validate_dates,
    // asn_GT2time -> pr_val_err, RECOVERABLE).
    obj.mft_payload.mft_this_update_parse = ParseOK
    obj.mft_payload.mft_next_update_parse = ParseOK
    // Public key (certificate.c:504-556 validate_public_key, val_crypto_err,
    // RECOVERABLE).
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- NI: cross-origin error containment (ABSENT, F2) ---
//
// PAPER-CLAIM: F2 | predicates: ni_s3_parse_signerinfos_violation, ni_s3_parse_time_violation, ni_s3_parse_mft_this_update_violation, ni_s3_parse_mft_next_update_violation, ni_s3_parse_pubkey_violation, ni_s3_parse_mft_filename_violation
// SOURCE: vendor/FORT-validator/src/src/log.c:659
//
// Grounded design decision — NO per-publication-origin fault boundary:
//   object/tal.c:495-557 perform_standalone_validation(): one pthread per TAL
//     file (spawn_tal_thread, :471-493), joined serially.
//   object/tal.c:340-415 handle_tal_uri(): that single thread walks the ENTIRE
//     deferred-certificate tree — every PP reachable from the TAL — in one OS
//     process address space (:394-410). No per-PP fork (contrast rpki-client's
//     forked parser child) and no recover.
//   log.c:98-100 declares pr_crit()/enomem_panic() __dead (noreturn).
//   log.c:659-664 pr_crit() -> exit(-1); log.c:620-656 enomem_panic() ->
//     exit(ENOMEM). log.c:120-144 sigsegv_handler() is diagnostic only
//     (backtrace then SIG_DFL + re-raise) — it provides NO containment.
// Consequently ANY fatal exit raised while processing one origin's object
// terminates the whole validator and drops EVERY origin's VRPs. The witness
// is reachable whenever an attacker object reaches a fatal site in the same
// process; attacker-influenced fatal sites include resource.c:93,386
// pr_crit("Parent has no resources.") on the inherit path, and the
// enomem_panic() family (alloc.c:15-74) under attacker-sized input.
// F2 is an audit candidate for Fort (not one of its
// source review); the per-field ParseFatal below is the candidate trigger
// surface, and the load-bearing, grounded fact is this containment absence.
//
// Encoding: source_pp != source_pp is false for every atom, so the predicate
// is unconditionally FALSE — errors are never contained.
pred s3_mft_error_contained[source_pp, victim_pp: PP] {
    source_pp != source_pp
}

// --- Conf: CMS eContent digest + signature binding (PRESENT, F1) ---
//
// PAPER-CLAIM: F1 | predicates: conf_s3_cms_digest_violation, conf_s3_cms_signature_violation, conf_s3_cms_sid_violation, conf_s3_cms_econtent_type_violation, conf_s3_mft_hash_violation
// SOURCE: vendor/FORT-validator/src/src/asn1/signed_data.c:152
//
// asn1/signed_data.c:137-158 validate_message_digest_attribute():
//   :152 hash_validate_octet_string("sha256", digest, eci->eContent) —
//   Fort DOES compute SHA-256(eContent) and compare it to the signed
//   messageDigest attribute (the check rpki-prover/rpstir2 omit).
// object/certificate.c:764-866 certificate_validate_signature():
//   EVP_DigestVerifyInit/Update/Final over DER(signedAttrs) vs EE pubkey.
// object/signed_object.c:24-67 validate_eContentType()/validate_content_type():
//   eContentType OID and the signed content-type attribute must both match.
// object/certificate.c:1362-1383 handle_ski_ee(): the EE cert
//   subjectKeyIdentifier must equal the SignerInfo sid (memcmp, :1377-1380).
pred s3_mft_verify_succeeds[cms: CMSSignedData] {
    // Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
    cms.econtent_digest = cms.signed_attrs_digest
    // Registry: CMSSignedData.signature_valid
    cms.signature_valid = True
    // Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
    cms.sid_matches_ee = True
    // Registry: CMSSignedData.econtent_type_matches
    cms.econtent_type_matches = True
}

// --- Conf: manifest fileList hash binding (PRESENT, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/manifest.c:282
//
// object/manifest.c:216-310 build_rpp() iterates mft->fileList (:236);
//   :282 hash_validate_mft_file(uri, &fah->hash) compares each listed child's
//   SHA-256 to the manifest entry hash. URI+hash binding.
// Registry: MFTPayload.file_list, MFTEntry.entry_uri, MFTEntry.entry_hash, RPKIObject.content_hash
pred s3_mft_hash_verified[mft: RPKIObject, child: RPKIObject] {
    some e: mft.mft_payload.file_list |
        e.entry_uri = child.uri and e.entry_hash = child.content_hash
}

// =====================================================================
// S4 RevocationProcessing — CRL (NI + Conf)
// =====================================================================

// --- NI: per-PP CRL store key (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/rpp.h:18
//
// rpp.h:18-31 struct rpp holds a per-PP CRL (uri/stack/error); rpp.c:112-120
//   rpp_add_crl() enforces exactly one CRL per PP. rpp.c:159-197 rpp_crl()
//   lazily loads THIS PP's CRL into rpp->crl.stack — no global CRL pool.
// Same caged filesystem key as S3 (local_cache.c:303-318). Composite key:
// origin + uri.
fun s4_crl_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- NI: CRL revocation scope (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/certificate.c:1983
//
// object/certificate.c:1983 certificate_traverse() passes ONLY the parent
//   PP's CRL: rpp_crl(rpp_parent, &rpp_parent_crl). object/certificate.c:1082
//   X509_STORE_CTX_set0_crls() installs that per-PP stack; object/crl.c:127-138
//   validate_extensions() -> handle_aki binds the CRL's AKI to the parent key
//   (extension.c:1001-1023 validate_public_key_hash). A CRL cannot revoke
//   across PPs: per-PP storage + signature + AKI + issuer DN all pin it to the
//   issuing CA. Empty body = always TRUE = revocation scope isolated.
pred s4_crl_scope_isolated[pp1, pp2: PP] {
    // (per-PP CRL; no global revoked-serial map — see SOURCE above)
}

// --- NI: CRL error containment (ABSENT, F2) ---
//
// PAPER-CLAIM: F2 (supporting)
// SOURCE: vendor/FORT-validator/src/src/log.c:659
//
// Same single-process, __dead-exit model as S3 (object/tal.c:340-415,495-557;
// log.c:620-664). CRL loading (rpp.c:159-197 rpp_crl, crl.c:166-184 crl_load)
// runs in the same worker as the rest of the tree; rpp.c:171-172
// pr_crit("RPP lacks a CRL.") and the enomem_panic() family are __dead. CRL
// field parses themselves are RECOVERABLE (crl.c:28-33 d2i_X509_CRL_bio ->
// val_crypto_err). Encoding: unconditionally FALSE.
pred s4_crl_error_contained[source_pp, victim_pp: PP] {
    source_pp != source_pp
}

// --- NI: CRL parse safety (recoverable; F2 candidate surface) ---
pred s4_crl_parse_succeeds[obj: RPKIObject] {
    obj.crl_payload.crl_this_update_parse = ParseOK
    obj.crl_payload.crl_next_update_parse = ParseOK
    obj.crl_payload.crl_revocation_date_parse = ParseOK
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- Conf: CRL signature verification (PRESENT, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/certificate.c:1092
//
// object/certificate.c:1052-1131 certificate_validate_chain(): :1092
//   X509_verify_cert() verifies the chain AND the CRL signature against the
//   issuing CA's public key, and checks revocation.
pred s4_crl_verify_succeeds[cms: CMSSignedData] {
    cms.signature_valid = True
}

// --- Conf: CRL issuer DN vs parent subject DN (PRESENT, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/name.c:173
//
// object/crl.c:155 crl_validate() -> validate_issuer_name("CRL", issuer).
// object/name.c:142-193 validate_issuer_name(): decodes the parent cert's
//   subject (:164) and the CRL's issuer (:168) and requires x509_name_equals
//   (:173). The CRL issuer DN must equal the issuing CA cert's subject DN.
// Registry: CRLPayload.crl_issuer, Certificate.subject_name
pred s4_crl_issuer_dn_verified[crl_obj: RPKIObject, parent_cert: Certificate] {
    crl_obj.crl_payload.crl_issuer = parent_cert.subject_name
}

// --- Conf: revocation by serial number (PRESENT, F1) ---
//
// object/crl.c:67-102 validate_revoked(); X509_verify_cert
// (certificate.c:1092) checks the certificate serial against CRL entries.
// Registry: CRLPayload.revoked_serials, Certificate.serial_number
pred s4_cert_revoked[crl_obj: RPKIObject, cert: Certificate] {
    cert.serial_number in crl_obj.crl_payload.revoked_serials
}

// =====================================================================
// S5 CertChainProcessing — CA_CERT (NI + Conf)
// =====================================================================

// --- NI: per-PP cert store key (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/certificate.c:1988
//
// object/certificate.c:1988 certificate_load(cert_uri) reads from the caged
//   local path; local_cache.c:303-318 keys the cache on uri_get_local.
//   Composite key: origin + uri.
fun s5_cert_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- NI: chain walk / parent resolution (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/cert_stack.c:63
//
// object/certificate.c:1953-2061 certificate_traverse(): parents live on the
//   per-TAL validation state's certificate stack (:2034 x509stack_push).
// cert_stack.c:63-91 struct cert_stack is per-TAL (defers + x509s + metas),
//   built top-down by the tree walk; object/tal.c:390-410 pops deferred certs
//   in order. The parent key is resolved via the AKI -> parent SKI hash
//   binding (extension.c:1001-1023 handle_aki -> validate_public_key_hash),
//   NOT a global SKI/AKI -> certificate index. Parent resolution is therefore
//   scoped to the current chain, so it cannot cross PPs.
// Registry: CA.ca_ski, Certificate.issuer_ski
pred s5_chain_walk_isolated[pp1, pp2: PP] {
    // (per-TAL cert stack + AKI->parent-key binding; no global ca_ski index)
}

// --- NI: SIA rpkiNotify scope (ABSENT, F4) ---
//
// PAPER-CLAIM: F4 | predicates: ni_s5_sia_scope_violation, ni_s5_sia_repo_scope_violation, ni_s5_sia_mft_scope_violation
// SOURCE: vendor/FORT-validator/src/src/object/certificate.c:1320
//
// object/certificate.c:1320-1328 handle_rpkiNotify(): uris_add(&uris->rpp, uri)
//   + uri_refget — the rpkiNotify URI is stored with NO comparison to the
//   issuing CA's repository host. object/certificate.c:1935-1951 download_rpp()
//   feeds it straight into cache_download_alt(). An attacker child CA whose
//   SIA rpkiNotify points at the victim's notification URL redirects RRDP
//   fetching there (cross-stage: S5 reads SIA, S2 fetches). Empty enforcement.
pred s5_sia_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
    // (no host validation on SIA rpkiNotify — see SOURCE above)
    parent_pp != parent_pp
}

// --- NI: SIA caRepository scope (ABSENT, F4) ---
//
// PAPER-CLAIM: F4 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/certificate.c:1310
//
// object/certificate.c:1310-1318 handle_caRepository(): uris_add + uri_refget,
//   no parent-host comparison. object/certificate.c:1917-1925
//   certificate_validate_aia() is an explicit no-op ("FIXME Compare the AIA to
//   the parent's URI ... We're currently not recording the URI"). caRepository
//   is consumed without issuing-CA scope validation.
pred s5_sia_repo_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
    // (no host validation on SIA caRepository — see SOURCE above)
    parent_pp != parent_pp
}

// --- NI: SIA rpkiManifest scope (ABSENT, F4) ---
//
// PAPER-CLAIM: F4 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/certificate.c:1302
//
// object/certificate.c:1302-1308 handle_rpkiManifest(): uris->mft =
//   uri_refget(uri) — the rpkiManifest URI is recorded with no check that it
//   lies within the issuing CA's caRepository scope (cross-stage: S5 reads
//   SIA, S3 fetches the manifest). Empty enforcement.
pred s5_sia_mft_scope_enforced[cert_obj: RPKIObject, parent_pp: PP] {
    // (no scope validation on SIA rpkiManifest — see SOURCE above)
    parent_pp != parent_pp
}

// --- Conf: RFC 3779 resource delegation containment (PRESENT, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/resource.c:135
//
// resource.c:119-159 add_prefix4(): :135 res4_contains_prefix(parent, ...);
//   under RPKI_POLICY_RFC6484 (strict) a non-contained prefix -> pr_val_err
//   (:138, reject). resource.c:161-201 add_prefix6() (res6_contains_prefix);
//   resource.c:423-460 add_asn() (:434 rasn_contains). EE certs for ROA/ASPA
//   use eecert_init(&ee, crl, false) (roa.c:288, manifest.c:351) with
//   force_inherit=false and the strict policy.
// resource.c:86-117 inherit_aors()/:379-396 inherit_asiors() implement the
//   RFC 3779 inherit form; base.als inherit_implies_no_explicit_resources pins
//   inherit to empty explicit resources.
// Registry: Certificate.ip_resources, Certificate.as_resources, Certificate.resources_inherit, CA.delegated_prefixes, CA.delegated_asns
pred s5_cert_resource_check[obj: RPKIObject, issuing_ca: CA] {
    {
        obj.cms.ee_certificate.resources_inherit = True
    } or {
        obj.cms.ee_certificate.ip_resources in issuing_ca.delegated_prefixes
        obj.cms.ee_certificate.as_resources in issuing_ca.delegated_asns
    }
}

// --- Conf: basicConstraints cA (PRESENT, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/object/certificate.c:1903
//
// object/certificate.c:1890-1914 get_certificate_type(): :1903 X509_check_ca
//   selects CERTYPE_CA; object/certificate.c:1340-1354 handle_bc() validates
//   the basicConstraints extension. Only cA=true certs are treated as CAs.
// Registry: Certificate.is_ca
pred s5_is_ca_checked[obj: RPKIObject] {
    obj.cms.ee_certificate.is_ca = True
}

// =====================================================================
// S6 PayloadProcessing — ROA, ASPA (NI + Conf)
// =====================================================================

// --- NI: per-PP payload store key (PRESERVED, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/cache/local_cache.c:303
//
// ROA/ASPA files stored under the caged uri_get_local path, same as S3-S5.
// Composite key: origin + uri.
fun s6_payload_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// --- NI: CMS structural checks (recoverable) ---
//
// Same signed_data_validate() path as S3 (asn1/signed_data.c:246-379),
// reached from object/roa.c:257-314 roa_traverse().
pred s6_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// --- NI: EE time field parse (recoverable; F2 candidate surface) ---
pred s6_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- NI: combined parse success ---
pred s6_payload_parse_succeeds[cms: CMSSignedData] {
    s6_cms_structure_ok[cms]
    s6_time_field_safe[cms]
    cms.ee_certificate.pubkey_parse = ParseOK
}

// --- NI: cross-origin error containment (ABSENT, F2) ---
//
// PAPER-CLAIM: F2 (supporting)
// SOURCE: vendor/FORT-validator/src/src/log.c:659
//
// Same single-process, __dead-exit model as S3/S4 (object/tal.c:340-415,
// 495-557; log.c:620-664). ROA/ASPA processing (roa.c:257-314) shares the
// signed_data/certificate code paths; reachable fatal sites include
// resource.c:93,386 pr_crit() on the inherit path and the enomem_panic()
// family. Encoding: unconditionally FALSE.
pred s6_payload_error_contained[source_pp, victim_pp: PP] {
    source_pp != source_pp
}

// --- Conf: CMS eContent digest + signature binding (PRESENT, F1) ---
//
// PAPER-CLAIM: F1 (supporting)
// SOURCE: vendor/FORT-validator/src/src/asn1/signed_data.c:152
//
// Same binding path as S3 (asn1/signed_data.c:137-158 messageDigest;
// certificate.c:764-866 signature; signed_object.c:24-67 eContentType;
// certificate.c:1362-1383 SID-EE).
pred s6_payload_verify_succeeds[cms: CMSSignedData] {
    // Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
    cms.econtent_digest = cms.signed_attrs_digest
    // Registry: CMSSignedData.signature_valid
    cms.signature_valid = True
    // Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
    cms.sid_matches_ee = True
    // Registry: CMSSignedData.econtent_type_matches
    cms.econtent_type_matches = True
}

// --- Conf: ROA payload -> EE IP resources (PRESENT, F1) ---
//
// object/roa.c:65-67 ____handle_roa_v4(): !resources_contains_ipv4(parent,...)
//   -> pr_val_err (reject). object/roa.c:124-126 ____handle_roa_v6().
// Registry: ROAPayload.roa_prefixes, Certificate.ip_resources
pred s6_roa_resource_check[obj: RPKIObject] {
    obj.roa_payload.roa_prefixes in obj.cms.ee_certificate.ip_resources
}

// --- Conf: ASPA payload -> EE AS resources (PRESENT, F1) ---
// Registry: ASPAPayload.customer_as, Certificate.as_resources
pred s6_aspa_resource_check[obj: RPKIObject] {
    obj.aspa_payload.customer_as in obj.cms.ee_certificate.as_resources
}

// --- Conf: EE cert -> CA delegation containment (PRESENT, F1) ---
//
// Same strict RFC6484 containment path as S5 (resource.c:135,434); EE certs
// for ROA/ASPA traverse certificate_validate_chain + certificate_get_resources.
// Registry: Certificate.ip_resources, Certificate.as_resources, Certificate.resources_inherit
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
// Every body opens with attack_context[atk_pp, victim_pp], which pins
// atk_pp = Attacker.controlled_pp and atk_pp != victim_pp (base.als).
// =====================================================================

// --- S2 NI per-field ---

// Registry: RPKIObject.uri, PP.notifyURI
pred ni_s2_fetch_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_SNAPSHOT + OT_DELTA + OT_NOTIFICATION)
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.uri = obj.uri
    s2_fetch_scope_enforced[atk_pp, obj.uri]
}

// Registry: RPKIObject.uri
// F3 primary: the attacker and victim RRDP documents share one URL-keyed
// fetch-status entry in the single per-TAL cache (local_cache.c:303-318),
// so the attacker's earlier fetch result is reused for the victim's URL.
pred ni_s2_fetch_cache_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_SNAPSHOT + OT_DELTA + OT_NOTIFICATION)
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and
        atk_obj.obj_type in (OT_SNAPSHOT + OT_DELTA + OT_NOTIFICATION) and
        s2_fetch_cache_key[atk_obj] = s2_fetch_cache_key[obj]
}

// Registry: PP.notifyURI
// Workspace isolation is PRESERVED in Fort (distinct notifyURIs); this
// predicate is UNSAT and documents that the F3 break is the fetch cache,
// not the on-disk workspace.
pred ni_s2_cache_workspace_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    not s2_cache_workspace_isolated[atk_pp, victim_pp]
}

// --- S3 NI per-field ---

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

// Registry: MFTEntry.entry_uri, MFTPayload.file_list
// Malformed manifest fileList filenames are handled by libxml/manifest.c
// without a process crash (manifest.c:210-214 get_extension; unknown
// extensions are simply skipped, :249-261). The shared-process F2 boundary
// still applies to any fatal provoked alongside, so this stays an NI candidate.
pred ni_s3_parse_mft_filename_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        some e: atk_obj.mft_payload.file_list | e.entry_uri.host != atk_pp.siaBase.host
    not s3_mft_error_contained[atk_pp, victim_pp]
}

// --- S3 Conf per-field (all UNSAT: Fort performs every check) ---

// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
pred conf_s3_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
}

// Registry: CMSSignedData.signature_valid
// Independent signature obligation (deleting `signature_valid = True` from
// s3_mft_verify_succeeds would flip this to SAT).
pred conf_s3_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.signature_valid = False
    s3_mft_verify_succeeds[obj.cms]
}

// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
// Independent SID-EE binding obligation (certificate.c:1362-1383 handle_ski_ee).
pred conf_s3_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.sid_matches_ee = False
    s3_mft_verify_succeeds[obj.cms]
}

// Registry: CMSSignedData.econtent_type_matches
// Independent eContentType obligation (signed_object.c:24-67).
pred conf_s3_cms_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_type_matches = False
    s3_mft_verify_succeeds[obj.cms]
}

// Registry: MFTEntry.entry_hash, MFTPayload.file_list, RPKIObject.content_hash
pred conf_s3_mft_hash_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    some child: victim_pp.objects |
        (some e: obj.mft_payload.file_list |
            e.entry_uri = child.uri and e.entry_hash != child.content_hash)
        and s3_mft_hash_verified[obj, child]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
}

// --- S4 NI per-field ---

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

// --- S4 Conf per-field (UNSAT) ---

// Registry: CMSSignedData.signature_valid
pred conf_s4_crl_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    aki[obj] = victim_pp.owner.ca_ski
    obj.cms.signature_valid = False
    s4_crl_verify_succeeds[obj.cms]
}

// Registry: CRLPayload.crl_issuer, Certificate.subject_name
// Independent CRL issuer-DN obligation (name.c:142-193). A CRL whose issuer
// DN differs from the issuing CA cert's subject DN cannot also pass the
// equality check — UNSAT, demonstrating Fort enforces it.
pred conf_s4_crl_issuer_dn_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    some parent: Certificate |
        obj.crl_payload.crl_issuer != parent.subject_name and
        s4_crl_issuer_dn_verified[obj, parent]
}

// --- S5 NI per-field ---

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

// Registry: Certificate.issuer_ski, CA.ca_ski
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

// --- S5 Conf per-field (UNSAT) ---

// Registry: Certificate.ip_resources, Certificate.as_resources, Certificate.resources_inherit, Certificate.is_ca, CA.delegated_prefixes, CA.delegated_asns
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

// --- S6 NI per-field ---

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
// Malformed EE ipAddrBlocks are decoded by libcrypto/asn1c and rejected via
// pr_val_err (certificate.c:1133-1180 handle_ip_extension), RECOVERABLE; the
// shared-process F2 boundary still applies to any concurrent fatal.
pred ni_s6_parse_ip_resources_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        some atk_obj.cms.ee_certificate.ip_resources
    not s6_payload_error_contained[atk_pp, victim_pp]
}

// --- S6 Conf per-field (UNSAT) ---

// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
pred conf_s6_roa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.roa_payload.roa_prefixes |
        p in victim_pp.owner.delegated_prefixes
}

// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
pred conf_s6_aspa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s6_payload_verify_succeeds[obj.cms]
    obj.aspa_payload.customer_as in victim_pp.owner.delegated_asns
}

// Registry: CMSSignedData.signature_valid
pred conf_s6_roa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.signature_valid = False
    s6_payload_verify_succeeds[obj.cms]
}

// Registry: CMSSignedData.signature_valid
pred conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.signature_valid = False
    s6_payload_verify_succeeds[obj.cms]
}

// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
pred conf_s6_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    obj.cms.sid_matches_ee = False
    s6_payload_verify_succeeds[obj.cms]
}

// Registry: CMSSignedData.econtent_type_matches
pred conf_s6_cms_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    obj.cms.econtent_type_matches = False
    s6_payload_verify_succeeds[obj.cms]
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

// Registry: Certificate.ip_resources, Certificate.as_resources, Certificate.resources_inherit
// Independent EE-certificate containment obligation (separate from the payload
// checks above): the EE cert itself must not overclaim beyond the attacker
// CA's delegation (resource.c:135,434; eecert_init force_inherit=false).
pred conf_s6_ee_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    obj.cms.ee_certificate.resources_inherit = False
    some overclaimed_prefix: Prefix |
        overclaimed_prefix in obj.cms.ee_certificate.ip_resources and
        overclaimed_prefix not in atk_pp.owner.delegated_prefixes and
        overclaimed_prefix in victim_pp.owner.delegated_prefixes
    s6_ee_resource_check[obj, atk_pp.owner]
}

// =====================================================================
// Aggregated violation predicates (stage-level)
// Every per-field predicate above is OR'd into exactly one of these, and
// each of these flows into cross_pp_security (aggregate soundness).
// =====================================================================

pred ni_s2_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s2_fetch_scope_violation[atk_pp, victim_pp, obj] or
    ni_s2_fetch_cache_violation[atk_pp, victim_pp, obj] or
    ni_s2_cache_workspace_violation[atk_pp, victim_pp, obj]
}

pred ni_s3_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
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
    attack_context[atk_pp, victim_pp]
    conf_s3_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_econtent_type_violation[atk_pp, victim_pp, obj] or
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
    conf_s4_crl_issuer_dn_violation[atk_pp, victim_pp, obj]
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
    attack_context[atk_pp, victim_pp]
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
    conf_s6_roa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_cms_econtent_type_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_ee_resource_violation[atk_pp, victim_pp, obj]
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
assert s2_ni_fetch_cache { no a, v: PP, o: RPKIObject | ni_s2_fetch_cache_violation[a, v, o] }
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
assert s3_conf_cms_signature { no a, v: PP, o: RPKIObject | conf_s3_cms_signature_violation[a, v, o] }
assert s3_conf_cms_sid { no a, v: PP, o: RPKIObject | conf_s3_cms_sid_violation[a, v, o] }
assert s3_conf_cms_econtent_type { no a, v: PP, o: RPKIObject | conf_s3_cms_econtent_type_violation[a, v, o] }
assert s3_conf_mft_hash { no a, v: PP, o: RPKIObject | conf_s3_mft_hash_violation[a, v, o] }
assert s4_ni_crl_store_key { no a, v: PP, o: RPKIObject | ni_s4_crl_store_key_violation[a, v, o] }
assert s4_ni_crl_scope { no a, v: PP, o: RPKIObject | ni_s4_crl_scope_violation[a, v, o] }
assert s4_ni_parse_crl_this_update { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_this_update_violation[a, v, o] }
assert s4_ni_parse_crl_next_update { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_next_update_violation[a, v, o] }
assert s4_ni_parse_crl_revocation_date { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_revocation_date_violation[a, v, o] }
assert s4_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s4_parse_pubkey_violation[a, v, o] }
assert s4_conf_crl_signature { no a, v: PP, o: RPKIObject | conf_s4_crl_signature_violation[a, v, o] }
assert s4_conf_crl_issuer_dn { no a, v: PP, o: RPKIObject | conf_s4_crl_issuer_dn_violation[a, v, o] }
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
assert s6_conf_roa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_signature_violation[a, v, o] }
assert s6_conf_aspa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_signature_violation[a, v, o] }
assert s6_conf_cms_sid { no a, v: PP, o: RPKIObject | conf_s6_cms_sid_violation[a, v, o] }
assert s6_conf_cms_econtent_type { no a, v: PP, o: RPKIObject | conf_s6_cms_econtent_type_violation[a, v, o] }
assert s6_conf_roa_resource { no a, v: PP, o: RPKIObject | conf_s6_roa_resource_violation[a, v, o] }
assert s6_conf_aspa_resource { no a, v: PP, o: RPKIObject | conf_s6_aspa_resource_violation[a, v, o] }
assert s6_conf_ee_resource { no a, v: PP, o: RPKIObject | conf_s6_ee_resource_violation[a, v, o] }

// =====================================================================
// Stage aggregate assertions (the nine Table 2 obligations + cross_pp)
// =====================================================================

assert s2_ni { no a, v: PP, o: RPKIObject | ni_s2_violation[a, v, o] }
assert s3_ni { no a, v: PP, o: RPKIObject | ni_s3_violation[a, v, o] }
assert s3_conf { no a, v: PP, o: RPKIObject | conf_s3_violation[a, v, o] }
assert s4_ni { no a, v: PP, o: RPKIObject | ni_s4_violation[a, v, o] }
assert s4_conf { no a, v: PP, o: RPKIObject | conf_s4_violation[a, v, o] }
assert s5_ni { no a, v: PP, o: RPKIObject | ni_s5_violation[a, v, o] }
assert s5_conf { no a, v: PP, o: RPKIObject | conf_s5_violation[a, v, o] }
assert s6_ni { no a, v: PP, o: RPKIObject | ni_s6_violation[a, v, o] }
assert s6_conf { no a, v: PP, o: RPKIObject | conf_s6_violation[a, v, o] }
assert cross_pp_security { no a, v: PP, o: RPKIObject | any_violation[a, v, o] }

// =====================================================================
// Per-field checks — bounded model checking
// Every reachable sig carries an explicit Alloy 6.2.0 scope.
// =====================================================================

check s2_ni_fetch_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s2_ni_fetch_cache for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
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
check s3_conf_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_cms_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_mft_hash for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_crl_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_crl_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_this_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_next_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_revocation_date for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf_crl_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf_crl_issuer_dn for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
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
check s6_conf_roa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_cms_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_ee_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// =====================================================================
// Stage aggregate checks — bounded model checking
// =====================================================================

check s2_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check cross_pp_security for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// =====================================================================
// Assumption consistency — must be SAT or every check above is vacuous.
// =====================================================================

run model_satisfiable for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
