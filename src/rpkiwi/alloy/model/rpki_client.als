// rpki_client.als — rpki-client 9.7 validation pipeline, mechanized audit model.
//
// Derived from the paper's §4.3 design-decision review and a traced source
// review of vendor/rpki-client/src/rpki-client-9.7/src/, NOT from the known
// source review. A decision that preserves an obligation is a predicate that is always
// true under the attacker model; a decision that breaks one is a violation
// predicate satisfiable under the attacker model. The timegm source path is a
// source example of the C2 fatal-exit design decision, never the reason it exists.
//
// =====================================================================
// AUDIT DERIVATION  (paper §4.3 claim -> predicates -> source file:line)
// =====================================================================
//
// C1. Per-repository filesystem store isolation; OpenSSL-backed CMS
//     verification; strict RFC 3779 resource containment. PRESERVES Conf at
//     S3-S6 (every s*_conf obligation is UNSAT within scope).
//       store isolation  : s3_manifest_store_key, s3_manifest_lookup_key,
//                           s4_crl_store_key, s5_cert_store_key,
//                           s6_payload_store_key, s5_chain_walk_isolated
//                           repo.c:544 rrdp_filename; repo.c:912 repo_dir(..,1);
//                           repo.c:895 rrdp_get keyed by notifyuri;
//                           parser.c:116 find_issuer (repo-scoped certid)
//       CMS verification  : s3_mft_verify_succeeds, s6_payload_verify_succeeds
//                           cms.c:221 CMS_verify; cms.c:361 SID; cms.c:287 ctype
//       resource contain. : s5_cert_resource_check, s6_ee_resource_check,
//                           s6_roa_resource_check, s6_aspa_resource_check
//                           validate.c:87 valid_cert; x509.c:215 x509_inherits
//
// C2. One shared forked parser child gives memory isolation but not liveness
//     isolation: any fatal-exit (errx->exit(1)) in the child propagates through
//     IPC to the parent. BREAKS NI at S3, S4, S6 (those s*_ni obligations SAT).
//       primary          : parser_child_isolates_liveness
//                           main.c:982 fork; main.c:1207 one process_start;
//                           main.c:1377 POLLHUP; main.c:1390 hangup break;
//                           main.c:1532 errx("not all files processed")
//       reachable faults  : x509.c:306 timegm sentinel (ni_s3/s4/s6_parse_time,
//                           ni_s4_parse_crl_*); parser.c:400 EVP_Digest;
//                           x509.c pubkey (ni_*_parse_pubkey)
//
// C3. CA cert SIA extensions are only checked for intra-certificate consistency
//     (rpkiManifest under caRepository), never scoped to the issuing CA's
//     publication host; valid_origin() is used for RRDP/HTTP refs, not SIA.
//     BREAKS NI at S5 (s5_ni SAT).
//       primary          : s5_sia_parent_scope_enforced (the MISSING check),
//                           ni_s5_sia_scope_violation, ni_s5_sia_repo_scope_violation,
//                           ni_s5_sia_mft_scope_violation
//                           cert.c:766 rpkiNotify (https only, no origin check);
//                           cert.c:729 caRepository extracted unscoped;
//                           cert.c:812 strstr(mft,repo) intra-cert only;
//                           main.c:546 repo_lookup fetches named host
//
// Expected Table 2 row (printed column order
//   S2-NI, S3-Conf, S3-NI, S4-Conf, S4-NI, S5-Conf, S5-NI, S6-Conf, S6-NI):
//   (  .  ,   .    ,   X  ,   .    ,   X  ,   .    ,   X  ,   .    ,   X  )
// Model cells (S2-NI; S3/S4/S5/S6 Conf+NI): S3-NI, S4-NI, S5-NI, S6-NI = X;
// all Conf cells and S2-NI = '.'. There is no S2-Conf obligation (paper §4.2).
//
// rpki-client process architecture (C2 backbone):
//   main.c:1207 process_start("parser") — ONE fork()ed child parses every
//     object type (MFT/CRL/cert/ROA/ASPA) for every PP.
//   main.c:982/1061/1290 fork()+pledge()+unveil() isolate memory, not liveness.
//   errx() in the child -> exit(1) -> POLLHUP on the socketpair
//   main.c:1377-1378 parent sets hangup; main.c:1390-1391 breaks the loop
//   main.c:1532-1534 entity_queue != 0 -> errx(1,"not all files processed")
//   => ANY fatal parse error ends the whole run; all PPs lose their output.
//
module rpki_client

open topo
open util/boolean

// =====================================================================
// S2 RepositorySync — NOTIFICATION, SNAPSHOT, DELTA (ni only)
// =====================================================================

// C1 (supporting). rrdp_notification.c:228-230 snapshot URI and :274-276 delta
// URIs are validated by valid_origin(attr, nxml->notifyuri) (validate.c:274-290),
// a strict same-host check against the notification's own authority.
pred s2_fetch_scope_enforced[pp: PP, target_uri: URI] {
    target_uri.host = pp.notifyURI.host
}

// C1 (supporting). repo.c:891-931 rrdp_get(): RRDP repos are keyed by notifyuri
// (repo.c:895 strcmp(rr->notifyuri, uri)); repo.c:912 rr->basedir =
// repo_dir(uri, ".rrdp", 1) = .rrdp/<SHA256(notifyURI)> (repo.c:229-235 hash_dir,
// repo.c:242-272 repo_dir hash=1). Distinct notifyURI per PP (topo
// dedicated_publication_points) => distinct basedir => a per-PP workspace.
// Registry: PP.notifyURI
fun s2_cache_workspace[pp: PP]: URI {
    pp.notifyURI
}

pred s2_cache_workspace_isolated[pp1, pp2: PP] {
    s2_cache_workspace[pp1] != s2_cache_workspace[pp2]
}

// =====================================================================
// S3 ManifestProcessing — MFT (ni + conf)
// =====================================================================

// --- C1 (supporting): per-repository manifest store key ---

// repo.c:544-565 rrdp_filename(): path = rr->basedir + rsync_uri, and
// rr->basedir = .rrdp/<SHA256(notifyURI)> (repo.c:912). The store key is
// therefore (origin, uri): two objects from different PPs cannot collide even
// with the same rsync URI. No SKI/AKI-keyed global index exists.
// Registry: Certificate.subject_ski
fun s3_manifest_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// parser.c:116-140 find_issuer(): the manifest's issuer is resolved by certid
// (a repo-scoped entity id), then checked with strcmp(aki, a->cert->ski).
// No global SKI/AKI manifest index. Lookup key is (origin, uri).
// Registry: Certificate.issuer_ski
fun s3_manifest_lookup_key[mft: RPKIObject]: set univ {
    mft.origin + mft.uri
}

// --- NI: CMS structural checks (recoverable, not fatal) ---

// cms.c:234-237 sk_CMS_SignerInfo_num(sinfos) != 1 -> warnx + goto out (returns
// 0 over IPC, NOT errx). cms.c:40-50 zero-length eContent -> warnx + return 0.
// Recoverable: a shared fatal-exit boundary does not make this path fatal.
// Registry: CMSSignedData.signer_infos
pred s3_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// --- NI: time field parse safety (C2 reachable fault) ---

// x509.c:295-307 x509_get_time(): (*t = timegm(&tm)) == -1 -> errx(1,"timegm
// failed"). timegm() returns -1 for BOTH an error AND the legitimate time_t of
// 1969-12-31T23:59:59Z; rpki-client cannot disambiguate -> fatal on a valid
// date. Reached from cert.c:252/261 (notBefore/notAfter), cms.c:88 (signingTime),
// crl.c:262/272, and mft.c:313/317 via x509_get_generalized_time.
// Registry: Certificate.time_field_parse
pred s3_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// --- NI: combined parse success for an MFT ---

// All signed objects use the same cms_parse_validate() path (cms.c:178-385) in
// the shared parser child; mft.c parses thisUpdate/nextUpdate; x509 parses the
// EE pubkey. Any of these can errx -> process death.
// Registry: MFTPayload.mft_this_update_parse, MFTPayload.mft_next_update_parse, Certificate.pubkey_parse
pred s3_mft_parse_succeeds[obj: RPKIObject] {
    s3_cms_structure_ok[obj.cms]
    s3_time_field_safe[obj.cms]
    obj.mft_payload.mft_this_update_parse = ParseOK
    obj.mft_payload.mft_next_update_parse = ParseOK
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- C2 PRIMARY: shared parser child liveness (non-)isolation ---

// PAPER-CLAIM: C2 | predicates: parser_child_isolates_liveness, ni_s3_parse_time_violation, ni_s4_parse_crl_this_update_violation, ni_s6_parse_time_violation
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/main.c:1532
//
// One shared parser child (main.c:1207 process_start("parser")) parses every
// PP's objects. fork()+pledge()+unveil() (main.c:982/1061/1290) isolate MEMORY,
// not LIVENESS: errx(1,...) in the child -> exit(1) -> POLLHUP (main.c:1377) ->
// hangup break (main.c:1390) -> entity_queue != 0 -> errx(1,"not all files
// processed") in the parent (main.c:1532). The source path is the parser child's fatal-exit handling.
//
// A liveness boundary would require the attacker's and victim's objects to be
// parsed by DIFFERENT parser children; rpki-client forks exactly one, so the set
// of liveness-isolated PP pairs is EMPTY. "pp -> pp in none -> none" is false for
// every pair (the empty binary relation), encoding that no pair is isolated.
pred parser_child_isolates_liveness[source_pp, victim_pp: PP] {
    source_pp -> victim_pp in none -> none
}

// --- C1: CMS eContent binding (OpenSSL CMS_verify) ---

// PAPER-CLAIM: C1 | predicates: s3_mft_verify_succeeds, s6_payload_verify_succeeds, s3_manifest_store_key, s5_cert_resource_check
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/cms.c:221
//
// cms.c:218-221 CMS_verify(cms, NULL, NULL, bio, NULL, CMS_NO_SIGNER_CERT_VERIFY)
// does FULL CMS verification: H(eContent) == messageDigest AND the signature over
// DER(signedAttrs). cms.c:96-175 enforces exactly one messageDigest/contentType/
// signingTime attribute. cms.c:287-328 checks eContentType matches the signed
// contentType; cms.c:354 extracts the EE cert; cms.c:361-368 binds the SignerInfo
// SID to that EE cert (CMS_SignerInfo_cert_cmp != 0 -> reject).
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest, CMSSignedData.signature_valid, CMSSignedData.sid_matches_ee, CMSSignedData.econtent_type_matches, CMSSignedData.ee_certificate
pred s3_mft_verify_succeeds[cms: CMSSignedData] {
    cms.econtent_digest = cms.signed_attrs_digest
    cms.signature_valid = True
    cms.sid_matches_ee = True
    cms.econtent_type_matches = True
}

// --- C1: manifest hash binding ---

// parser.c:264-305 proc_parser_mft_check(): each file in the MFT fileList is
// opened and valid_filehash() compares its bytes to the entry hash. A child is
// accepted only if its uri matches an entry_uri and its content_hash matches the
// paired entry_hash.
// Registry: MFTPayload.file_list, MFTEntry.entry_uri, MFTEntry.entry_hash, RPKIObject.content_hash
pred s3_mft_hash_verified[mft: RPKIObject, child: RPKIObject] {
    some e: mft.mft_payload.file_list |
        e.entry_uri = child.uri and e.entry_hash = child.content_hash
}

// =====================================================================
// S4 RevocationProcessing — CRL (ni + conf)
// =====================================================================

// C1 (supporting). Same per-repo filesystem store as S3: CRL files live under
// rrdp_filename() = basedir + rsync_uri (repo.c:544-565). Key = (origin, uri).
// Registry: Certificate.issuer_ski
fun s4_crl_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// C1 (supporting). crl.c:289-313 crlcmp(): CRLs are keyed by the compound
// (aki, mftpath); crl.c:321-340 crl_get() looks a CRL up by (a->cert->ski,
// a->cert->mft) from the per-repo auth tree. There is NO global revoked-serial
// map, so an attacker CRL cannot revoke a victim cert cross-PP. Empty body =
// always isolated.
pred s4_crl_scope_isolated[pp1, pp2: PP] {
}

// --- NI: CRL parse safety (C2 reachable fault) ---

// crl.c:262/272 x509_get_time() for thisUpdate/nextUpdate -> same timegm errx
// (x509.c:306). Runs in the shared parser child.
// Registry: CRLPayload.crl_this_update_parse, CRLPayload.crl_next_update_parse, CRLPayload.crl_revocation_date_parse, Certificate.pubkey_parse
pred s4_crl_parse_succeeds[obj: RPKIObject] {
    obj.crl_payload.crl_this_update_parse = ParseOK
    obj.crl_payload.crl_next_update_parse = ParseOK
    obj.crl_payload.crl_revocation_date_parse = ParseOK
    obj.cms.ee_certificate.pubkey_parse = ParseOK
}

// --- C1: CRL signature verification ---

// validate.c:374-433 valid_x509(): X509_V_FLAG_CRL_CHECK (validate.c:401) +
// X509_verify_cert() (validate.c:416) verifies the full chain AND the CRL
// signature against the issuing CA's key. Requires signature_valid = True.
// Registry: CMSSignedData.signature_valid
pred s4_crl_verify_succeeds[cms: CMSSignedData] {
    cms.signature_valid = True
}

// --- C1: CRL issuer DN binding ---

// crl.c:232-236 x509_valid_issuer_name() validates the CRL issuer DN; the CRL is
// bound to the issuing CA cert through the verified chain (validate.c:401/416),
// so a CRL whose issuer DN does not match the issuing CA cert's subject DN is not
// applied. parser.c:347-350 additionally requires crl->aki == mft->aki.
// Registry: CRLPayload.crl_issuer, Certificate.subject_name
pred s4_crl_issuer_dn_verified[crl_obj: RPKIObject, parent_cert: Certificate] {
    crl_obj.crl_payload.crl_issuer = parent_cert.subject_name
}

// =====================================================================
// S5 CertChainProcessing — CA_CERT (ni + conf)
// =====================================================================

// C1 (supporting). Same per-repo filesystem store as S3/S4: key = (origin, uri).
// Registry: Certificate.subject_ski
fun s5_cert_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// C1 (supporting). rpki-client builds the chain from per-repo filesystem paths
// and the per-repo auth tree (parser.c:633 auth_insert, parser.c:116 find_issuer
// by repo-scoped certid), not a global SKI index. validate.c:87 valid_cert()
// takes struct auth *a from that per-repo tree. Empty body = always isolated.
// Registry: Certificate.issuer_ski
pred s5_chain_walk_isolated[pp1, pp2: PP] {
}

// C1 (supporting). parser.c:116-140 find_issuer(): strcmp(aki, a->cert->ski) ties
// the object's AKI to the issuing CA's SKI (CA.ca_ski); base.als
// attacker_signature_capability forbids forging a victim-key signature, so an
// attacker cannot bind a victim CA as issuer. parser.c:329-333 crl_get keys on
// the same auth SKI.
// Registry: CA.ca_ski
pred s5_issuer_key_binding[obj: RPKIObject, issuing_ca: CA] {
    aki[obj] = issuing_ca.ca_ski
}

// --- C3 PRIMARY: CA cert SIA scope ---

// PAPER-CLAIM: C3 | predicates: s5_sia_parent_scope_enforced, ni_s5_sia_scope_violation, ni_s5_sia_repo_scope_violation, ni_s5_sia_mft_scope_violation
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/cert.c:812
//
// What cert_ca_sia (cert.c:697-830) ACTUALLY checks on a CA cert's SIA:
//   rpkiNotify  (cert.c:766-782): only that the scheme is https. No host compare.
//   caRepository(cert.c:726-748): copied into cert->repo. No host compare.
//   rpkiManifest(cert.c:812-814): strstr(cert->mft, cert->repo) == cert->mft &&
//     cert->mft + strlen(cert->repo) == mftfilename — an INTRA-certificate
//     consistency check (manifest directly under THIS cert's caRepository). It
//     does NOT bind caRepository/rpkiNotify to the issuing (parent) CA.
// valid_origin() (validate.c:274-290) IS called, but only for RRDP snapshot/delta
// refs vs the notification's own notifyuri (rrdp_notification.c:230/276) and for
// HTTP redirects (http.c:1441) — never for a CA cert's SIA against its issuer.
// queue_add_from_cert (main.c:513-578, :546 repo_lookup) then fetches from
// whatever host the SIA names. So an attacker child-CA cert can point
// caRepository/rpkiManifest/rpkiNotify at the victim's host -> cross-PP redirect.

// The intra-certificate consistency rpki-client enforces (cert.c:812-814):
// rpkiManifest sits under caRepository, hence shares its host.
pred s5_sia_internal_consistency[cert: Certificate] {
    (some cert.sia_mft_uri and some cert.sia_repo_uri) implies
        cert.sia_mft_uri.host = cert.sia_repo_uri.host
}

// The parent-origin scope rpki-client is MISSING: it would require the CA cert's
// caRepository/rpkiManifest/rpkiNotify to resolve under the issuing CA's own
// publication host. No such check exists; violation predicates do not assume it.
pred s5_sia_parent_scope_enforced[cert: Certificate, parent_pp: PP] {
    (some cert.sia_repo_uri) implies cert.sia_repo_uri.host = parent_pp.siaBase.host
    (some cert.sia_mft_uri) implies cert.sia_mft_uri.host = parent_pp.siaBase.host
    (some cert.sia_notify_uri) implies cert.sia_notify_uri.host = parent_pp.notifyURI.host
}

// --- C1: resource delegation containment ---

// validate.c:87-124 valid_cert(): for each non-inherit AS/IP resource, valid_as
// (validate.c:40) / valid_ip (validate.c:66) require strict RFC 3779 containment
// in the issuing authority (as_check_covered / ip_addr_check_covered); an
// inherit marker (CERT_AS_INHERIT / CERT_IP_INHERIT, validate.c:88-90/111-113;
// x509.c:215 x509_inherits) walks up to the parent. Overclaim -> reject.
// Registry: Certificate.ip_resources, Certificate.as_resources, Certificate.resources_inherit, CA.delegated_prefixes, CA.delegated_asns
pred s5_cert_resource_check[obj: RPKIObject, issuing_ca: CA] {
    {
        obj.cms.ee_certificate.resources_inherit = True
    } or {
        obj.cms.ee_certificate.ip_resources in issuing_ca.delegated_prefixes
        obj.cms.ee_certificate.as_resources in issuing_ca.delegated_asns
    }
}

// --- C1: basicConstraints cA flag ---

// cert.c:44-137 cert_check_purpose(): X509_check_ca + critical basicConstraints
// decide CERT_PURPOSE_CA; only CA-purpose certs are added to the auth tree
// (parser.c:625-633) and used as issuers in the chain walk.
// Registry: Certificate.is_ca
pred s5_is_ca_checked[obj: RPKIObject] {
    obj.cms.ee_certificate.is_ca = True
}

// =====================================================================
// S6 PayloadProcessing — ROA, ASPA (ni + conf)
// =====================================================================

// C1 (supporting). Same per-repo filesystem store as S3/S4/S5: key = (origin, uri).
// Registry: Certificate.subject_ski
fun s6_payload_store_key[obj: RPKIObject]: set univ {
    obj.origin + obj.uri
}

// NI: same recoverable CMS structural checks as S3 (cms.c:234/40).
// Registry: CMSSignedData.signer_infos
pred s6_cms_structure_ok[cms: CMSSignedData] {
    one cms.signer_infos
    some cms.econtent_digest
}

// NI: same x509.c:306 timegm fatal path for the ROA/ASPA EE cert.
// Registry: Certificate.time_field_parse
pred s6_time_field_safe[cms: CMSSignedData] {
    cms.ee_certificate.time_field_parse = ParseOK
}

// NI: combined ROA/ASPA parse in the shared parser child.
// Registry: Certificate.pubkey_parse
pred s6_payload_parse_succeeds[cms: CMSSignedData] {
    s6_cms_structure_ok[cms]
    s6_time_field_safe[cms]
    cms.ee_certificate.pubkey_parse = ParseOK
}

// --- C1: CMS eContent binding (same OpenSSL path as S3) ---

// PAPER-CLAIM: C1 (supporting) | predicates: s6_payload_verify_succeeds
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/cms.c:221
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest, CMSSignedData.signature_valid, CMSSignedData.sid_matches_ee, CMSSignedData.econtent_type_matches, CMSSignedData.ee_certificate
pred s6_payload_verify_succeeds[cms: CMSSignedData] {
    cms.econtent_digest = cms.signed_attrs_digest
    cms.signature_valid = True
    cms.sid_matches_ee = True
    cms.econtent_type_matches = True
}

// --- C1: ROA/ASPA resource certification ---

// validate.c:130-148 valid_roa(): ROA prefixes within the EE cert IP resources.
// Registry: ROAPayload.roa_prefixes, Certificate.ip_resources
pred s6_roa_resource_check[obj: RPKIObject] {
    obj.roa_payload.roa_prefixes in obj.cms.ee_certificate.ip_resources
}

// validate.c:509-520 valid_aspa(): ASPA customerASID within the EE cert AS set.
// Registry: ASPAPayload.customer_as, Certificate.as_resources
pred s6_aspa_resource_check[obj: RPKIObject] {
    obj.aspa_payload.customer_as in obj.cms.ee_certificate.as_resources
}

// EE cert -> issuing CA delegation (same valid_cert path as S5; inherit walk-up).
// Registry: Certificate.ip_resources, Certificate.as_resources, Certificate.resources_inherit, CA.ca_ski
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
// =====================================================================

// --- S2: RepositorySync per-field (C1 supporting; both UNSAT) ---

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

// Registry: Certificate.issuer_ski
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
// C2: the shared parser child has no liveness isolation. Missing/multiple
// SignerInfos is kept as a parser-failure candidate; cms.c:234-237's
// warnx+goto path is recorded as the source-level guard.
pred ni_s3_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        not (one atk_obj.cms.signer_infos)
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// PAPER-CLAIM: C2 (supporting)
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/x509.c:306
// Registry: Certificate.time_field_parse
pred ni_s3_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.cms.ee_certificate.time_field_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: MFTPayload.mft_this_update_parse
pred ni_s3_parse_mft_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.mft_payload.mft_this_update_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: MFTPayload.mft_next_update_parse
pred ni_s3_parse_mft_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.mft_payload.mft_next_update_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: Certificate.pubkey_parse
pred ni_s3_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        atk_obj.cms.ee_certificate.pubkey_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: MFTEntry.entry_uri
// mft.c validates each fileList filename via valid_filename() before use; the
// path itself is not a fatal boundary, so the filename path stays contained.
pred ni_s3_parse_mft_filename_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        some e: atk_obj.mft_payload.file_list | e.entry_uri.host != atk_pp.siaBase.host
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// --- S3 Conf per-field (C1; all UNSAT) ---

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

// Independent CMS signature obligation (deletion-test for signature_valid).
// Registry: CMSSignedData.signature_valid
pred conf_s3_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.signature_valid = False
    s3_mft_verify_succeeds[obj.cms]
}

// Independent SID obligation (cms.c:361-368 CMS_SignerInfo_cert_cmp).
// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
pred conf_s3_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.sid_matches_ee = False
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
}

// Independent eContentType obligation (cms.c:287-328).
// Registry: CMSSignedData.econtent_type_matches
pred conf_s3_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_type_matches = False
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
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

// PAPER-CLAIM: C2 (supporting)
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/crl.c:262
// Registry: CRLPayload.crl_this_update_parse
pred ni_s4_parse_crl_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.crl_payload.crl_this_update_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: CRLPayload.crl_next_update_parse
pred ni_s4_parse_crl_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.crl_payload.crl_next_update_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: CRLPayload.crl_revocation_date_parse
pred ni_s4_parse_crl_revocation_date_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.crl_payload.crl_revocation_date_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: Certificate.pubkey_parse
pred ni_s4_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        atk_crl.cms.ee_certificate.pubkey_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// --- S4 Conf per-field (C1; all UNSAT) ---

// Registry: CMSSignedData.signature_valid
pred conf_s4_crl_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    aki[obj] = victim_pp.owner.ca_ski
    obj.cms.signature_valid = False
    s4_crl_verify_succeeds[obj.cms]
}

// CRL issuer-DN binding: even with a forged victim issuer DN and AKI, a CRL that
// is not validly signed under the victim CA is rejected (deletion-test for the
// signature/chain gate that carries the DN binding).
// Registry: CRLPayload.crl_issuer, Certificate.subject_name
pred conf_s4_crl_issuer_dn_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    aki[obj] = victim_pp.owner.ca_ski
    some vcert: RPKIObject |
        vcert.origin = victim_pp and vcert.obj_type = OT_CA_CERT and
        s4_crl_issuer_dn_verified[obj, vcert.cms.ee_certificate]
    s4_crl_verify_succeeds[obj.cms]
    obj.cms.signature_valid = False
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

// Registry: Certificate.issuer_ski
pred ni_s5_chain_walk_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    not s5_chain_walk_isolated[atk_pp, victim_pp]
}

// PAPER-CLAIM: C3 (supporting)
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/cert.c:766
// rpkiNotify redirect: attacker child-CA cert points rpkiNotify at the victim's
// RRDP host; rpki-client checks only the https scheme (cert.c:766-782), never the
// parent origin -> reachable.
// Registry: Certificate.sia_notify_uri
pred ni_s5_sia_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    some obj.cms.ee_certificate.sia_notify_uri
    obj.cms.ee_certificate.sia_notify_uri.host = victim_pp.notifyURI.host
    not s5_sia_parent_scope_enforced[obj.cms.ee_certificate, atk_pp]
}

// PAPER-CLAIM: C3 (supporting)
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/cert.c:729
// caRepository redirect: the only check (cert.c:812 intra-cert consistency) still
// passes while caRepository points at the victim's host.
// Registry: Certificate.sia_repo_uri
pred ni_s5_sia_repo_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    some obj.cms.ee_certificate.sia_repo_uri
    obj.cms.ee_certificate.sia_repo_uri.host = victim_pp.siaBase.host
    s5_sia_internal_consistency[obj.cms.ee_certificate]
    not s5_sia_parent_scope_enforced[obj.cms.ee_certificate, atk_pp]
}

// PAPER-CLAIM: C3 (supporting)
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/cert.c:812
// rpkiManifest redirect: strstr(mft,repo) consistency holds with both under the
// victim host; no parent-origin scope -> reachable.
// Registry: Certificate.sia_mft_uri
pred ni_s5_sia_mft_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    some obj.cms.ee_certificate.sia_mft_uri
    obj.cms.ee_certificate.sia_mft_uri.host = victim_pp.siaBase.host
    s5_sia_internal_consistency[obj.cms.ee_certificate]
    not s5_sia_parent_scope_enforced[obj.cms.ee_certificate, atk_pp]
}

// --- S5 Conf per-field (C1; all UNSAT) ---

// Registry: Certificate.ip_resources, Certificate.as_resources, CA.delegated_prefixes, CA.delegated_asns
pred conf_s5_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    s5_is_ca_checked[obj]
    s5_issuer_key_binding[obj, atk_pp.owner]
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

// basicConstraints obligation: a non-CA cert (cA=false) cannot be used to
// delegate resources (deletion-test for s5_is_ca_checked).
// Registry: Certificate.is_ca
pred conf_s5_is_ca_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    obj.cms.ee_certificate.is_ca = False
    s5_is_ca_checked[obj]
    some overclaimed_prefix: Prefix |
        overclaimed_prefix in obj.cms.ee_certificate.ip_resources and
        overclaimed_prefix in victim_pp.owner.delegated_prefixes
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
// C2: the shared parser child has no liveness isolation; missing/multiple
// SignerInfos is kept as a parser-failure candidate for ROA/ASPA.
pred ni_s6_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        not (one atk_obj.cms.signer_infos)
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// PAPER-CLAIM: C2 (supporting)
// SOURCE: vendor/rpki-client/src/rpki-client-9.7/src/x509.c:306
// Registry: Certificate.time_field_parse
pred ni_s6_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        atk_obj.cms.ee_certificate.time_field_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: Certificate.pubkey_parse
pred ni_s6_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        atk_obj.cms.ee_certificate.pubkey_parse = ParseFatal
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// Registry: Certificate.ip_resources
// ip.c:79-97 ip_addr_check_covered uses parsed prefix lengths; rpki-client
// rejects malformed resources (recoverable) rather than aborting.
pred ni_s6_parse_ip_resources_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        some atk_obj.cms.ee_certificate.ip_resources
    not parser_child_isolates_liveness[atk_pp, victim_pp]
}

// --- S6 Conf per-field (C1; all UNSAT) ---

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

// Independent CMS signature obligations (deletion-test for signature_valid).
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

// Independent SID obligation at S6 (cms.c:361-368).
// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
pred conf_s6_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    obj.cms.sid_matches_ee = False
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
}

// Independent eContentType obligation at S6 (cms.c:287-328).
// Registry: CMSSignedData.econtent_type_matches
pred conf_s6_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    obj.cms.econtent_type_matches = False
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
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
// Every per-field violation is OR'd into its stage aggregate, and every stage
// aggregate into cross_pp_security — so a SAT per-field check always implies its
// stage aggregate and cross_pp_security are SAT (aggregate soundness).
// =====================================================================

pred ni_s2_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s2_fetch_scope_violation[atk_pp, victim_pp, obj] or
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
    conf_s3_sid_violation[atk_pp, victim_pp, obj] or
    conf_s3_econtent_type_violation[atk_pp, victim_pp, obj] or
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
    conf_s5_resource_violation[atk_pp, victim_pp, obj] or
    conf_s5_is_ca_violation[atk_pp, victim_pp, obj]
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
    conf_s6_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_econtent_type_violation[atk_pp, victim_pp, obj] or
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
assert s3_conf_cms_signature { no a, v: PP, o: RPKIObject | conf_s3_cms_signature_violation[a, v, o] }
assert s3_conf_sid { no a, v: PP, o: RPKIObject | conf_s3_sid_violation[a, v, o] }
assert s3_conf_econtent_type { no a, v: PP, o: RPKIObject | conf_s3_econtent_type_violation[a, v, o] }
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
assert s5_conf_is_ca { no a, v: PP, o: RPKIObject | conf_s5_is_ca_violation[a, v, o] }
assert s6_ni_store_key { no a, v: PP, o: RPKIObject | ni_s6_store_key_violation[a, v, o] }
assert s6_ni_parse_signerinfos { no a, v: PP, o: RPKIObject | ni_s6_parse_signerinfos_violation[a, v, o] }
assert s6_ni_parse_time { no a, v: PP, o: RPKIObject | ni_s6_parse_time_violation[a, v, o] }
assert s6_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s6_parse_pubkey_violation[a, v, o] }
assert s6_ni_parse_ip_resources { no a, v: PP, o: RPKIObject | ni_s6_parse_ip_resources_violation[a, v, o] }
assert s6_conf_roa_cms_digest { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_digest_violation[a, v, o] }
assert s6_conf_aspa_cms_digest { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_digest_violation[a, v, o] }
assert s6_conf_roa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_signature_violation[a, v, o] }
assert s6_conf_aspa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_signature_violation[a, v, o] }
assert s6_conf_sid { no a, v: PP, o: RPKIObject | conf_s6_sid_violation[a, v, o] }
assert s6_conf_econtent_type { no a, v: PP, o: RPKIObject | conf_s6_econtent_type_violation[a, v, o] }
assert s6_conf_roa_resource { no a, v: PP, o: RPKIObject | conf_s6_roa_resource_violation[a, v, o] }
assert s6_conf_aspa_resource { no a, v: PP, o: RPKIObject | conf_s6_aspa_resource_violation[a, v, o] }

// =====================================================================
// Aggregate (Table 2) assertions
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
// Every reachable sig is scoped (Alloy 6.2.0 rejects any unscoped sig).
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
check s3_conf_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
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
check s5_conf_is_ca for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_signerinfos for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_time for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_ip_resources for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
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

run model_satisfiable for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
