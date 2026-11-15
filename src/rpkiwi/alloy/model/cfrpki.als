// cfrpki.als - OctoRPKI (Cloudflare) validation pipeline audit model.
//
// Faithful mechanization of the paper's section 4.3 source-code review of
// OctoRPKI 1.5.10 (vendor/cfrpki/src, tag v1.5.10-3-g94ee106). Each predicate
// traces to a design decision at a cited source location; no predicate exists
// only because an observed exploit exists. The nine Table 2 obligations are S2-NI plus the
// Conf+NI pair of S3-S6 (there is NO S2-Conf obligation: section 4.2 enforces
// confinement downstream of S2; there IS an S6-Conf obligation).
//
// =====================================================================
// AUDIT DERIVATION - paper claim -> predicate(s) -> source (file:line)
// =====================================================================
//
// O1. One global Validator struct holds the object cache, manifest index,
//     parent-certificate map and revocation set in Go maps keyed by SKI/AKI,
//     with no per-origin partitioning. Breaks NI at S2-S6.
//       predicates: ni_s2_fetch_scope_violation, ni_s2_cache_workspace_violation,
//         ni_s3_store_key_violation, ni_s3_manifest_lookup_violation,
//         ni_s4_crl_store_key_violation, ni_s4_crl_scope_violation,
//         ni_s5_chain_walk_violation,
//         ni_s5_sia_scope_violation, ni_s5_sia_repo_scope_violation,
//         ni_s5_sia_mft_scope_violation, ni_s6_store_key_violation
//       source: validator/pki/pki.go:190-218 (Validator struct), :459,:461
//         (ValidObjects/Objects[ski]), :478-479 (parent by aki), :577,:579
//         (ROA[ski]), :623,:625 (Manifest[ski]), :201,:670,:681 (Revoked/
//         ValidCRL[aki]); cmd/octorpki/octorpki.go:355,:361,:1098-1104.
//
// O2. The traversal loop lacks a recover() wrapper; any panic in the parsing
//     chain terminates the process. Breaks NI at S3, S4, S6 (shared maps at
//     S2/S5). OctoRPKI's only reachable parse panic is the empty-SignerInfos
//     index access in CMS.Validate; Go's asn1/x509/time decoders return errors.
//       predicates: ni_s3_parse_signerinfos_violation,
//         ni_s6_parse_signerinfos_violation (containment: s3_mft_error_contained,
//         s6_payload_error_contained; reachability: signerinfos_can_crash)
//       source: validator/lib/cms.go:333 (SignerInfos[0].SignedAttrs, no len),
//         :370,:420; validator/pki/pki.go:850-921 (Explore, no recover);
//         reached from validator/lib/manifest.go:122, validator/lib/roa.go:323.
//
// O3. CMS digest binding and CRL signature checks keep confinement intact at
//     S3-S6 (RFC 6487 7.2 / RFC 3779 resource containment is enforced too).
//       predicates: conf_s3_cms_digest_violation, conf_s3_cms_signature_violation,
//         conf_s3_cms_sid_violation, conf_s3_cms_econtent_type_violation,
//         conf_s3_mft_hash_violation, conf_s4_crl_signature_violation,
//         conf_s4_crl_issuer_violation, conf_s5_resource_violation,
//         conf_s5_resources_inherit_violation, conf_s5_is_ca_violation,
//         conf_s6_roa_cms_digest_violation, conf_s6_aspa_cms_digest_violation,
//         conf_s6_roa_cms_signature_violation, conf_s6_aspa_cms_signature_violation,
//         conf_s6_roa_resource_violation, conf_s6_aspa_resource_violation,
//         conf_s6_ee_resource_violation, conf_s6_roa_sid_violation,
//         conf_s6_roa_econtent_type_violation
//       source: validator/lib/cms.go:347 (H(eContent)==messageDigest), :374
//         (signedAttrs signature), :365 (RSA key); validator/pki/pki.go:666
//         (CheckCRLSignature), :500-545 (RFC 3779 containment); validator/lib/
//         cert.go:467,:507,:556; validator/lib/roa.go:214.
//
// Expected Table 2 row (S2-NI, S3-Conf, S3-NI, S4-Conf, S4-NI, S5-Conf, S5-NI,
//   S6-Conf, S6-NI): (X, ., X, ., X, ., X, ., X).
// Every NI obligation is a SAT candidate (O1 shared maps + O2 panic); every
// Conf obligation is UNSAT (O3). The model also checks S6-Conf.
// Alloy 6.2.0 - bounded relational model checking.
module cfrpki

open topo
open util/boolean

// =====================================================================
// Reachability of parse crashes
//
// Go's standard library returns errors, not panics.  The single panic site
// modeled here is the unchecked SignerInfos[0] access in CMS.Validate.  A
// can_crash predicate records a source-level panic condition; a SOURCE-FACT
// marks a source guard that prevents that condition.
// =====================================================================

// PAPER-CLAIM: O2 | predicates: ni_s3_parse_signerinfos_violation, ni_s6_parse_signerinfos_violation
// SOURCE: validator/lib/cms.go:333
// Source path: CMS.Validate indexes SignerInfos[0].SignedAttrs with no length
// check (cms.go:333; also :370 Signature, :420 GetSigningTime). An empty
// SignerInfos set panics before any cryptographic check; Explore has no recover.
pred signerinfos_can_crash[cms: CMSSignedData] { some cms }

// SOURCE-FACT: ValidateTime (cert.go:563-573) compares already-parsed time
// values; x509 time parsing returns errors. SOURCE: validator/lib/cert.go:563
pred time_parse_can_crash[cms: CMSSignedData] { some cms }

// SOURCE-FACT: the RSA key assertion is guarded by an ok flag. SOURCE: validator/lib/cms.go:365
pred pubkey_parse_can_crash[cms: CMSSignedData] { some cms }

// SOURCE-FACT: asn1.Unmarshal returns an error on malformed MFT dates. SOURCE: validator/lib/manifest.go:106
pred mft_time_parse_can_crash[payload: MFTPayload] { some payload }

// SOURCE-FACT: x509.ParseDERCRL returns an error; the CRL path does not reach CMS.Validate.
// SOURCE: validator/pki/pki.go:354
pred crl_time_parse_can_crash[payload: CRLPayload] { some payload }

// SOURCE-FACT: ExtractPathManifest rejects "../" and returns an error.
// SOURCE: validator/pki/pki.go:755
pred filename_parse_can_crash[payload: MFTPayload] { some payload }

// O2: no recover() around the resource parse; RFC 3779 ipAddrBlocks is decoded via asn1.Unmarshal (no fixed-index
// child access as in rpstir2). SOURCE: validator/lib/cert.go:300
pred ip_resources_parse_can_crash[cms: CMSSignedData] { some cms }

// =====================================================================
// S2 RepositorySync - NOTIFICATION, SNAPSHOT, DELTA (NI only)
// =====================================================================

// PAPER-CLAIM: O1 (supporting)
// SOURCE: cmd/octorpki/octorpki.go:355
// Registry: RPKIObject.uri, PP.notifyURI
// RRDP callback guards the write path with strings.Contains(path, rsync) - a
// substring test, not an authority comparison, and skipped when len(args)==0
// (octorpki.go:353-355). An attacker RRDP document whose URI collides with the
// victim's passes this weak guard.
pred ni_s2_fetch_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_SNAPSHOT + OT_DELTA + OT_NOTIFICATION)
    some atk_obj: RPKIObject | atk_obj.origin = atk_pp and atk_obj.uri = obj.uri
}

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:190
// Registry: PP.siaBase, RPKIObject.content_hash, RPKIObject.uri
// OctoRPKI writes every fetched object into one on-disk cache via a single
// Validator (pki.go:190-218; WriteRsyncFileOnDisk octorpki.go:361) with no
// per-PP workspace. An attacker object sharing the victim's cache path (URI)
// overwrites the victim's cached bytes.
pred ni_s2_cache_workspace_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.uri = obj.uri and
        atk_obj.content_hash != obj.content_hash
}

// =====================================================================
// S3 ManifestProcessing - MFT (NI + Conf)
// =====================================================================

// ValidObjects/Objects/ValidManifest are keyed by SubjectKeyId (pki.go:427,459,
// 461,623) with no PP dimension.
fun s3_manifest_store_key[obj: RPKIObject]: KeyId { obj.cms.ee_certificate.subject_ski }

// CMS digest+signature gate (the gate OctoRPKI actually runs at manifest.go:122).
// cms.go:347 H(eContent)==messageDigest; cms.go:374 signedAttrs signature.
pred s3_mft_verify_succeeds[cms: CMSSignedData] {
    cms.econtent_digest = cms.signed_attrs_digest
    cms.signature_valid = True
}

// Manifest hash binding: ExtractPathManifest (pki.go:748-766) + Explore hash
// check (pki.go:867-888) match a child by filename and compare content_hash.
pred s3_mft_hash_verified[mft: RPKIObject, child: RPKIObject] {
    some e: mft.mft_payload.file_list |
        e.entry_uri = child.uri and e.entry_hash = child.content_hash
}

// A panic (empty SignerInfos) is NOT contained: Explore (pki.go:850-921) has no
// recover(). A returned Go error IS contained. SOURCE: validator/pki/pki.go:850
pred s3_mft_error_contained[atk_obj: RPKIObject] { not signerinfos_can_crash[atk_obj.cms] }

// --- S3 NI per-field ---

// PAPER-CLAIM: O1 | predicates: ni_s3_store_key_violation, ni_s3_manifest_lookup_violation, ni_s4_crl_store_key_violation, ni_s4_crl_scope_violation, ni_s5_chain_walk_violation, ni_s6_store_key_violation, ni_s2_cache_workspace_violation
// SOURCE: validator/pki/pki.go:459
// Registry: Certificate.subject_ski
// Global ValidObjects/Objects[ski] (pki.go:459,461): an attacker MFT whose EE
// subject_ski equals the victim MFT's collides in the shared map.
pred ni_s3_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        s3_manifest_store_key[atk_obj] = s3_manifest_store_key[obj]
}

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:623
// Registry: Certificate.subject_ski
// ValidManifest[ski] (pki.go:621-623) is global; an SKI collision lets the
// attacker's manifest share the victim's lookup slot.
pred ni_s3_manifest_lookup_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some atk_mft: RPKIObject |
        atk_mft.origin = atk_pp and atk_mft.obj_type = OT_MFT and
        s3_manifest_store_key[atk_mft] = s3_manifest_store_key[obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/cms.go:333
// Registry: CMSSignedData.signer_infos
// Empty SignerInfos -> cms.go:333 index panic (reached via manifest.go:122) ->
// no recover() in Explore -> process dies, dropping all origins' VRPs.
pred ni_s3_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        signerinfos_can_crash[atk_obj.cms] and not s3_mft_error_contained[atk_obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/cert.go:563
// Registry: Certificate.time_field_parse
// O2: Explore has no recover(); a panic on this parse path is process-wide. The model keeps the candidate; the x509 error path is recorded as a guard.
pred ni_s3_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        time_parse_can_crash[atk_obj.cms] and not s3_mft_error_contained[atk_obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/manifest.go:106
// Registry: MFTPayload.mft_this_update_parse
// O2: no recover() around the parse; the model keeps the malformed-date candidate; asn1.Unmarshal normally returns an error.
pred ni_s3_parse_mft_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        mft_time_parse_can_crash[atk_obj.mft_payload]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/manifest.go:106
// Registry: MFTPayload.mft_next_update_parse
// O2: no recover() around the parse; the model keeps the malformed-date candidate; asn1.Unmarshal normally returns an error.
pred ni_s3_parse_mft_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        mft_time_parse_can_crash[atk_obj.mft_payload]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/cms.go:365
// Registry: Certificate.pubkey_parse
// O2: no recover() around the parse; the model keeps the key-parse candidate; the RSA assertion is guarded by an ok flag.
pred ni_s3_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        pubkey_parse_can_crash[atk_obj.cms] and not s3_mft_error_contained[atk_obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/pki/pki.go:755
// Registry: MFTEntry.entry_uri
// O2: the filename path is unwrapped/uncontained; ExtractPathManifest rejects "../" and returns an error,
// so a malformed manifest filename does not cross the origin boundary.
pred ni_s3_parse_mft_filename_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type = OT_MFT and
        (some e: atk_obj.mft_payload.file_list | e.entry_uri.host != atk_pp.siaBase.host) and
        filename_parse_can_crash[atk_obj.mft_payload]
}

// --- S3 Conf per-field (O3: all UNSAT) ---

// PAPER-CLAIM: O3 | predicates: conf_s3_cms_digest_violation, conf_s6_roa_cms_digest_violation, conf_s6_aspa_cms_digest_violation
// SOURCE: validator/lib/cms.go:347
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest, CMSSignedData.signature_valid
// cms.go:347 rejects H(eContent) != messageDigest, so no accepted MFT can carry
// a mismatched digest (UNSAT).
pred conf_s3_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources | p in victim_pp.owner.delegated_prefixes
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:374
// Registry: CMSSignedData.signature_valid
// cms.go:370-376 verifies the signedAttributes signature (UNSAT when False).
pred conf_s3_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.signature_valid = False
    s3_mft_verify_succeeds[obj.cms]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:332
// Registry: CMSSignedData.sid_matches_ee, CMSSignedData.ee_certificate
// OctoRPKI does NOT compare the SignerIdentifier to the EE cert (cms.go:332-379
// has no SID check). The omission is INERT for confinement: the signature is
// verified against the embedded EE cert and RFC 3779 containment (pki.go:500-545)
// still blocks victim-resource attribution, so no accepted MFT with a mismatched
// SID can carry victim resources (UNSAT).
pred conf_s3_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.sid_matches_ee = False
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources | p in victim_pp.owner.delegated_prefixes
    s5_cert_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:332
// Registry: CMSSignedData.econtent_type_matches
// OctoRPKI does NOT compare the eContentType OID (cms.go:332-379). INERT:
// digest+signature bind the content and RFC 3779 containment blocks victim
// overclaim, so the omission yields no cross-PP confinement effect (UNSAT).
pred conf_s3_cms_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_type_matches = False
    s3_mft_verify_succeeds[obj.cms]
    some p: obj.cms.ee_certificate.ip_resources | p in victim_pp.owner.delegated_prefixes
    s5_cert_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/pki/pki.go:884
// Registry: MFTEntry.entry_hash, MFTPayload.file_list, RPKIObject.content_hash
// StrictHash compares the fetched file's SHA-256 to the manifest entry hash
// (pki.go:867-888); unique_mft_entry_uri makes hash-match and hash-mismatch
// mutually exclusive on a child, so an accepted hash mismatch is UNSAT.
pred conf_s3_mft_hash_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    some child: victim_pp.objects |
        (some e: obj.mft_payload.file_list |
            e.entry_uri = child.uri and e.entry_hash != child.content_hash)
        and s3_mft_hash_verified[obj, child]
    some p: obj.cms.ee_certificate.ip_resources | p in victim_pp.owner.delegated_prefixes
}

// =====================================================================
// S4 RevocationProcessing - CRL (NI + Conf)
// =====================================================================

// ValidCRL/CRL/Revoked keyed by AKI (pki.go:670,681,201); Revoked key is
// string(aki)+serial (pki.go:494,672). No PP dimension.
fun s4_crl_store_key[obj: RPKIObject]: KeyId { obj.cms.ee_certificate.issuer_ski }

// CRL signature gate (the gate OctoRPKI actually runs). pki.go:666 CheckCRLSignature.
pred s4_crl_verify_succeeds[cms: CMSSignedData] { cms.signature_valid = True }

// OctoRPKI revokes a cert iff the CRL's AKI equals the cert's AKI (Revoked key
// string(aki)+serial, pki.go:494 lookup vs pki.go:672 insert).
pred s4_cert_revoked_by[crl_obj: RPKIObject, cert: Certificate] {
    cert.serial_number in crl_obj.crl_payload.revoked_serials
    aki[crl_obj] = cert.issuer_ski
}

// --- S4 NI per-field ---

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:670
// Registry: Certificate.issuer_ski, CA.ca_ski
// ValidCRL[aki]/CRL[aki] (pki.go:670,686) are global; a CRL whose AKI equals a
// victim object's collides in the shared map.
pred ni_s4_crl_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        s4_crl_store_key[atk_crl] = obj.cms.ee_certificate.issuer_ski
}

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:201
// Registry: CRLPayload.revoked_serials, Certificate.serial_number
// Revoked map (pki.go:201) is global, keyed by AKI+serial with no PP scope; an
// attacker CRL sharing the victim's AKI can target the victim cert's serial.
pred ni_s4_crl_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        aki[atk_crl] = obj.cms.ee_certificate.issuer_ski and
        obj.cms.ee_certificate.serial_number in atk_crl.crl_payload.revoked_serials
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/pki/pki.go:354
// Registry: CRLPayload.crl_this_update_parse
// O2: no recover() around the CRL parse; the model keeps the malformed-CRL candidate; ParseDERCRL normally returns an error.
pred ni_s4_parse_crl_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        crl_time_parse_can_crash[atk_crl.crl_payload]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/pki/pki.go:354
// Registry: CRLPayload.crl_next_update_parse
// O2: no recover() around the CRL parse; the model keeps the malformed-CRL candidate; ParseDERCRL normally returns an error.
pred ni_s4_parse_crl_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        crl_time_parse_can_crash[atk_crl.crl_payload]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/pki/pki.go:354
// Registry: CRLPayload.crl_revocation_date_parse
// O2: no recover() around the CRL parse; the model keeps the malformed-CRL candidate; ParseDERCRL normally returns an error.
pred ni_s4_parse_crl_revocation_date_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        crl_time_parse_can_crash[atk_crl.crl_payload]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/cms.go:365
// Registry: Certificate.pubkey_parse
// O2: no recover() around the parse; the model keeps the key-parse candidate; the RSA assertion is guarded by an ok flag.
pred ni_s4_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_ASPA + OT_CA_CERT)
    some atk_crl: RPKIObject |
        atk_crl.origin = atk_pp and atk_crl.obj_type = OT_CRL and
        pubkey_parse_can_crash[atk_crl.cms]
}

// --- S4 Conf per-field (O3: all UNSAT) ---

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/pki/pki.go:666
// Registry: CMSSignedData.signature_valid, CA.ca_ski
// CheckCRLSignature (pki.go:665-666) verifies the CRL against the parent CA
// public key, so a CRL claiming the victim CA but not signed by it is rejected
// (UNSAT).
pred conf_s4_crl_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    aki[obj] = victim_pp.owner.ca_ski
    obj.cms.signature_valid = False
    s4_crl_verify_succeeds[obj.cms]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/pki/pki.go:494
// Registry: CRLPayload.crl_issuer, Certificate.subject_name, CRLPayload.revoked_serials, Certificate.serial_number
// OctoRPKI parses the CRL issuer DN but never compares it to the parent CA
// subject DN (AddCRL pki.go:636-688 binds by AKI pki.go:638 only). The omission
// is INERT: revocation is keyed by AKI+serial (pki.go:494 lookup, :672 insert),
// so a validly-signed attacker CRL (its own AKI) with a spoofed victim issuer DN
// cannot revoke a victim cert (whose AKI differs). UNSAT by distinct_ca_ski.
pred conf_s4_crl_issuer_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    obj.cms.signature_valid = True
    aki[obj] = atk_pp.owner.ca_ski
    some pc: RPKIObject |
        pc.origin = victim_pp and pc.obj_type = OT_CA_CERT and
        obj.crl_payload.crl_issuer = pc.cms.ee_certificate.subject_name
    some vc: RPKIObject |
        vc.origin = victim_pp and
        vc.obj_type in (OT_CA_CERT + OT_ROA + OT_MFT + OT_ASPA) and
        s4_cert_revoked_by[obj, vc.cms.ee_certificate]
}

// =====================================================================
// S5 CertChainProcessing - CA_CERT (NI + Conf)
// =====================================================================

// ValidObjects[ski] store (pki.go:459) and ValidObjects[aki] parent lookup
// (pki.go:478-479), both global and SKI/AKI-keyed.
fun s5_cert_store_key[obj: RPKIObject]: KeyId { obj.cms.ee_certificate.subject_ski }

// RFC 3779 resource containment against the issuing CA (pki.go:500-545, cert.go:
// 467,507). inherit delegates to the issuing CA's own ancestor chain
// (cert.go:164-166 IPAddressNull -> checkParent; pki.go:502-519).
pred s5_cert_resource_check[obj: RPKIObject, issuing_ca: CA] {
    { obj.cms.ee_certificate.resources_inherit = True }
    or {
        obj.cms.ee_certificate.ip_resources in issuing_ca.delegated_prefixes
        obj.cms.ee_certificate.as_resources in issuing_ca.delegated_asns
    }
}

// OctoRPKI performs no publication-origin scoping of SIA URIs: rrdpNotify is
// registered into a global map keyed by URL with only a first-writer-wins
// consistency check (octorpki.go:269,1098-1104); caRepository/rpkiManifest are
// consumed by ExtractPathCert (pki.go:722-724) with no authority check. A
// "scoped" SIA would have its host inside the issuing CA's own PP - which is
// never verified.
pred s5_sia_notify_scoped[cert_obj: RPKIObject, issuing_pp: PP] {
    cert_obj.cms.ee_certificate.sia_notify_uri.host = issuing_pp.siaBase.host
}
pred s5_sia_repo_scoped[cert_obj: RPKIObject, issuing_pp: PP] {
    cert_obj.cms.ee_certificate.sia_repo_uri.host = issuing_pp.siaBase.host
}
pred s5_sia_mft_scoped[cert_obj: RPKIObject, issuing_pp: PP] {
    cert_obj.cms.ee_certificate.sia_mft_uri.host = issuing_pp.siaBase.host
}

// --- S5 NI per-field ---

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:459
// Registry: Certificate.subject_ski
// Global ValidObjects[ski] store (pki.go:459,461).
// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:478
// Registry: Certificate.issuer_ski, CA.ca_ski
// Parent resolved by AKI in the GLOBAL ValidObjects map (pki.go:478-479). An
// attacker CA cert whose SKI equals the victim child's AKI becomes a cross-
// origin parent candidate - the paper's "cross-CA unmodified mirror" (section 6.1).
pred ni_s5_chain_walk_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        s5_cert_store_key[atk_cert] = obj.cms.ee_certificate.issuer_ski
}

// PAPER-CLAIM: O1 (supporting)
// SOURCE: cmd/octorpki/octorpki.go:1098
// Registry: Certificate.sia_notify_uri
// Cross-stage NI: S5 reads the CA cert SIA rrdpNotify, S2 fetches it. The global
// rrdpFetchDomain map (octorpki.go:269,1103) is not scoped to the issuing CA, so
// an attacker cert can point rrdpNotify at the victim's host.
pred ni_s5_sia_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        some atk_cert.cms.ee_certificate.sia_notify_uri and
        atk_cert.cms.ee_certificate.sia_notify_uri.host = victim_pp.siaBase.host and
        not s5_sia_notify_scoped[atk_cert, atk_pp]
}

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/lib/cert.go:457
// Registry: Certificate.sia_repo_uri
// caRepository (GetRsyncGeneralName cert.go:457) is consumed without authority
// scoping; an attacker cert can redirect rsync fetching to the victim's host.
pred ni_s5_sia_repo_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        some atk_cert.cms.ee_certificate.sia_repo_uri and
        atk_cert.cms.ee_certificate.sia_repo_uri.host = victim_pp.siaBase.host and
        not s5_sia_repo_scoped[atk_cert, atk_pp]
}

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:722
// Registry: Certificate.sia_mft_uri
// rpkiManifest (ExtractPathCert pki.go:722-724) is consumed without scope
// validation against the issuing CA's publication point.
pred ni_s5_sia_mft_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_cert: RPKIObject |
        atk_cert.origin = atk_pp and atk_cert.obj_type = OT_CA_CERT and
        some atk_cert.cms.ee_certificate.sia_mft_uri and
        atk_cert.cms.ee_certificate.sia_mft_uri.host = victim_pp.siaBase.host and
        not s5_sia_mft_scoped[atk_cert, atk_pp]
}

// --- S5 Conf per-field (O3: all UNSAT) ---

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/pki/pki.go:541
// Registry: Certificate.ip_resources, Certificate.as_resources, CA.delegated_prefixes, CA.delegated_asns
// CA delegation containment: ValidateCertificate rejects invalid IPs/ASNs
// (pki.go:541-545), so an attacker CA cert cannot certify victim resources (UNSAT).
pred conf_s5_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    {
        some op: Prefix |
            op in obj.cms.ee_certificate.ip_resources and
            op not in atk_pp.owner.delegated_prefixes and
            op in victim_pp.owner.delegated_prefixes
    } or {
        some oa: ASN |
            oa in obj.cms.ee_certificate.as_resources and
            oa not in atk_pp.owner.delegated_asns and
            oa in victim_pp.owner.delegated_asns
    }
    s5_cert_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cert.go:164
// Registry: Certificate.resources_inherit
// An inherit cert (IPAddressNull, cert.go:164-166) delegates to the issuing CA's
// own ancestor chain (pki.go:502-519), not the victim's; inherit_implies_no_
// explicit_resources forbids explicit resources, so a validated inherit cert
// cannot carry a victim prefix (UNSAT).
pred conf_s5_resources_inherit_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    obj.cms.ee_certificate.resources_inherit = True
    some op: Prefix |
        op in obj.cms.ee_certificate.ip_resources and
        op in victim_pp.owner.delegated_prefixes
    s5_cert_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/pki/pki.go:466
// Registry: Certificate.is_ca
// OctoRPKI does NOT enforce basicConstraints cA (ValidateCertificate pki.go:466-
// 548 and cert.go:549-561 verify time, signature and RFC 3779 resources, but not
// the cA bit). The omission is INERT for confinement: resource containment still
// blocks victim overclaim regardless of the cA flag, so a non-CA cert carrying a
// victim prefix is still rejected (UNSAT). Candidate: the missing
// basicConstraints check has no cross-PP confinement effect in this model.
pred conf_s5_is_ca_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    obj.cms.ee_certificate.is_ca = False
    some op: Prefix |
        op in obj.cms.ee_certificate.ip_resources and
        op not in atk_pp.owner.delegated_prefixes and
        op in victim_pp.owner.delegated_prefixes
    s5_cert_resource_check[obj, atk_pp.owner]
}

// =====================================================================
// S6 PayloadProcessing - ROA, ASPA (NI + Conf)
// =====================================================================

// ValidROA/ROA[ski] (pki.go:577,579), global SKI-keyed.
fun s6_payload_store_key[obj: RPKIObject]: KeyId { obj.cms.ee_certificate.subject_ski }

// CMS digest+signature gate on the ROA/ASPA path (roa.go:323 -> cms.go:347,374).
pred s6_payload_verify_succeeds[cms: CMSSignedData] {
    cms.econtent_digest = cms.signed_attrs_digest
    cms.signature_valid = True
}

// ROA prefixes within EE cert IP resources (roa.go:214 -> cert.go:467).
pred s6_roa_resource_check[obj: RPKIObject] {
    obj.roa_payload.roa_prefixes in obj.cms.ee_certificate.ip_resources
}
// ASPA customer AS within EE cert AS resources (modeled analogously).
pred s6_aspa_resource_check[obj: RPKIObject] {
    obj.aspa_payload.customer_as in obj.cms.ee_certificate.as_resources
}
// EE cert resources within the issuing CA (AddCert -> ValidateCertificate,
// pki.go:551,466-548).
pred s6_ee_resource_check[obj: RPKIObject, issuing_ca: CA] {
    s5_cert_resource_check[obj, issuing_ca]
}

// A ROA/ASPA parse panic (empty SignerInfos via roa.go:323 -> cms.go:333) is not
// contained (Explore has no recover, pki.go:850-921).
pred s6_payload_error_contained[atk_obj: RPKIObject] { not signerinfos_can_crash[atk_obj.cms] }

// --- S6 NI per-field ---

// PAPER-CLAIM: O1 (supporting)
// SOURCE: validator/pki/pki.go:577
// Registry: Certificate.subject_ski
// Global ValidROA/ROA[ski] (pki.go:577,579).
pred ni_s6_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        s6_payload_store_key[atk_obj] = s6_payload_store_key[obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/roa.go:323
// Registry: CMSSignedData.signer_infos
// Empty SignerInfos -> cms.go:333 panic (reached from roa.go:323) -> no recover.
pred ni_s6_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        signerinfos_can_crash[atk_obj.cms] and not s6_payload_error_contained[atk_obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/cert.go:563
// Registry: Certificate.time_field_parse
// O2: no recover() around the parse; x509 time handling normally returns errors.
pred ni_s6_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        time_parse_can_crash[atk_obj.cms] and not s6_payload_error_contained[atk_obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/cms.go:365
// Registry: Certificate.pubkey_parse
// O2: no recover() around the parse; the model keeps the key-parse candidate; the RSA assertion is guarded by an ok flag.
pred ni_s6_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        pubkey_parse_can_crash[atk_obj.cms] and not s6_payload_error_contained[atk_obj]
}

// PAPER-CLAIM: O2 (supporting)
// SOURCE: validator/lib/cert.go:300
// Registry: Certificate.ip_resources
// O2: no recover() around the resource parse; RFC 3779 decoding via asn1.Unmarshal returns an error; no fixed-
// index child access as in rpstir2 (UNSAT).
pred ni_s6_parse_ip_resources_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some atk_obj: RPKIObject |
        atk_obj.origin = atk_pp and atk_obj.obj_type in (OT_ROA + OT_ASPA) and
        some atk_obj.cms.ee_certificate.ip_resources and
        ip_resources_parse_can_crash[atk_obj.cms]
}

// --- S6 Conf per-field (O3: all UNSAT) ---

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:347
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signature_valid
// cms.go:347 digest comparison rejects a tampered ROA eContent (UNSAT).
pred conf_s6_roa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.roa_payload.roa_prefixes | p in victim_pp.owner.delegated_prefixes
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:347
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signature_valid
pred conf_s6_aspa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    s6_payload_verify_succeeds[obj.cms]
    obj.aspa_payload.customer_as in victim_pp.owner.delegated_asns
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:374
// Registry: CMSSignedData.signature_valid
pred conf_s6_roa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.signature_valid = False
    s6_payload_verify_succeeds[obj.cms]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:374
// Registry: CMSSignedData.signature_valid
pred conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.signature_valid = False
    s6_payload_verify_succeeds[obj.cms]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/roa.go:214
// Registry: ROAPayload.roa_prefixes, Certificate.ip_resources
// ROA prefixes must lie within the EE cert IP resources (roa.go:214, cert.go:467);
// a prefix outside the attacker's delegation is rejected (UNSAT).
pred conf_s6_roa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    some op: Prefix |
        op in obj.roa_payload.roa_prefixes and
        op not in atk_pp.owner.delegated_prefixes and
        op in victim_pp.owner.delegated_prefixes
    s6_roa_resource_check[obj]
    s6_ee_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/roa.go:214
// Registry: ASPAPayload.customer_as, Certificate.as_resources
pred conf_s6_aspa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.aspa_payload.customer_as not in atk_pp.owner.delegated_asns
    obj.aspa_payload.customer_as in victim_pp.owner.delegated_asns
    s6_aspa_resource_check[obj]
    s6_ee_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/pki/pki.go:551
// Registry: CMSSignedData.ee_certificate, Certificate.ip_resources, CA.delegated_prefixes
// EE resource containment (independent of ROA->EE): AddROA calls AddCert ->
// ValidateCertificate (pki.go:551,466-548), so the EE cert itself cannot claim a
// victim prefix outside the attacker's delegation (UNSAT).
pred conf_s6_ee_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    some op: Prefix |
        op in obj.cms.ee_certificate.ip_resources and
        op not in atk_pp.owner.delegated_prefixes and
        op in victim_pp.owner.delegated_prefixes
    s6_ee_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:332
// Registry: CMSSignedData.sid_matches_ee
// SID is not checked (cms.go:332-379); INERT, because digest+signature+resource
// containment still block victim-resource attribution (UNSAT).
pred conf_s6_roa_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.sid_matches_ee = False
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.roa_payload.roa_prefixes | p in victim_pp.owner.delegated_prefixes
    s6_roa_resource_check[obj]
    s6_ee_resource_check[obj, atk_pp.owner]
}

// PAPER-CLAIM: O3 (supporting)
// SOURCE: validator/lib/cms.go:332
// Registry: CMSSignedData.econtent_type_matches
// eContentType is not checked (cms.go:332-379); INERT (UNSAT by resource containment).
pred conf_s6_roa_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_type_matches = False
    s6_payload_verify_succeeds[obj.cms]
    some p: obj.roa_payload.roa_prefixes | p in victim_pp.owner.delegated_prefixes
    s6_roa_resource_check[obj]
    s6_ee_resource_check[obj, atk_pp.owner]
}

// =====================================================================
// Stage aggregate violation predicates (OR of every per-field predicate)
// =====================================================================

pred ni_s2_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
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
    conf_s3_cms_econtent_type_violation[atk_pp, victim_pp, obj] or
    conf_s3_mft_hash_violation[atk_pp, victim_pp, obj]
}
pred ni_s4_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    ni_s4_crl_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s4_crl_scope_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_this_update_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_next_update_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_revocation_date_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_pubkey_violation[atk_pp, victim_pp, obj]
}
pred conf_s4_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    conf_s4_crl_signature_violation[atk_pp, victim_pp, obj] or
    conf_s4_crl_issuer_violation[atk_pp, victim_pp, obj]
}
pred ni_s5_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    ni_s5_chain_walk_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_repo_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_mft_scope_violation[atk_pp, victim_pp, obj]
}
pred conf_s5_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    conf_s5_resource_violation[atk_pp, victim_pp, obj] or
    conf_s5_resources_inherit_violation[atk_pp, victim_pp, obj] or
    conf_s5_is_ca_violation[atk_pp, victim_pp, obj]
}
pred ni_s6_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    ni_s6_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_signerinfos_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_time_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_pubkey_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_ip_resources_violation[atk_pp, victim_pp, obj]
}
pred conf_s6_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    conf_s6_roa_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_ee_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_econtent_type_violation[atk_pp, victim_pp, obj]
}

pred any_ni_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    ni_s2_violation[atk_pp, victim_pp, obj] or
    ni_s3_violation[atk_pp, victim_pp, obj] or
    ni_s4_violation[atk_pp, victim_pp, obj] or
    ni_s5_violation[atk_pp, victim_pp, obj] or
    ni_s6_violation[atk_pp, victim_pp, obj]
}
pred any_conf_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    conf_s3_violation[atk_pp, victim_pp, obj] or
    conf_s4_violation[atk_pp, victim_pp, obj] or
    conf_s5_violation[atk_pp, victim_pp, obj] or
    conf_s6_violation[atk_pp, victim_pp, obj]
}
pred any_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
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
assert s4_conf_crl_issuer { no a, v: PP, o: RPKIObject | conf_s4_crl_issuer_violation[a, v, o] }
assert s5_ni_chain_walk { no a, v: PP, o: RPKIObject | ni_s5_chain_walk_violation[a, v, o] }
assert s5_ni_sia_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_scope_violation[a, v, o] }
assert s5_ni_sia_repo_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_repo_scope_violation[a, v, o] }
assert s5_ni_sia_mft_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_mft_scope_violation[a, v, o] }
assert s5_conf_resource { no a, v: PP, o: RPKIObject | conf_s5_resource_violation[a, v, o] }
assert s5_conf_resources_inherit { no a, v: PP, o: RPKIObject | conf_s5_resources_inherit_violation[a, v, o] }
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
assert s6_conf_roa_resource { no a, v: PP, o: RPKIObject | conf_s6_roa_resource_violation[a, v, o] }
assert s6_conf_aspa_resource { no a, v: PP, o: RPKIObject | conf_s6_aspa_resource_violation[a, v, o] }
assert s6_conf_ee_resource { no a, v: PP, o: RPKIObject | conf_s6_ee_resource_violation[a, v, o] }
assert s6_conf_roa_sid { no a, v: PP, o: RPKIObject | conf_s6_roa_sid_violation[a, v, o] }
assert s6_conf_roa_econtent_type { no a, v: PP, o: RPKIObject | conf_s6_roa_econtent_type_violation[a, v, o] }

// =====================================================================
// Stage aggregate (Table 2 cell) assertions and cross-PP security
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

// Aggregate soundness: no per-field violation can hold while its stage
// aggregate (and the top-level any_violation) is UNSAT.
assert aggregate_sound {
    all a, v: PP, o: RPKIObject {
        (ni_s2_fetch_scope_violation[a, v, o] or ni_s2_cache_workspace_violation[a, v, o]) implies ni_s2_violation[a, v, o]
        (ni_s3_store_key_violation[a, v, o] or ni_s3_manifest_lookup_violation[a, v, o] or ni_s3_parse_signerinfos_violation[a, v, o] or ni_s3_parse_time_violation[a, v, o] or ni_s3_parse_mft_this_update_violation[a, v, o] or ni_s3_parse_mft_next_update_violation[a, v, o] or ni_s3_parse_pubkey_violation[a, v, o] or ni_s3_parse_mft_filename_violation[a, v, o]) implies ni_s3_violation[a, v, o]
        (conf_s3_cms_digest_violation[a, v, o] or conf_s3_cms_signature_violation[a, v, o] or conf_s3_cms_sid_violation[a, v, o] or conf_s3_cms_econtent_type_violation[a, v, o] or conf_s3_mft_hash_violation[a, v, o]) implies conf_s3_violation[a, v, o]
        (ni_s4_crl_store_key_violation[a, v, o] or ni_s4_crl_scope_violation[a, v, o] or ni_s4_parse_crl_this_update_violation[a, v, o] or ni_s4_parse_crl_next_update_violation[a, v, o] or ni_s4_parse_crl_revocation_date_violation[a, v, o] or ni_s4_parse_pubkey_violation[a, v, o]) implies ni_s4_violation[a, v, o]
        (conf_s4_crl_signature_violation[a, v, o] or conf_s4_crl_issuer_violation[a, v, o]) implies conf_s4_violation[a, v, o]
        (ni_s5_chain_walk_violation[a, v, o] or ni_s5_sia_scope_violation[a, v, o] or ni_s5_sia_repo_scope_violation[a, v, o] or ni_s5_sia_mft_scope_violation[a, v, o]) implies ni_s5_violation[a, v, o]
        (conf_s5_resource_violation[a, v, o] or conf_s5_resources_inherit_violation[a, v, o] or conf_s5_is_ca_violation[a, v, o]) implies conf_s5_violation[a, v, o]
        (ni_s6_store_key_violation[a, v, o] or ni_s6_parse_signerinfos_violation[a, v, o] or ni_s6_parse_time_violation[a, v, o] or ni_s6_parse_pubkey_violation[a, v, o] or ni_s6_parse_ip_resources_violation[a, v, o]) implies ni_s6_violation[a, v, o]
        (conf_s6_roa_cms_digest_violation[a, v, o] or conf_s6_aspa_cms_digest_violation[a, v, o] or conf_s6_roa_cms_signature_violation[a, v, o] or conf_s6_aspa_cms_signature_violation[a, v, o] or conf_s6_roa_resource_violation[a, v, o] or conf_s6_aspa_resource_violation[a, v, o] or conf_s6_ee_resource_violation[a, v, o] or conf_s6_roa_sid_violation[a, v, o] or conf_s6_roa_econtent_type_violation[a, v, o]) implies conf_s6_violation[a, v, o]
        (ni_s2_violation[a, v, o] or ni_s3_violation[a, v, o] or ni_s4_violation[a, v, o] or ni_s5_violation[a, v, o] or ni_s6_violation[a, v, o]) implies any_ni_violation[a, v, o]
        (conf_s3_violation[a, v, o] or conf_s4_violation[a, v, o] or conf_s5_violation[a, v, o] or conf_s6_violation[a, v, o]) implies any_conf_violation[a, v, o]
        any_ni_violation[a, v, o] implies any_violation[a, v, o]
        any_conf_violation[a, v, o] implies any_violation[a, v, o]
    }
}

// =====================================================================
// Bounded checks - explicit Alloy 6.2.0 scope for every reachable sig
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
check s4_conf_crl_issuer for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_chain_walk for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_repo_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_mft_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_resources_inherit for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
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
check s6_conf_roa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_ee_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

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
check aggregate_sound for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

run model_satisfiable for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
