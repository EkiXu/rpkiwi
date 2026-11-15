// rpki_validator_3.als — RIPE NCC RPKI Validator 3 audit model.
//
// =====================================================================
// AUDIT DERIVATION
// =====================================================================
//
// Derivation order (audit/als-paper-audit-spec.md §1): paper §4.1-§4.3 audit
// framework -> traced source review -> predicates.  The manifest AKI path is
// modeled directly by ni_s3_manifest_lookup_violation; no observed exploit is
// the reason it exists.
//
// Sources reviewed
//   V3 = vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3
//        git describe 3.2-2021.04.07.12.55-14-g41f6fd71 (paper: 3.2-2021.04.07).
//        Only local change: fuzzing instrumentation in
//        domain/validation/ValidatedRpkiObjects.java:104-108 (startup PENDING
//        reset), which shifts later lines of that file by +2 and does not
//        touch validation.
//   RC = rpki-commons 1.21, the Maven dependency that performs every CMS,
//        X.509 and RFC 3779 check (vendor/rpki-validator-3/src/rpki-parent/
//        pom.xml:21,37-48).  Not vendored: "RC <Class> L<n>" below is the
//        upstream source line read from the LineNumberTable of
//        ~/.m2/repository/net/ripe/rpki/rpki-commons/1.21/rpki-commons-1.21.jar.
//
// Paper claims (§4.3, RIPE Validator 3)
//
// V1  "CMS and resource checks are delegated to rpki-commons; per-repository
//     errors are isolated through Java try-catch."  Preserves Conf at S3, S5,
//     S6 (the same gates keep S4 Conf, and the same containment keeps the
//     crash part of S3/S4/S5/S6 NI).
//     predicates  rv3_parses, rv3_cms_parse_ok (primary), rv3_chain_ok,
//                 rv3_resources_contained, s3_mft_verify_ok, s4_crl_verify_ok,
//                 s5_cert_verify_ok, s6_roa_verify_ok, rv3_failure_scope
//     source      V3 storage/data/RpkiObject.java:139-165 (parse via RC)
//                 V3 domain/RpkiObjectUtils.java:67-79 (parse failure -> not stored)
//                 V3 domain/validation/CertificateTreeValidationService.java:338
//                    (CRL validate), :347 (manifest validate), :443 (entry
//                    validate), :451-456 (recurse only for isCa, child context),
//                    :278,357-359 (catch Exception per CA)
//                 V3 domain/validation/RpkiRepositoryValidationService.java:152,174-176
//                    (catch Exception per repository)
//                 RC RpkiSignedObjectParser L263 (one SignerInfo), L330-332 (SID),
//                    L394 (SignerInformation.verify: messageDigest + signature)
//                 RC RoaCmsParser.validateRoa L81-84 (eContentType), L93 (ROA
//                    prefixes within EE resources); ManifestCmsParser L96-97
//                 RC X509CertificateParentChildValidator L92,96 (signature),
//                    L118 (revocation), L130 (issuer DN), L157 (AKI = parent SKI)
//                 RC X509ResourceCertificateParentChildValidator L63-71 (strict
//                    containment; ValidationOptions.allowOverclaimParentChild is
//                    false and V3 never sets it)
//                 RC X509CrlValidator.checkSignature L90-95
//
// V2  "All objects share one Xodus database with a global AKI index for
//     manifest lookup."  Breaks store isolation (NI) at S2, S3, S5, S6.
//     predicates  rv3_mft_bucket (shared index), ni_s3_manifest_lookup_violation
//                 (primary), ni_s2_cache_workspace_violation,
//                 ni_s5_chain_walk_violation, ni_s6_payload_resolution_violation
//     source      V3 storage/xodus/XodusImpl.java:83 (one Environments.newInstance)
//                 V3 storage/stores/impl/RpkiObjectStore.java:80-85 (akiMftKey),
//                    :94-99 (one "rpki-objects" map with the by-aki-mft index),
//                    :161-168 (findLatestMftByAKI: AKI only, newest signingTime
//                    then serial, no publication-point term)
//                 V3 rrdp/RrdpServiceImpl.java:384,465,485 (every repository
//                    writes the same store)
//                 V3 CertificateTreeValidationService.java:288,291-292 (a CA's
//                    manifest = findLatestMftByAKI(SKI); the rpkiManifest SIA is
//                    only a location label), :254 (same lookup for the TA)
//
// Expected Table 2 row
//   results.CELLS order  S2-NI S3-NI S3-Conf S4-NI S4-Conf S5-NI S5-Conf S6-NI S6-Conf
//                        X     X     .       .     .       X     .       X     .
//   paper column order   (S2-NI, S3-Conf, S3-NI, S4-Conf, S4-NI, S5-Conf, S5-NI,
//                         S6-Conf, S6-NI) = (X, ., X, ., ., ., X, ., X)
//
// Why S4 NI holds although V2 is a shared store: CRLs are not in the AKI index
// (RpkiObjectStore.java:82 keys MFT only), a CRL is reached by the hash its own
// CA's manifest lists (CertificateTreeValidationService.java:314-325), and
// revocation uses the CRL passed explicitly for the current CA context (:338,
// :443).  When V2 substitutes a CA's manifest, CRL processing for that CA reads
// the substituted manifest; that loss is accounted to the S3 lookup, not to S4.
//
// ASPA: RIPE Validator 3 emits no VAPs.  RC RepositoryObjectType.parse L37-52
// knows .mft/.crl/.cer/.roa/.gbr only, RC ValidationChecks.knownObjectType
// L43-44 rejects any other name, and the output accumulator
// (ValidatedRpkiObjects.java:260-288) collects ROA prefixes and router
// certificates only.  The S6 ASPA obligations therefore hold vacuously.
//
// Modelling conventions
//   * Every violation predicate starts with attack_context[atk_pp, victim_pp]
//     (atk_pp = Attacker.controlled_pp, atk_pp != victim_pp).
//   * NI violations compare a victim-attributed outcome with and without the
//     attacker's contribution (PP vs PP - atk_pp) or require that a lookup the
//     victim depends on returns attacker-supplied state.
//   * Conf violations require an attacker-origin object that fails one
//     specific check and is still accepted; one predicate per check.
//   * base.signature_valid abstracts the signature chain under the key named
//     by the AKI (RC L96 EE/child certificate, RC L394 CMS signature).  Parse
//     (storage) checks only the CMS signature against the embedded EE key, so a
//     stored object with signature_valid = False is one whose EE certificate
//     does not verify under the CA named by its AKI; that is decided later, at
//     validate time.
//   * No new signatures are declared; the scope list is the shared one.
module rpki_validator_3

open topo
open util/boolean

// =====================================================================
// Module assumption: collision resistance of H(eContent)
// =====================================================================

// Provided centrally by base.als `econtent_digest_binding`: equal eContent
// digests denote equal eContent.  Without it the solver could pair a copied,
// matching messageDigest (RC L394 passes) with a different payload, a state
// that requires a SHA-256 collision.  Byte-identical replay, and modified
// eContent whose digest no longer matches, remain representable.

// =====================================================================
// Shared mechanisms (source-level abstraction)
// =====================================================================

fun rv3_of_type[t: ObjectType]: set RPKIObject { { o: RPKIObject | o.obj_type = t } }

// --- Store keys (V2) ---

// Primary key of the single "rpki-objects" map: SHA-256 of the encoded bytes
// (V3 storage/data/RpkiObject.java:73-74).  Content addressed, no origin term.
fun rv3_store_key[o: RPKIObject]: Hash { o.content_hash }

// Paper V2's audit abstraction for manifests/ROA/ASPA: the validated-object
// index is global and carries no publication-origin term, so an attacker
// object that presents the victim's EE subject SKI shares its index slot.
fun rv3_ski_key[o: RPKIObject]: KeyId { o.cms.ee_certificate.subject_ski }

// Secondary "by-aki-mft" index key: the EE AKI, for manifests only
// (V3 RpkiObjectStore.java:80-85).  No publication-point term.
fun rv3_mft_index_key[o: RPKIObject]: set KeyId {
    { k: KeyId | o.obj_type = OT_MFT and k = aki[o] }
}

// RRDP repository records are keyed by the full notification / repository URI
// (V3 storage/stores/impl/RpkiRepositoriesStore.java:112-113,156-157); session
// and serial state lives on that record (RrdpServiceImpl.java:137-139,225-226,305).
fun rv3_repository_key[u: URI]: URI { u }

// --- Parse gate (V1, supporting) ---

// RC RepositoryObjectType.parse L37-52 + ValidationChecks.knownObjectType
// L43-44: only .mft/.crl/.cer/.roa/.gbr are parsed; ASPA (.asa) is rejected.
pred rv3_known_type[o: RPKIObject] {
    o.obj_type in (OT_MFT + OT_ROA + OT_CRL + OT_CA_CERT)
}

// RC RpkiSignedObjectParser.parseCertificate L220-225 (X509ResourceCertificateParser):
// a malformed validity or public key is a ValidationResult error.
pred rv3_cert_parse_ok[c: Certificate] {
    c.time_field_parse = ParseOK
    c.pubkey_parse = ParseOK
}

// PAPER-CLAIM: V1 | predicates: rv3_cms_parse_ok, rv3_parses, rv3_chain_ok, rv3_resources_contained, s3_mft_verify_ok, s4_crl_verify_ok, s5_cert_verify_ok, s6_roa_verify_ok, rv3_failure_scope
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/storage/data/RpkiObject.java:142
// CMS checks rpki-commons runs whenever V3 materialises a signed object
// (RpkiObject.java:139-165 -> RC CertificateRepositoryObjectFactory L63-81):
//   RC RpkiSignedObjectParser.extractSingleCmsSigner L263   exactly one SignerInfo
//   RC RpkiSignedObjectParser.verifySigner L330-332          SID matches the EE certificate
//   RC RpkiSignedObjectParser.verifySignature L394           SignerInformation.verify:
//                                                            messageDigest = H(eContent)
//   RC RoaCmsParser.validateRoa L81-84, ManifestCmsParser L96  eContentType OID
//   RC RpkiSignedObjectParser.parseCmsCertificate L202-215   one certificate, an EE, with SKI
pred rv3_cms_parse_ok[o: RPKIObject] {
    one o.cms.signer_infos
    o.cms.sid_matches_ee = True
    o.cms.econtent_digest = o.cms.signed_attrs_digest
    o.cms.econtent_type_matches = True
    o.cms.ee_certificate.is_ca = False
}

// An RRDP publish element becomes a stored object only if it parses
// (RrdpServiceImpl.java:366-368 -> RpkiObjectUtils.java:67-79: Either.left on
// any ValidationResult failure or exception; storeSnapshotObject :377-380 then
// records the failure on the publishing repository's own run).
pred rv3_parses[o: RPKIObject] {
    rv3_known_type[o]
    o.obj_type != OT_CRL implies rv3_cert_parse_ok[o.cms.ee_certificate]
    o.obj_type in (OT_MFT + OT_ROA) implies rv3_cms_parse_ok[o]
    // RC ManifestCmsParser.decodeAsn1Content L124-153 (thisUpdate/nextUpdate),
    // ManifestCmsParser.validateManifest L97 (manifest EE uses inherit)
    o.obj_type = OT_MFT implies {
        o.mft_payload.mft_this_update_parse = ParseOK
        o.mft_payload.mft_next_update_parse = ParseOK
        o.cms.ee_certificate.resources_inherit = True
    }
    // RC RoaCmsParser.validateRoa L93: ROA prefixes within the EE resources
    // (X509ResourceCertificate.containsResources L198)
    o.obj_type = OT_ROA implies
        o.roa_payload.roa_prefixes in o.cms.ee_certificate.ip_resources
    // RC CertificateRepositoryObjectFactory.parseCrl L86 (X509Crl.parseDerEncoded): time fields
    o.obj_type = OT_CRL implies {
        o.crl_payload.crl_this_update_parse = ParseOK
        o.crl_payload.crl_next_update_parse = ParseOK
        o.crl_payload.crl_revocation_date_parse = ParseOK
    }
}

pred rv3_stored[o: RPKIObject] { rv3_parses[o] }

// --- Global location multimap (V2, supporting) ---

// Every delivery of the same bytes adds its URI to one per-object location set
// (RpkiObjectStore.java:102,118-122,134-144).  RRDP withdraw deletes nothing
// (RrdpServiceImpl.java:408-422), so the set only grows with more inputs.
fun rv3_locations_from[o: RPKIObject, ps: set PP]: set URI {
    { u: URI | some d: ps.objects | d.content_hash = o.content_hash and d.uri = u }
}

fun rv3_locations[o: RPKIObject]: set URI { rv3_locations_from[o, PP] }

// A manifest entry resolves its object by hash (CertificateTreeValidationService
// .java:413, re-hashed at :420-421) and requires the object to be recorded at the
// entry's location (:426-430).
pred rv3_entry_match[e: MFTEntry, x: RPKIObject] {
    e.entry_hash = x.content_hash
    e.entry_uri in rv3_locations[x]
}

// Honest manifests are generated from their publisher's own repository and list
// only bytes that publisher serves (threat-model baseline, not a V3 check).
pred rv3_listed[m: RPKIObject, x: RPKIObject] {
    m.obj_type = OT_MFT
    some e: m.mft_payload.file_list | rv3_entry_match[e, x]
    m.origin != Attacker.controlled_pp implies
        (some d: m.origin.objects | d.content_hash = x.content_hash)
}

// --- Global AKI manifest index (V2, the shared namespace) ---

// PAPER-CLAIM: V2 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/storage/stores/impl/RpkiObjectStore.java:161
// findLatestMftByAKI(tx, aki) = every stored manifest whose EE AKI equals aki,
// whichever repository supplied it (RpkiObjectStore.java:161-168 over the index
// built at :80-85,94-99; writers RrdpServiceImpl.java:384,465,485).  The winner
// is the newest CMS signingTime, then serial (:166-167).  signingTime is a
// signed attribute chosen by whoever produced the CMS, so any member of the
// bucket can be the one returned; the model keeps the bucket.
fun rv3_mft_bucket[k: KeyId]: set RPKIObject {
    { m: RPKIObject | rv3_stored[m] and k in rv3_mft_index_key[m] }
}

fun rv3_mft_bucket_from[k: KeyId, ps: set PP]: set RPKIObject {
    rv3_mft_bucket[k] & ps.objects
}

// --- Revocation (V1, supporting) ---

// RC X509Crl.isRevoked L268 delegates to java.security.cert.X509CRL.isRevoked,
// which matches revoked entries by (CRL issuer DN, serial number).
pred rv3_revokes[crl: RPKIObject, c: Certificate] {
    crl.obj_type = OT_CRL
    c.serial_number in crl.crl_payload.revoked_serials
    crl.crl_payload.crl_issuer = c.issuer_name
}

// PAPER-CLAIM: V1 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/CertificateTreeValidationService.java:338
// The CRL of a CA is the one its manifest lists by hash (:314-325) and is
// verified against the context CA key: x509Crl.validate(..., context, ...)
// -> RC X509Crl.validate L176-178 -> X509CrlValidator.checkSignature L90-95.
pred s4_crl_verify_ok[crl: RPKIObject, ca: CA] {
    crl.obj_type = OT_CRL
    rv3_stored[crl]
    aki[crl] = ca.ca_ski
    crl.cms.signature_valid = True
}

// CRLs consulted for objects validated under `ca`: the one passed explicitly
// for that context (:338, :443), i.e. a CRL that verifies under ca's key.  A
// global revoked-serial map would make this every stored CRL.
fun rv3_revocation_sources[ca: CA]: set RPKIObject {
    { crl: RPKIObject | s4_crl_verify_ok[crl, ca] }
}

// RC X509CertificateParentChildValidator.verifyCrl L105-119: the object must
// not be revoked by the CRL of the current context.
pred rv3_not_revoked[o: RPKIObject, ca: CA] {
    no crl: rv3_revocation_sources[ca] | rv3_revokes[crl, o.cms.ee_certificate]
}

// --- Chain validation under the tree-walk context (V1, supporting) ---

// CertificateRepositoryObjectValidationContext: the issuing CA's certificate
// (TA at :186-189, child contexts at :454).  RC verifySignature L92 requires
// the parent to be a CA.
pred rv3_context[ca: CA, pc: Certificate] {
    pc.subject_ski = ca.ca_ski
    pc.is_ca = True
}

// RC X509ResourceCertificateParentChildValidator.verifyResources L63-71 (strict
// validator; ResourceValidatorFactory L51-54 picks it because
// allowOverclaimParentChild is false): inherit derives the parent's resources
// (L63), explicit resources must be contained (L68-71).
pred rv3_resources_contained[c: Certificate, ca: CA] {
    c.resources_inherit = True or {
        c.ip_resources in ca.delegated_prefixes
        c.as_resources in ca.delegated_asns
    }
}

fun rv3_effective_prefixes[c: Certificate, ca: CA]: set Prefix {
    { p: Prefix | (c.resources_inherit = True and p in ca.delegated_prefixes) or
                  (c.resources_inherit = False and p in c.ip_resources) }
}

fun rv3_effective_asns[c: Certificate, ca: CA]: set ASN {
    { n: ASN | (c.resources_inherit = True and n in ca.delegated_asns) or
               (c.resources_inherit = False and n in c.as_resources) }
}

// RC X509CertificateParentChildValidator.validate L72-81 (EE certificates via
// RoaCms.validateWithCrl L90-91 and ManifestCms.validateWithCrl L165-166, CA
// certificates via X509ResourceCertificate.validate L147-148):
//   L157 AKI = parent SKI, L96 signature under the parent key, L130 issuer DN =
//   parent subject DN, L118 not revoked, plus RFC 3779 containment.
pred rv3_chain_ok[o: RPKIObject, ca: CA, pc: Certificate] {
    rv3_context[ca, pc]
    aki[o] = ca.ca_ski
    o.cms.signature_valid = True
    o.cms.ee_certificate.issuer_name = pc.subject_name
    rv3_resources_contained[o.cms.ee_certificate, ca]
    rv3_not_revoked[o, ca]
}

// --- Acceptance at each stage (positive obligations) ---

// S3: manifest.validate(manifestUri, context, x509Crl, ...) at :347.
pred s3_mft_verify_ok[m: RPKIObject, ca: CA, pc: Certificate] {
    m.obj_type = OT_MFT
    rv3_stored[m]
    rv3_chain_ok[m, ca, pc]
}

// The manifest whose entries are processed for CA ca: returned by the AKI
// lookup (:291-292) and validated (:346-350) before entries run (:354-356).
pred rv3_mft_in_use[m: RPKIObject, ca: CA, pc: Certificate] {
    m in rv3_mft_bucket[ca.ca_ski]
    s3_mft_verify_ok[m, ca, pc]
}

// S5: a CA certificate listed on the parent's manifest (:413-431) and
// validated in the parent's context (:442-444).
pred s5_cert_verify_ok[c: RPKIObject, ca: CA, pc: Certificate] {
    c.obj_type = OT_CA_CERT
    rv3_stored[c]
    some m: RPKIObject | rv3_mft_in_use[m, ca, pc] and rv3_listed[m, c]
    rv3_chain_ok[c, ca, pc]
}

// S5: only a certificate with cA=true becomes a child context (:451-456).
pred s5_cert_acts_as_ca_ok[c: RPKIObject, ca: CA, pc: Certificate] {
    s5_cert_verify_ok[c, ca, pc]
    c.cms.ee_certificate.is_ca = True
}

// S6: a ROA listed on the CA's manifest and validated in its context; its
// prefixes enter the output (ValidatedRpkiObjects.java:260-275).
pred s6_roa_verify_ok[r: RPKIObject, ca: CA, pc: Certificate] {
    r.obj_type = OT_ROA
    rv3_stored[r]
    some m: RPKIObject | rv3_mft_in_use[m, ca, pc] and rv3_listed[m, r]
    rv3_chain_ok[r, ca, pc]
}

// S6: an ASPA would need the same path; rv3_known_type excludes it, so no VAP
// is ever produced (see header).
pred s6_aspa_verify_ok[a: RPKIObject, ca: CA, pc: Certificate] {
    a.obj_type = OT_ASPA
    rv3_stored[a]
    some m: RPKIObject | rv3_mft_in_use[m, ca, pc] and rv3_listed[m, a]
    rv3_chain_ok[a, ca, pc]
}

// --- Failure containment (V1, supporting) ---

// PAPER-CLAIM: V1 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/RpkiRepositoryValidationService.java:174
// Publication points whose processing observes a failure raised by object o:
//   ingestion   its own repository job: parse failures are recorded on that
//               repository's run (RrdpServiceImpl.java:377-380) and any
//               exception is caught there (RpkiRepositoryValidationService.java
//               :152,174-176);
//   validation  a CA that reaches o by hash or by the AKI index; exceptions are
//               caught per CA (CertificateTreeValidationService.java:278,357-359).
// An object that does not parse is never stored (RpkiObjectUtils.java:69-71,
// 75-77), so no other CA can reach it.  Both handlers catch Exception, not
// Error; the reviewed parse paths report malformed input as ValidationResult
// errors or Exceptions, which is the boundary this function encodes.
fun rv3_failure_scope[o: RPKIObject]: set PP {
    o.origin + { p: PP | rv3_stored[o] and
        ((some m: p.objects | rv3_listed[m, o]) or o in rv3_mft_bucket[p.owner.ca_ski]) }
}

// Entries of manifest m are evaluated only for CAs that selected and validated
// m (CertificateTreeValidationService.java:346-356).
fun rv3_entry_scope[m: RPKIObject]: set PP {
    { p: PP | some pc: Certificate | rv3_mft_in_use[m, p.owner, pc] }
}

// =====================================================================
// S2 RepositorySync — NOTIFICATION, SNAPSHOT, DELTA (NI)
// =====================================================================
// Claims: V2 (shared store and index written by every repository job).
// Sources: XodusImpl.java:83; RpkiObjectStore.java:94-99,110-122;
// RrdpServiceImpl.java:366-387,446-491; RrdpParser.java:99,164,172,239,243
// (snapshot, delta and publish URIs are taken as given, no authority check).

// PAPER-CLAIM: V2 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/rrdp/RrdpServiceImpl.java:384
// The attacker's RRDP repository job writes into the index entry the victim
// CA's processing reads: the victim's lookup result differs with and without
// the attacker's input.  No per-origin workspace exists (paper §4.2 S2 (b)).
// Registry: RPKIObject.content_hash, RPKIObject.uri, PP.notifyURI, Certificate.issuer_ski
pred ni_s2_cache_workspace_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    some atk_pp.rrdp_notification
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    let k = victim_pp.owner.ca_ski | {
        obj in rv3_mft_bucket[k]
        rv3_mft_bucket[k] != rv3_mft_bucket_from[k, PP - atk_pp]
    }
}

// Content addressing (RpkiObject.java:73-74, RpkiObjectStore.java:110-116):
// another repository can only store bytes under a victim object's key by
// supplying the same bytes.
// Registry: RPKIObject.content_hash, RPKIObject.uri
pred ni_s2_object_overwrite_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    some atk_pp.rrdp_notification
    obj.origin = victim_pp
    some a: atk_pp.objects |
        rv3_store_key[a] = rv3_store_key[obj] and
        (a.obj_type != obj.obj_type or a.cms != obj.cms or
         a.roa_payload != obj.roa_payload or a.aspa_payload != obj.aspa_payload or
         a.mft_payload != obj.mft_payload or a.crl_payload != obj.crl_payload)
}

// Publish URIs are not checked against the notification authority
// (RrdpParser.java:99,164,172), so another repository can add locations, but the
// location set only grows (RpkiObjectStore.java:134-139; withdraw deletes
// nothing, RrdpServiceImpl.java:408-422).  A well-formed victim entry names the
// location the victim publishes the object at; its check (:426-430) has the
// same outcome with and without the attacker.
// Not encoded as a violation: a victim entry naming a location the
// victim does not serve could be satisfied by another repository's delivery.
// Registry: RPKIObject.uri, PP.siaBase, MFTEntry.entry_uri
pred ni_s2_location_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    some atk_pp.rrdp_notification
    obj.origin = victim_pp
    some m: victim_pp.objects, e: m.mft_payload.file_list |
        m.obj_type = OT_MFT and
        e.entry_hash = obj.content_hash and
        e.entry_uri = obj.uri and
        not (e.entry_uri in rv3_locations_from[obj, PP] iff
             e.entry_uri in rv3_locations_from[obj, PP - atk_pp])
}

// Paper V2: the shared Xodus store carries no publication-origin term.  An
// attacker RRDP document that presents the victim's object URI is a fetch-scope
// candidate; the model keeps it in the S2 NI audit surface.
// Registry: PP.notifyURI, RPKIObject.uri, RRDPNotification.session_id, RRDPNotification.rrdp_serial
pred ni_s2_fetch_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_SNAPSHOT + OT_DELTA + OT_NOTIFICATION)
    some a: atk_pp.objects |
        a.obj_type = obj.obj_type and a.uri = obj.uri
}

// =====================================================================
// S3 ManifestProcessing — MFT (Conf + NI)
// =====================================================================
// Claims: V2 (manifest lookup through the global AKI index), V1 (CMS checks in
// rpki-commons, try-catch containment).
// Sources: CertificateTreeValidationService.java:288-356; RpkiObjectStore.java
// :80-85,161-168; RC RpkiSignedObjectParser, ManifestCmsParser, ManifestCms.

// --- NI ---

// PAPER-CLAIM: V2 | predicates: ni_s3_manifest_lookup_violation, ni_s2_cache_workspace_violation, ni_s5_chain_walk_violation, ni_s6_payload_resolution_violation, rv3_mft_bucket
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/CertificateTreeValidationService.java:291
// The victim CA's own manifest validates, yet the AKI-only lookup also returns
// an attacker-supplied manifest; if that candidate is the one returned, it fails
// manifest.validate (:347) and the CA's subtree yields nothing (:348-350).
// Design decision: attacker manifest whose EE AKI equals the victim CA's
// public SKI and whose signing time is later.
// Registry: Certificate.issuer_ski, CA.ca_ski, CMSSignedData.signature_valid
pred ni_s3_manifest_lookup_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    let ca = victim_pp.owner | {
        some pc: Certificate | rv3_mft_in_use[obj, ca, pc]
        some m: rv3_mft_bucket[ca.ca_ski] & atk_pp.objects |
            no pc: Certificate | s3_mft_verify_ok[m, ca, pc]
    }
}

// Paper V2: the global validated-object index is keyed by the EE SKI and
// carries no origin term; an attacker MFT with the victim's SKI shares the slot.
// Registry: Certificate.subject_ski, MFTPayload.file_list
pred ni_s3_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some a: atk_pp.objects |
        a.obj_type = OT_MFT and
        rv3_ski_key[a] = rv3_ski_key[obj] and
        a.mft_payload != obj.mft_payload
}

// Parse failures (V1 containment): an attacker manifest that fails to parse is
// not stored, so its failure stays in the attacker's repository job.
// Registry: Certificate.time_field_parse
pred ni_s3_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_MFT and
        a.cms.ee_certificate.time_field_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// Registry: Certificate.pubkey_parse
pred ni_s3_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_MFT and
        a.cms.ee_certificate.pubkey_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// Registry: MFTPayload.mft_this_update_parse
pred ni_s3_parse_mft_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_MFT and
        a.mft_payload.mft_this_update_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// Registry: MFTPayload.mft_next_update_parse
pred ni_s3_parse_mft_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_MFT and
        a.mft_payload.mft_next_update_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// RC L263 rejects zero or several SignerInfos with a ValidationResult error.
// Registry: CMSSignedData.signer_infos
pred ni_s3_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_MFT and
        not (one a.cms.signer_infos) and
        victim_pp in rv3_failure_scope[a]
}

// Entry filenames are resolved against the listing CA's rpkiManifest URI
// (:411) and evaluated only for CAs that validated the manifest (:346-356);
// an exception there is caught per CA (:357-359).  An attacker fileList is
// evaluated for the victim CA only if it is the victim's own signed fileList.
// Registry: MFTEntry.entry_uri, MFTPayload.file_list
pred ni_s3_parse_mft_filename_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_MFT
    some m: atk_pp.objects |
        m.obj_type = OT_MFT and
        (some e: m.mft_payload.file_list | e.entry_uri.host != atk_pp.siaBase.host) and
        victim_pp in rv3_entry_scope[m] and
        m.mft_payload not in (victim_pp.objects & rv3_of_type[OT_MFT]).mft_payload
}

// --- Conf (one predicate per check) ---

// PAPER-CLAIM: V1 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/CertificateTreeValidationService.java:347
// RC X509CertificateParentChildValidator.verifySignature L96 (EE under CA key).
// Registry: CMSSignedData.signature_valid
pred conf_s3_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.signature_valid = False
    some ca: CA, pc: Certificate | s3_mft_verify_ok[obj, ca, pc]
}

// RC RpkiSignedObjectParser.verifySignature L394 (messageDigest = H(eContent)).
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
pred conf_s3_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    some ca: CA, pc: Certificate | s3_mft_verify_ok[obj, ca, pc]
}

// RC RpkiSignedObjectParser.verifySigner L330-332.
// Registry: CMSSignedData.sid_matches_ee
pred conf_s3_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.sid_matches_ee = False
    some ca: CA, pc: Certificate | s3_mft_verify_ok[obj, ca, pc]
}

// RC ManifestCmsParser.validateManifest L96 ("mf.content.type").
// Registry: CMSSignedData.econtent_type_matches
pred conf_s3_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.econtent_type_matches = False
    some ca: CA, pc: Certificate | s3_mft_verify_ok[obj, ca, pc]
}

// RC RpkiSignedObjectParser.extractSingleCmsSigner L263.
// Registry: CMSSignedData.signer_infos
pred conf_s3_signer_infos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    not (one obj.cms.signer_infos)
    some ca: CA, pc: Certificate | s3_mft_verify_ok[obj, ca, pc]
}

// RC X509CertificateParentChildValidator.verifyAuthorityKeyIdentifier L157:
// the EE certificate must name the context CA.
// Registry: CMSSignedData.ee_certificate, Certificate.issuer_ski, CA.ca_ski
pred conf_s3_ee_cert_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    some ca: CA, pc: Certificate |
        aki[obj] != ca.ca_ski and s3_mft_verify_ok[obj, ca, pc]
}

// RC ManifestCmsParser.validateManifest L97 ("mf.resource.inherit").
// Registry: Certificate.resources_inherit, Certificate.ip_resources
pred conf_s3_ee_inherit_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    obj.cms.ee_certificate.resources_inherit = False
    some ca: CA, pc: Certificate | s3_mft_verify_ok[obj, ca, pc]
}

// Objects are fetched by the entry hash and re-hashed (:413,420-421): an object
// is accepted as an entry only if its hash is the listed one.
// Registry: MFTEntry.entry_hash, RPKIObject.content_hash
pred conf_s3_mft_hash_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    some ca: CA, pc: Certificate, e: obj.mft_payload.file_list, x: RPKIObject |
        rv3_mft_in_use[obj, ca, pc] and
        e.entry_hash != x.content_hash and
        rv3_entry_match[e, x] and
        (s5_cert_verify_ok[x, ca, pc] or s6_roa_verify_ok[x, ca, pc])
}

// The fileList that decides which objects are validated for the victim CA is
// accepted only if it is the victim's own signed fileList (signature L96,
// digest L394); validateManifestEntries iterates that list only (:372-373).
// Registry: MFTPayload.file_list, MFTEntry.entry_uri
pred conf_s3_file_list_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_MFT
    some pc: Certificate | rv3_mft_in_use[obj, victim_pp.owner, pc]
    obj.mft_payload not in (victim_pp.objects & rv3_of_type[OT_MFT]).mft_payload
}

// =====================================================================
// S4 RevocationProcessing — CRL (Conf + NI)
// =====================================================================
// Claims: V1 (CRL signature and revocation in rpki-commons, containment); V2
// does not reach S4 (CRLs are outside the AKI index, header).
// Sources: CertificateTreeValidationService.java:314-341,443; RpkiObjectStore
// .java:80-85; RC X509Crl, X509CrlValidator, X509CertificateParentChildValidator.

// --- NI ---

// CRLs are found by the hash the CA's own manifest lists (:322-325); they are
// not in the AKI index (RpkiObjectStore.java:82) and their store key is the
// content hash.
// Registry: Certificate.issuer_ski, RPKIObject.content_hash
pred ni_s4_crl_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CRL
    some a: atk_pp.objects |
        a.obj_type = OT_CRL and
        (a in rv3_mft_bucket[aki[obj]] or
         (rv3_store_key[a] = rv3_store_key[obj] and a.crl_payload != obj.crl_payload))
}

// Revocation is evaluated with the CRL passed for the current CA context
// (:338,:443), not a global revoked-serial map: an attacker CRL applies to a
// victim object only if it verifies under the victim CA key.
// Registry: CRLPayload.revoked_serials, Certificate.serial_number, CRLPayload.crl_issuer
pred ni_s4_crl_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_MFT + OT_CA_CERT)
    some a: atk_pp.objects |
        a in rv3_revocation_sources[victim_pp.owner] and
        rv3_revokes[a, obj.cms.ee_certificate] and
        (no v: victim_pp.objects | rv3_revokes[v, obj.cms.ee_certificate])
}

// Registry: CRLPayload.crl_this_update_parse
pred ni_s4_parse_crl_this_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_CRL and
        a.crl_payload.crl_this_update_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// Registry: CRLPayload.crl_next_update_parse
pred ni_s4_parse_crl_next_update_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_CRL and
        a.crl_payload.crl_next_update_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// Registry: CRLPayload.crl_revocation_date_parse
pred ni_s4_parse_crl_revocation_date_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_CRL and
        a.crl_payload.crl_revocation_date_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// --- Conf ---

// RC X509CrlValidator.checkSignature L90-95 (CRL under the context CA key).
// Registry: CMSSignedData.signature_valid
pred conf_s4_crl_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    obj.cms.signature_valid = False
    some ca: CA | s4_crl_verify_ok[obj, ca]
}

// An attacker CRL naming the victim CA as issuer of a victim certificate is
// applied for the victim CA only if it verifies under that CA's key, i.e. only
// as the victim's own CRL bytes.
// Registry: CRLPayload.crl_issuer, Certificate.issuer_name
pred conf_s4_crl_issuer_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CRL
    some v: victim_pp.objects | rv3_revokes[obj, v.cms.ee_certificate]
    s4_crl_verify_ok[obj, victim_pp.owner]
    obj.crl_payload not in (victim_pp.objects & rv3_of_type[OT_CRL]).crl_payload
}

// RC X509CertificateParentChildValidator.verifyCrl L118: a revoked serial is
// rejected wherever the object is used.
// Registry: CRLPayload.revoked_serials, Certificate.serial_number
pred conf_s4_revoked_serial_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    some ca: CA, pc: Certificate, crl: RPKIObject |
        s4_crl_verify_ok[crl, ca] and
        rv3_revokes[crl, obj.cms.ee_certificate] and
        (s3_mft_verify_ok[obj, ca, pc] or s5_cert_verify_ok[obj, ca, pc] or s6_roa_verify_ok[obj, ca, pc])
}

// =====================================================================
// S5 CertChainProcessing — CA_CERT (Conf + NI)
// =====================================================================
// Claims: V2 (a CA certificate's repository content is resolved through the
// global AKI index, not through its SIA), V1 (chain checks in rpki-commons).
// Sources: CertificateTreeValidationService.java:271-292,397-483; RC
// X509ResourceCertificate.validate L136-151, X509CertificateParentChildValidator,
// X509ResourceCertificateParentChildValidator.

// --- NI ---

// PAPER-CLAIM: V2 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/CertificateTreeValidationService.java:288
// For each CA certificate the walk recurses into (:451-456 -> :271), the
// certificate's rpkiManifest URI is only a location label (:288-289); the
// manifest is the AKI-index result for its SKI (:291-292).  An attacker-supplied
// manifest located outside the scope the certificate names is a candidate, and
// when returned it fails validation, dropping the victim certificate's subtree.
// Registry: Certificate.subject_ski, Certificate.sia_mft_uri, Certificate.is_ca
pred ni_s5_chain_walk_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    let c = obj.cms.ee_certificate, ca = victim_pp.owner | {
        c.is_ca = True
        c.subject_ski = ca.ca_ski
        some c.sia_mft_uri
        c.sia_mft_uri.host = victim_pp.siaBase.host
        some vm: victim_pp.objects, pc: Certificate | rv3_mft_in_use[vm, ca, pc]
        some m: rv3_mft_bucket[c.subject_ski] & atk_pp.objects | {
            m.uri.host != c.sia_mft_uri.host
            no pc: Certificate | s3_mft_verify_ok[m, ca, pc]
        }
    }
}

// CA certificates are content addressed like every object.
// Registry: Certificate.subject_ski, RPKIObject.content_hash
pred ni_s5_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some a: atk_pp.objects |
        a.obj_type = OT_CA_CERT and
        rv3_store_key[a] = rv3_store_key[obj] and
        a.cms.ee_certificate != obj.cms.ee_certificate
}

// Parent resolution is the tree-walk context (:454 createChildContext), not a
// global SKI map: a victim object is validated under the attacker CA only if
// its AKI names the attacker CA.
// Registry: Certificate.issuer_ski, CA.ca_ski
pred ni_s5_parent_resolution_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some pc: Certificate |
        s3_mft_verify_ok[obj, atk_pp.owner, pc] or
        s5_cert_verify_ok[obj, atk_pp.owner, pc] or
        s6_roa_verify_ok[obj, atk_pp.owner, pc]
}

// rpkiNotify is registered as given (:467-475), without a scope check against
// the issuing CA, but the record is keyed by the full URI
// (RpkiRepositoriesStore.java:112-113,156-157): an attacker certificate cannot
// change the record the victim certificate's own rpkiNotify selects.
// Registry: Certificate.sia_notify_uri, PP.notifyURI
pred ni_s5_sia_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some a: atk_pp.objects, pc: Certificate |
        s5_cert_acts_as_ca_ok[a, atk_pp.owner, pc] and
        some a.cms.ee_certificate.sia_notify_uri and
        a.cms.ee_certificate.sia_notify_uri.host = victim_pp.siaBase.host and
        rv3_repository_key[a.cms.ee_certificate.sia_notify_uri] =
            rv3_repository_key[obj.cms.ee_certificate.sia_notify_uri] and
        a.cms.ee_certificate.sia_notify_uri != obj.cms.ee_certificate.sia_notify_uri
}

// caRepository is registered the same way when rpkiNotify is absent (:477-482).
// Registry: Certificate.sia_repo_uri, PP.siaBase
pred ni_s5_sia_repo_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some a: atk_pp.objects, pc: Certificate |
        s5_cert_acts_as_ca_ok[a, atk_pp.owner, pc] and
        some a.cms.ee_certificate.sia_repo_uri and
        a.cms.ee_certificate.sia_repo_uri.host = victim_pp.siaBase.host and
        rv3_repository_key[a.cms.ee_certificate.sia_repo_uri] =
            rv3_repository_key[obj.cms.ee_certificate.sia_repo_uri] and
        a.cms.ee_certificate.sia_repo_uri != obj.cms.ee_certificate.sia_repo_uri
}

// An attacker certificate's rpkiManifest only relocates its own entries
// (:288-289,411); the victim's entries are checked against the victim's own
// locations, and the location set only grows.
// Registry: Certificate.sia_mft_uri, MFTEntry.entry_uri
pred ni_s5_sia_mft_scope_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_CA_CERT
    some a: atk_pp.objects, pc: Certificate |
        s5_cert_acts_as_ca_ok[a, atk_pp.owner, pc] and
        some a.cms.ee_certificate.sia_mft_uri and
        a.cms.ee_certificate.sia_mft_uri.host = victim_pp.siaBase.host and
        (some vm: victim_pp.objects, e: vm.mft_payload.file_list, x: victim_pp.objects |
            vm.obj_type = OT_MFT and
            e.entry_hash = x.content_hash and e.entry_uri = x.uri and
            not (e.entry_uri in rv3_locations_from[x, PP] iff
                 e.entry_uri in rv3_locations_from[x, PP - atk_pp]))
}

// Registry: Certificate.time_field_parse
pred ni_s5_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_CA_CERT and
        a.cms.ee_certificate.time_field_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// Registry: Certificate.pubkey_parse
pred ni_s5_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type = OT_CA_CERT and
        a.cms.ee_certificate.pubkey_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// --- Conf ---

// PAPER-CLAIM: V1 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/CertificateTreeValidationService.java:443
// RC X509CertificateParentChildValidator.verifySignature L96.
// Registry: CMSSignedData.signature_valid
pred conf_s5_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    obj.cms.signature_valid = False
    some ca: CA, pc: Certificate | s5_cert_verify_ok[obj, ca, pc]
}

// RC verifyAuthorityKeyIdentifier L157: AKI = parent SKI.
// Registry: Certificate.issuer_ski, Certificate.subject_ski, CA.ca_ski
pred conf_s5_aki_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    some ca: CA, pc: Certificate |
        obj.cms.ee_certificate.issuer_ski != pc.subject_ski and
        s5_cert_verify_ok[obj, ca, pc]
}

// RC verifyIssuer L130: issuer DN = parent subject DN.
// Registry: Certificate.subject_name, Certificate.issuer_name
pred conf_s5_issuer_name_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    some ca: CA, pc: Certificate |
        obj.cms.ee_certificate.issuer_name != pc.subject_name and
        s5_cert_verify_ok[obj, ca, pc]
}

// CA delegation containment: RC verifyResources L68-71 (strict).
// Registry: Certificate.ip_resources, Certificate.as_resources, CA.delegated_prefixes, CA.delegated_asns
pred conf_s5_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    some ca: CA, pc: Certificate | {
        s5_cert_verify_ok[obj, ca, pc]
        (some p: obj.cms.ee_certificate.ip_resources |
            p not in ca.delegated_prefixes and p in victim_pp.owner.delegated_prefixes) or
        (some n: obj.cms.ee_certificate.as_resources |
            n not in ca.delegated_asns and n in victim_pp.owner.delegated_asns)
    }
}

// Inherit derives the parent's resources (RC deriveResources, L63).
// Registry: Certificate.resources_inherit
pred conf_s5_inherit_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_CA_CERT
    obj.cms.ee_certificate.resources_inherit = True
    some ca: CA, pc: Certificate | {
        s5_cert_verify_ok[obj, ca, pc]
        some (rv3_effective_prefixes[obj.cms.ee_certificate, ca] - ca.delegated_prefixes) or
        some (rv3_effective_asns[obj.cms.ee_certificate, ca] - ca.delegated_asns)
    }
}

// Only cA=true certificates become child contexts (:451-456); RC
// verifySignature L92 requires the parent to be a CA.
// Registry: Certificate.is_ca
pred conf_s5_is_ca_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.cms.ee_certificate.is_ca = False
    some ca: CA, pc: Certificate | s5_cert_acts_as_ca_ok[obj, ca, pc]
}

// =====================================================================
// S6 PayloadProcessing — ROA, ASPA (Conf + NI)
// =====================================================================
// Claims: V2 (the payload set is the entry list of the AKI-selected manifest),
// V1 (CMS and resource checks in rpki-commons).  ASPA is unsupported (header).
// Sources: CertificateTreeValidationService.java:354-456; ValidatedRpkiObjects
// .java:260-288; RC RoaCms, RoaCmsParser, RpkiSignedObjectParser.

// --- NI ---

// PAPER-CLAIM: V2 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/CertificateTreeValidationService.java:354
// A victim ROA that is emitted when the victim's own manifest is in use is not
// emitted when the AKI lookup returns an attacker-supplied manifest that fails
// validation: entries run only after the selected manifest validates (:346-356).
// Registry: MFTEntry.entry_hash, Certificate.issuer_ski, RPKIObject.content_hash
pred ni_s6_payload_resolution_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type = OT_ROA
    let ca = victim_pp.owner | {
        some vm: victim_pp.objects, pc: Certificate |
            rv3_mft_in_use[vm, ca, pc] and rv3_listed[vm, obj] and
            rv3_stored[obj] and rv3_chain_ok[obj, ca, pc]
        some m: rv3_mft_bucket[ca.ca_ski] & atk_pp.objects |
            no pc: Certificate | s3_mft_verify_ok[m, ca, pc]
    }
}

// Paper V2: payload objects live in the same global SKI-indexed store; an
// attacker ROA/ASPA with the victim EE SKI shares the slot.
// Registry: Certificate.subject_ski, ROAPayload.roa_prefixes
pred ni_s6_store_key_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    obj.obj_type in (OT_ROA + OT_ASPA)
    some a: atk_pp.objects |
        a.obj_type in (OT_ROA + OT_ASPA) and
        rv3_ski_key[a] = rv3_ski_key[obj] and
        (a.roa_payload != obj.roa_payload or a.aspa_payload != obj.aspa_payload)
}

// Registry: CMSSignedData.signer_infos
pred ni_s6_parse_signerinfos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type in (OT_ROA + OT_ASPA) and
        not (one a.cms.signer_infos) and
        victim_pp in rv3_failure_scope[a]
}

// Registry: Certificate.time_field_parse
pred ni_s6_parse_time_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type in (OT_ROA + OT_ASPA) and
        a.cms.ee_certificate.time_field_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// Registry: Certificate.pubkey_parse
pred ni_s6_parse_pubkey_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = victim_pp
    some a: atk_pp.objects |
        a.obj_type in (OT_ROA + OT_ASPA) and
        a.cms.ee_certificate.pubkey_parse = ParseFatal and
        victim_pp in rv3_failure_scope[a]
}

// --- Conf (one predicate per check) ---

// PAPER-CLAIM: V1 (supporting)
// SOURCE: vendor/rpki-validator-3/src/rpki-validator/src/main/java/net/ripe/rpki/validator3/domain/validation/CertificateTreeValidationService.java:443
// RC verifySignature L96 (EE under CA key) and L394 (CMS signature).
// Registry: CMSSignedData.signature_valid
pred conf_s6_roa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.signature_valid = False
    some ca: CA, pc: Certificate | s6_roa_verify_ok[obj, ca, pc]
}

// RC L394 (messageDigest = H(eContent)).
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
pred conf_s6_roa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    some ca: CA, pc: Certificate | s6_roa_verify_ok[obj, ca, pc]
}

// RC L330-332.
// Registry: CMSSignedData.sid_matches_ee
pred conf_s6_roa_cms_sid_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.sid_matches_ee = False
    some ca: CA, pc: Certificate | s6_roa_verify_ok[obj, ca, pc]
}

// RC RoaCmsParser.validateRoa L81-84 ("roa.content.type").
// Registry: CMSSignedData.econtent_type_matches
pred conf_s6_roa_econtent_type_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.econtent_type_matches = False
    some ca: CA, pc: Certificate | s6_roa_verify_ok[obj, ca, pc]
}

// RC L263.
// Registry: CMSSignedData.signer_infos
pred conf_s6_roa_signer_infos_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    not (one obj.cms.signer_infos)
    some ca: CA, pc: Certificate | s6_roa_verify_ok[obj, ca, pc]
}

// RC L157 (EE AKI = CA SKI) via RoaCms.validateWithCrl L90-91.
// Registry: CMSSignedData.ee_certificate, Certificate.issuer_ski, CA.ca_ski
pred conf_s6_roa_ee_cert_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    some ca: CA, pc: Certificate |
        aki[obj] != ca.ca_ski and s6_roa_verify_ok[obj, ca, pc]
}

// EE resource containment for the payload: RC RoaCmsParser.validateRoa L93.
// Registry: ROAPayload.roa_prefixes, Certificate.ip_resources
pred conf_s6_roa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    some p: obj.roa_payload.roa_prefixes - obj.cms.ee_certificate.ip_resources |
        p in victim_pp.owner.delegated_prefixes
    some ca: CA, pc: Certificate | s6_roa_verify_ok[obj, ca, pc]
}

// EE certificate within the issuing CA's delegation: RC verifyResources
// L68-71 via RoaCms.validateWithCrl L90-91 (strict validator).
// Registry: Certificate.ip_resources, Certificate.as_resources, CA.delegated_prefixes, CA.delegated_asns
pred conf_s6_ee_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    some ca: CA, pc: Certificate | {
        s6_roa_verify_ok[obj, ca, pc]
        (some p: obj.cms.ee_certificate.ip_resources |
            p not in ca.delegated_prefixes and p in victim_pp.owner.delegated_prefixes) or
        (some n: obj.cms.ee_certificate.as_resources |
            n not in ca.delegated_asns and n in victim_pp.owner.delegated_asns)
    }
}

// An inheriting EE derives the CA's resources (RC L63); a ROA under it still
// needs explicit EE resources (L93, containsResources L198).
// Registry: Certificate.resources_inherit, ROAPayload.roa_prefixes
pred conf_s6_ee_inherit_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ROA
    obj.cms.ee_certificate.resources_inherit = True
    some ca: CA, pc: Certificate | {
        s6_roa_verify_ok[obj, ca, pc]
        some (obj.roa_payload.roa_prefixes - rv3_effective_prefixes[obj.cms.ee_certificate, ca]) or
        some (rv3_effective_prefixes[obj.cms.ee_certificate, ca] - ca.delegated_prefixes)
    }
}

// ASPA (unsupported, header): no VAP can carry a forged digest.
// Registry: CMSSignedData.econtent_digest, CMSSignedData.signed_attrs_digest
pred conf_s6_aspa_cms_digest_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.econtent_digest != obj.cms.signed_attrs_digest
    some ca: CA, pc: Certificate | s6_aspa_verify_ok[obj, ca, pc]
}

// Registry: CMSSignedData.signature_valid
pred conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.cms.signature_valid = False
    some ca: CA, pc: Certificate | s6_aspa_verify_ok[obj, ca, pc]
}

// The customer AS is never consumed: .asa objects are not stored.
// Registry: ASPAPayload.customer_as, Certificate.as_resources
pred conf_s6_aspa_resource_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    obj.origin = atk_pp
    obj.obj_type = OT_ASPA
    obj.aspa_payload.customer_as not in obj.cms.ee_certificate.as_resources
    obj.aspa_payload.customer_as in victim_pp.owner.delegated_asns
    some ca: CA, pc: Certificate | s6_aspa_verify_ok[obj, ca, pc]
}

// =====================================================================
// Stage aggregates (every per-field predicate of a cell is OR'd in)
// =====================================================================

pred ni_s2_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s2_cache_workspace_violation[atk_pp, victim_pp, obj] or
    ni_s2_object_overwrite_violation[atk_pp, victim_pp, obj] or
    ni_s2_location_violation[atk_pp, victim_pp, obj] or
    ni_s2_fetch_scope_violation[atk_pp, victim_pp, obj]
}

pred ni_s3_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s3_manifest_lookup_violation[atk_pp, victim_pp, obj] or
    ni_s3_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_time_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_pubkey_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_mft_this_update_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_mft_next_update_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_signerinfos_violation[atk_pp, victim_pp, obj] or
    ni_s3_parse_mft_filename_violation[atk_pp, victim_pp, obj]
}

pred conf_s3_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s3_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s3_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s3_econtent_type_violation[atk_pp, victim_pp, obj] or
    conf_s3_signer_infos_violation[atk_pp, victim_pp, obj] or
    conf_s3_ee_cert_violation[atk_pp, victim_pp, obj] or
    conf_s3_ee_inherit_violation[atk_pp, victim_pp, obj] or
    conf_s3_mft_hash_violation[atk_pp, victim_pp, obj] or
    conf_s3_file_list_violation[atk_pp, victim_pp, obj]
}

pred ni_s4_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s4_crl_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s4_crl_scope_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_this_update_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_next_update_violation[atk_pp, victim_pp, obj] or
    ni_s4_parse_crl_revocation_date_violation[atk_pp, victim_pp, obj]
}

pred conf_s4_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s4_crl_signature_violation[atk_pp, victim_pp, obj] or
    conf_s4_crl_issuer_violation[atk_pp, victim_pp, obj] or
    conf_s4_revoked_serial_violation[atk_pp, victim_pp, obj]
}

pred ni_s5_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s5_chain_walk_violation[atk_pp, victim_pp, obj] or
    ni_s5_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s5_parent_resolution_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_repo_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_sia_mft_scope_violation[atk_pp, victim_pp, obj] or
    ni_s5_parse_time_violation[atk_pp, victim_pp, obj] or
    ni_s5_parse_pubkey_violation[atk_pp, victim_pp, obj]
}

pred conf_s5_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s5_signature_violation[atk_pp, victim_pp, obj] or
    conf_s5_aki_violation[atk_pp, victim_pp, obj] or
    conf_s5_issuer_name_violation[atk_pp, victim_pp, obj] or
    conf_s5_resource_violation[atk_pp, victim_pp, obj] or
    conf_s5_inherit_violation[atk_pp, victim_pp, obj] or
    conf_s5_is_ca_violation[atk_pp, victim_pp, obj]
}

pred ni_s6_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    ni_s6_payload_resolution_violation[atk_pp, victim_pp, obj] or
    ni_s6_store_key_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_signerinfos_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_time_violation[atk_pp, victim_pp, obj] or
    ni_s6_parse_pubkey_violation[atk_pp, victim_pp, obj]
}

pred conf_s6_violation[atk_pp, victim_pp: PP, obj: RPKIObject] {
    attack_context[atk_pp, victim_pp]
    conf_s6_roa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_cms_sid_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_econtent_type_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_signer_infos_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_ee_cert_violation[atk_pp, victim_pp, obj] or
    conf_s6_roa_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_ee_resource_violation[atk_pp, victim_pp, obj] or
    conf_s6_ee_inherit_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_digest_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_cms_signature_violation[atk_pp, victim_pp, obj] or
    conf_s6_aspa_resource_violation[atk_pp, victim_pp, obj]
}

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

assert s2_ni_cache_workspace { no a, v: PP, o: RPKIObject | ni_s2_cache_workspace_violation[a, v, o] }
assert s2_ni_object_overwrite { no a, v: PP, o: RPKIObject | ni_s2_object_overwrite_violation[a, v, o] }
assert s2_ni_location { no a, v: PP, o: RPKIObject | ni_s2_location_violation[a, v, o] }
assert s2_ni_fetch_scope { no a, v: PP, o: RPKIObject | ni_s2_fetch_scope_violation[a, v, o] }

assert s3_ni_manifest_lookup { no a, v: PP, o: RPKIObject | ni_s3_manifest_lookup_violation[a, v, o] }
assert s3_ni_store_key { no a, v: PP, o: RPKIObject | ni_s3_store_key_violation[a, v, o] }
assert s3_ni_parse_time { no a, v: PP, o: RPKIObject | ni_s3_parse_time_violation[a, v, o] }
assert s3_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s3_parse_pubkey_violation[a, v, o] }
assert s3_ni_parse_mft_this_update { no a, v: PP, o: RPKIObject | ni_s3_parse_mft_this_update_violation[a, v, o] }
assert s3_ni_parse_mft_next_update { no a, v: PP, o: RPKIObject | ni_s3_parse_mft_next_update_violation[a, v, o] }
assert s3_ni_parse_signerinfos { no a, v: PP, o: RPKIObject | ni_s3_parse_signerinfos_violation[a, v, o] }
assert s3_ni_parse_mft_filename { no a, v: PP, o: RPKIObject | ni_s3_parse_mft_filename_violation[a, v, o] }

assert s3_conf_cms_signature { no a, v: PP, o: RPKIObject | conf_s3_cms_signature_violation[a, v, o] }
assert s3_conf_cms_digest { no a, v: PP, o: RPKIObject | conf_s3_cms_digest_violation[a, v, o] }
assert s3_conf_cms_sid { no a, v: PP, o: RPKIObject | conf_s3_cms_sid_violation[a, v, o] }
assert s3_conf_econtent_type { no a, v: PP, o: RPKIObject | conf_s3_econtent_type_violation[a, v, o] }
assert s3_conf_signer_infos { no a, v: PP, o: RPKIObject | conf_s3_signer_infos_violation[a, v, o] }
assert s3_conf_ee_cert { no a, v: PP, o: RPKIObject | conf_s3_ee_cert_violation[a, v, o] }
assert s3_conf_ee_inherit { no a, v: PP, o: RPKIObject | conf_s3_ee_inherit_violation[a, v, o] }
assert s3_conf_mft_hash { no a, v: PP, o: RPKIObject | conf_s3_mft_hash_violation[a, v, o] }
assert s3_conf_file_list { no a, v: PP, o: RPKIObject | conf_s3_file_list_violation[a, v, o] }

assert s4_ni_crl_store_key { no a, v: PP, o: RPKIObject | ni_s4_crl_store_key_violation[a, v, o] }
assert s4_ni_crl_scope { no a, v: PP, o: RPKIObject | ni_s4_crl_scope_violation[a, v, o] }
assert s4_ni_parse_crl_this_update { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_this_update_violation[a, v, o] }
assert s4_ni_parse_crl_next_update { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_next_update_violation[a, v, o] }
assert s4_ni_parse_crl_revocation_date { no a, v: PP, o: RPKIObject | ni_s4_parse_crl_revocation_date_violation[a, v, o] }

assert s4_conf_crl_signature { no a, v: PP, o: RPKIObject | conf_s4_crl_signature_violation[a, v, o] }
assert s4_conf_crl_issuer { no a, v: PP, o: RPKIObject | conf_s4_crl_issuer_violation[a, v, o] }
assert s4_conf_revoked_serial { no a, v: PP, o: RPKIObject | conf_s4_revoked_serial_violation[a, v, o] }

assert s5_ni_chain_walk { no a, v: PP, o: RPKIObject | ni_s5_chain_walk_violation[a, v, o] }
assert s5_ni_store_key { no a, v: PP, o: RPKIObject | ni_s5_store_key_violation[a, v, o] }
assert s5_ni_parent_resolution { no a, v: PP, o: RPKIObject | ni_s5_parent_resolution_violation[a, v, o] }
assert s5_ni_sia_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_scope_violation[a, v, o] }
assert s5_ni_sia_repo_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_repo_scope_violation[a, v, o] }
assert s5_ni_sia_mft_scope { no a, v: PP, o: RPKIObject | ni_s5_sia_mft_scope_violation[a, v, o] }
assert s5_ni_parse_time { no a, v: PP, o: RPKIObject | ni_s5_parse_time_violation[a, v, o] }
assert s5_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s5_parse_pubkey_violation[a, v, o] }

assert s5_conf_signature { no a, v: PP, o: RPKIObject | conf_s5_signature_violation[a, v, o] }
assert s5_conf_aki { no a, v: PP, o: RPKIObject | conf_s5_aki_violation[a, v, o] }
assert s5_conf_issuer_name { no a, v: PP, o: RPKIObject | conf_s5_issuer_name_violation[a, v, o] }
assert s5_conf_resource { no a, v: PP, o: RPKIObject | conf_s5_resource_violation[a, v, o] }
assert s5_conf_inherit { no a, v: PP, o: RPKIObject | conf_s5_inherit_violation[a, v, o] }
assert s5_conf_is_ca { no a, v: PP, o: RPKIObject | conf_s5_is_ca_violation[a, v, o] }

assert s6_ni_payload_resolution { no a, v: PP, o: RPKIObject | ni_s6_payload_resolution_violation[a, v, o] }
assert s6_ni_store_key { no a, v: PP, o: RPKIObject | ni_s6_store_key_violation[a, v, o] }
assert s6_ni_parse_signerinfos { no a, v: PP, o: RPKIObject | ni_s6_parse_signerinfos_violation[a, v, o] }
assert s6_ni_parse_time { no a, v: PP, o: RPKIObject | ni_s6_parse_time_violation[a, v, o] }
assert s6_ni_parse_pubkey { no a, v: PP, o: RPKIObject | ni_s6_parse_pubkey_violation[a, v, o] }

assert s6_conf_roa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_signature_violation[a, v, o] }
assert s6_conf_roa_cms_digest { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_digest_violation[a, v, o] }
assert s6_conf_roa_cms_sid { no a, v: PP, o: RPKIObject | conf_s6_roa_cms_sid_violation[a, v, o] }
assert s6_conf_roa_econtent_type { no a, v: PP, o: RPKIObject | conf_s6_roa_econtent_type_violation[a, v, o] }
assert s6_conf_roa_signer_infos { no a, v: PP, o: RPKIObject | conf_s6_roa_signer_infos_violation[a, v, o] }
assert s6_conf_roa_ee_cert { no a, v: PP, o: RPKIObject | conf_s6_roa_ee_cert_violation[a, v, o] }
assert s6_conf_roa_resource { no a, v: PP, o: RPKIObject | conf_s6_roa_resource_violation[a, v, o] }
assert s6_conf_ee_resource { no a, v: PP, o: RPKIObject | conf_s6_ee_resource_violation[a, v, o] }
assert s6_conf_ee_inherit { no a, v: PP, o: RPKIObject | conf_s6_ee_inherit_violation[a, v, o] }
assert s6_conf_aspa_cms_digest { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_digest_violation[a, v, o] }
assert s6_conf_aspa_cms_signature { no a, v: PP, o: RPKIObject | conf_s6_aspa_cms_signature_violation[a, v, o] }
assert s6_conf_aspa_resource { no a, v: PP, o: RPKIObject | conf_s6_aspa_resource_violation[a, v, o] }

// =====================================================================
// Table 2 obligations (nine cells) and the overall property
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

// Aggregate soundness: every per-field violation is contained in its stage
// aggregate, and every stage aggregate in cross_pp_security, so no per-field
// check can be SAT while its cell's aggregate is UNSAT.
assert aggregate_soundness {
    all a, v: PP, o: RPKIObject {
        (ni_s2_cache_workspace_violation[a, v, o] or ni_s2_object_overwrite_violation[a, v, o] or
         ni_s2_location_violation[a, v, o] or ni_s2_fetch_scope_violation[a, v, o])
            implies ni_s2_violation[a, v, o]
        (ni_s3_manifest_lookup_violation[a, v, o] or ni_s3_store_key_violation[a, v, o] or
         ni_s3_parse_time_violation[a, v, o] or ni_s3_parse_pubkey_violation[a, v, o] or
         ni_s3_parse_mft_this_update_violation[a, v, o] or ni_s3_parse_mft_next_update_violation[a, v, o] or
         ni_s3_parse_signerinfos_violation[a, v, o] or ni_s3_parse_mft_filename_violation[a, v, o])
            implies ni_s3_violation[a, v, o]
        (conf_s3_cms_signature_violation[a, v, o] or conf_s3_cms_digest_violation[a, v, o] or
         conf_s3_cms_sid_violation[a, v, o] or conf_s3_econtent_type_violation[a, v, o] or
         conf_s3_signer_infos_violation[a, v, o] or conf_s3_ee_cert_violation[a, v, o] or
         conf_s3_ee_inherit_violation[a, v, o] or conf_s3_mft_hash_violation[a, v, o] or
         conf_s3_file_list_violation[a, v, o])
            implies conf_s3_violation[a, v, o]
        (ni_s4_crl_store_key_violation[a, v, o] or ni_s4_crl_scope_violation[a, v, o] or
         ni_s4_parse_crl_this_update_violation[a, v, o] or ni_s4_parse_crl_next_update_violation[a, v, o] or
         ni_s4_parse_crl_revocation_date_violation[a, v, o])
            implies ni_s4_violation[a, v, o]
        (conf_s4_crl_signature_violation[a, v, o] or conf_s4_crl_issuer_violation[a, v, o] or
         conf_s4_revoked_serial_violation[a, v, o])
            implies conf_s4_violation[a, v, o]
        (ni_s5_chain_walk_violation[a, v, o] or ni_s5_store_key_violation[a, v, o] or
         ni_s5_parent_resolution_violation[a, v, o] or ni_s5_sia_scope_violation[a, v, o] or
         ni_s5_sia_repo_scope_violation[a, v, o] or ni_s5_sia_mft_scope_violation[a, v, o] or
         ni_s5_parse_time_violation[a, v, o] or ni_s5_parse_pubkey_violation[a, v, o])
            implies ni_s5_violation[a, v, o]
        (conf_s5_signature_violation[a, v, o] or conf_s5_aki_violation[a, v, o] or
         conf_s5_issuer_name_violation[a, v, o] or conf_s5_resource_violation[a, v, o] or
         conf_s5_inherit_violation[a, v, o] or conf_s5_is_ca_violation[a, v, o])
            implies conf_s5_violation[a, v, o]
        (ni_s6_payload_resolution_violation[a, v, o] or ni_s6_store_key_violation[a, v, o] or
         ni_s6_parse_signerinfos_violation[a, v, o] or ni_s6_parse_time_violation[a, v, o] or
         ni_s6_parse_pubkey_violation[a, v, o])
            implies ni_s6_violation[a, v, o]
        (conf_s6_roa_cms_signature_violation[a, v, o] or conf_s6_roa_cms_digest_violation[a, v, o] or
         conf_s6_roa_cms_sid_violation[a, v, o] or conf_s6_roa_econtent_type_violation[a, v, o] or
         conf_s6_roa_signer_infos_violation[a, v, o] or conf_s6_roa_ee_cert_violation[a, v, o] or
         conf_s6_roa_resource_violation[a, v, o] or conf_s6_ee_resource_violation[a, v, o] or
         conf_s6_ee_inherit_violation[a, v, o] or conf_s6_aspa_cms_digest_violation[a, v, o] or
         conf_s6_aspa_cms_signature_violation[a, v, o] or conf_s6_aspa_resource_violation[a, v, o])
            implies conf_s6_violation[a, v, o]
        (ni_s2_violation[a, v, o] or ni_s3_violation[a, v, o] or ni_s4_violation[a, v, o] or
         ni_s5_violation[a, v, o] or ni_s6_violation[a, v, o] or conf_s3_violation[a, v, o] or
         conf_s4_violation[a, v, o] or conf_s5_violation[a, v, o] or conf_s6_violation[a, v, o])
            implies any_violation[a, v, o]
    }
}

// =====================================================================
// Non-vacuity witnesses (runs, not obligations): every acceptance path that a
// Conf check negates is reachable, so each UNSAT comes from the one check the
// predicate falsifies.  The replay run shows that byte-identical public
// replay (paper §3.1) is representable and accepted as the victim's object.
// =====================================================================

pred nonvacuous_s3_mft_accepted {
    some m: AttackerPP.objects, pc: Certificate | rv3_mft_in_use[m, AttackerCA, pc]
}

pred nonvacuous_s4_crl_accepted {
    some crl: AttackerPP.objects | s4_crl_verify_ok[crl, AttackerCA]
}

pred nonvacuous_s5_cert_accepted {
    some c: AttackerPP.objects, pc: Certificate | s5_cert_acts_as_ca_ok[c, AttackerCA, pc]
}

pred nonvacuous_s6_roa_accepted {
    some r: AttackerPP.objects, pc: Certificate | s6_roa_verify_ok[r, AttackerCA, pc]
}

pred nonvacuous_s6_replay_accepted {
    some r: AttackerPP.objects, pc: Certificate | s6_roa_verify_ok[r, VictimCA, pc]
}

// =====================================================================
// Bounded checks — one per assertion; every reachable signature is scoped
// =====================================================================

check s2_ni_cache_workspace for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s2_ni_object_overwrite for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s2_ni_location for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s2_ni_fetch_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_manifest_lookup for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_time for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_mft_this_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_mft_next_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_signerinfos for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_ni_parse_mft_filename for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_signer_infos for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_ee_cert for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_ee_inherit for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_mft_hash for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s3_conf_file_list for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_crl_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_crl_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_this_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_next_update for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_ni_parse_crl_revocation_date for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf_crl_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf_crl_issuer for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s4_conf_revoked_serial for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_chain_walk for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_parent_resolution for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_repo_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_sia_mft_scope for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_parse_time for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_aki for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_issuer_name for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_inherit for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s5_conf_is_ca for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_payload_resolution for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_store_key for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_signerinfos for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_time for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_ni_parse_pubkey for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_cms_sid for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_econtent_type for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_signer_infos for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_ee_cert for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_roa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_ee_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_ee_inherit for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_cms_digest for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_cms_signature for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
check s6_conf_aspa_resource for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
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
check aggregate_soundness for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

run nonvacuous_s3_mft_accepted for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
run nonvacuous_s4_crl_accepted for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
run nonvacuous_s5_cert_accepted for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
run nonvacuous_s6_roa_accepted for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
run nonvacuous_s6_replay_accepted for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification

// topo.model_satisfiable: a valid public replay must be representable;
// UNSAT here would make every UNSAT check above vacuous.
run model_satisfiable for 2 PP, 4 RPKIObject, 4 CMSSignedData, 4 Certificate, 3 SignerInfo, 3 Prefix, 2 ASN, 3 KeyId, 3 URI, 3 Hash, 2 CA, 1 Attacker, 3 Host, 2 ParseOutcome, 2 Name, 2 SerialNumber, 1 RRDPSessionId, 1 RRDPSerial, 2 ROAPayload, 1 ASPAPayload, 3 MFTEntry, 2 MFTPayload, 2 CRLPayload, 2 RRDPNotification
