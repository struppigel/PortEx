/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package io.github.struppigel.parser.sections.cert;

import io.github.struppigel.parser.Interruption;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.sections.cert.ParseContext.IssueSink;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Parses PKCS#7 SignedData structures: Authenticode signatures, nested
 * signatures, legacy countersignatures and RFC 3161 timestamp tokens.
 * <p>
 * Every part that fails to parse is reported as issue and skipped, so one
 * malformed certificate or attribute does not hide the rest of the signature.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class SignedDataParser {

    /** the role of a SignerInfo, which determines the expected attributes */
    private enum Role {
        AUTHENTICODE, COUNTERSIGNER, TIMESTAMP_TOKEN
    }

    /** more nested signatures per signer than this are unusual */
    private static final int UNUSUAL_NESTED_COUNT = 8;

    private final ParseContext ctx;
    private final boolean berDocument;

    /**
     * @param ctx         the parse context of the table
     * @param berDocument true iff the DER document of the entry uses BER
     */
    SignedDataParser(ParseContext ctx, boolean berDocument) {
        this.ctx = ctx;
        this.berDocument = berDocument;
    }

    /** The generic fields of a SignedData. */
    private static final class Content {
        private int version;
        private final List<AlgorithmId> digestAlgorithms = new ArrayList<>();
        private String eContentType;
        private DerElement eContent;
        private DerElement certificates;
        private DerElement signerInfos;
    }

    /* ------------------------------ Authenticode ------------------------------ */

    /**
     * Parses an Authenticode signature.
     *
     * @param contentInfo  the ContentInfo element
     * @param entryIndex   the index of the WIN_CERTIFICATE
     * @param nestingLevel 0 for the top level signature
     * @param parentNumber the number of the signature this one is nested in,
     *                     0 if none
     * @return the signature, null if it could not be parsed
     */
    AuthenticodeSignature parseAuthenticode(DerElement contentInfo, int entryIndex, int nestingLevel,
                                            int parentNumber) {
        Interruption.checkInterrupt();
        int number = ctx.nextSignatureNumber();
        IssueSink sink = ctx.sink();
        String label = "signature " + number + (parentNumber > 0 ? " (nested in " + parentNumber + ")" : "");
        if (number > CertificateTable.MAX_SIGNATURES) {
            sink.add(CertificateIssueType.LIMIT_EXCEEDED, label + ": more than " + CertificateTable.MAX_SIGNATURES
                    + " signatures, the rest is not parsed", contentInfo.location(), null);
            return null;
        }
        Content content;
        try {
            content = parseContent(contentInfo, sink, label, Oids.SPC_INDIRECT_DATA);
        } catch (DerException e) {
            sink.addDerException(label, e);
            return null;
        }
        if (content == null) {
            return null;
        }

        AlgorithmId imageAlgorithm = null;
        DerElement imageDigest = null;
        DerElement indirect = null;
        PageHashes pageHashes = null;
        if (Oids.SPC_INDIRECT_DATA.equals(content.eContentType)) {
            if (content.eContent == null) {
                sink.add(CertificateIssueType.MALFORMED_PKCS7, label + ": SpcIndirectDataContent is missing",
                        contentInfo.location(), AuthenticodeFieldKey.IMAGE_DIGEST);
            } else {
                try {
                    indirect = content.eContent.expectSequence();
                    DerElement data = indirect.child(0).expectSequence();
                    String dataType = sink.oid(data.child(0));
                    if (!Oids.SPC_PE_IMAGE_DATA.equals(dataType)) {
                        sink.add(CertificateIssueType.WRONG_CONTENT_TYPE, label + ": the signed content describes "
                                        + Oids.nameOrOid(dataType) + " instead of SpcPeImageData",
                                data.child(0).location(), AuthenticodeFieldKey.CONTENT_TYPE);
                    } else if (data.optChild(1).isPresent()) {
                        pageHashes = parsePageHashes(data.child(1), sink, label);
                    }
                    DerElement digestInfo = indirect.child(1).expectSequence();
                    imageAlgorithm = sink.algorithm(digestInfo.child(0), true);
                    imageDigest = digestInfo.child(1).expect(DerElement.OCTET_STRING);
                    if (imageDigest.isConstructed()) {
                        throw new DerException("constructed image digest", imageDigest.fileOffset());
                    }
                } catch (DerException e) {
                    sink.addDerException(label + ": SpcIndirectDataContent", e);
                }
            }
        }

        List<AuthenticodeCertificate> bag = parseCertificates(content.certificates, sink, label);
        List<SignerInfo> signers = new ArrayList<>();
        List<AuthenticodeSignature> nested = new ArrayList<>();
        int signerCount = content.signerInfos.childCount();
        if (signerCount != 1) {
            sink.add(CertificateIssueType.UNUSUAL_SIGNER_COUNT, label + " has " + signerCount
                    + " signers, Authenticode requires exactly one", content.signerInfos.location(), null);
        }
        int index = 0;
        for (DerElement si : content.signerInfos.children()) {
            if (++index > CertificateTable.MAX_SIGNERS) {
                sink.add(CertificateIssueType.LIMIT_EXCEEDED, label + ": more than "
                        + CertificateTable.MAX_SIGNERS + " signers, the rest is not parsed", si.location(), null);
                break;
            }
            try {
                signers.add(parseSigner(si, bag, Collections.<AuthenticodeCertificate>emptyList(),
                        Role.AUTHENTICODE, sink, label, entryIndex, nestingLevel, number, nested));
            } catch (DerException e) {
                sink.addDerException(label + ": signer " + index, e);
            }
        }

        checkDigestConsistency(content, imageAlgorithm, signers, sink, label);
        checkAlgorithms(imageAlgorithm, imageDigest, signers, bag, sink, label);
        checkIsolatedCertificates(bag, signers, sink, label);
        checkSignerCertificates(signers, sink, label);

        return new AuthenticodeSignature(entryIndex, nestingLevel, number, parentNumber, contentInfo,
                content.eContentType, content.version, content.digestAlgorithms, imageAlgorithm, imageDigest,
                indirect, pageHashes, bag, signers, nested, berDocument, sink.issues());
    }

    /**
     * Parses the generic part of a ContentInfo with SignedData.
     *
     * @return the content, null if the ContentInfo is no SignedData
     */
    private Content parseContent(DerElement contentInfo, IssueSink sink, String label,
                                 String expectedContentType) throws DerException {
        contentInfo.expectSequence();
        String type = sink.oid(contentInfo.child(0));
        if (!Oids.SIGNED_DATA.equals(type)) {
            sink.add(CertificateIssueType.WRONG_CONTENT_TYPE, label + ": the content type is "
                            + Oids.nameOrOid(type) + " instead of signedData",
                    contentInfo.child(0).location(), AuthenticodeFieldKey.CONTENT_TYPE);
            return null;
        }
        DerElement wrapper = contentInfo.child(1);
        if (!wrapper.isContext(0)) {
            throw new DerException("expected [0] content but found " + wrapper.tagName(), wrapper.fileOffset());
        }
        extraElements(contentInfo, 2, label + ": the ContentInfo", sink);
        extraElements(wrapper, 1, label + ": the content of the ContentInfo", sink);
        DerElement sd = wrapper.explicitContent().expectSequence();
        Content content = new Content();
        content.version = sd.child(0).asSmallInteger();
        DerElement algorithms = sd.child(1).expectSet();
        int count = 0;
        for (DerElement alg : algorithms.children()) {
            if (++count > CertificateTable.MAX_ATTRIBUTES) {
                break;
            }
            content.digestAlgorithms.add(sink.algorithm(alg, true));
        }
        DerElement encap = sd.child(2).expectSequence();
        content.eContentType = sink.oid(encap.child(0));
        Optional<DerElement> eContent = encap.optChild(1);
        if (eContent.isPresent() && eContent.get().isContext(0)) {
            content.eContent = eContent.get().explicitContent();
            extraElements(eContent.get(), 1, label + ": the content of the EncapsulatedContentInfo", sink);
        }
        extraElements(encap, 2, label + ": the EncapsulatedContentInfo", sink);
        for (int i = 3; i < sd.childCount(); i++) {
            DerElement c = sd.child(i);
            if (c.isContext(0) && c.isConstructed()) {
                content.certificates = c;
            } else if (c.isSet()) {
                content.signerInfos = c;
            }
        }
        if (content.signerInfos == null) {
            throw new DerException("SignedData has no SignerInfos", sd.fileOffset());
        }
        // after the certificates [0] and CRLs [1] the SignerInfos are the last element (RFC 5652)
        List<DerElement> extra = new ArrayList<>();
        int expected = 0; // 0: certificates may follow, 1: CRLs may follow, 2: only the SignerInfos
        for (int i = 3; i < sd.childCount(); i++) {
            DerElement c = sd.child(i);
            if (c == content.signerInfos) {
                expected = 3;
            } else if (expected == 0 && c.isContext(0) && c.isConstructed()) {
                expected = 1;
            } else if (expected <= 1 && c.isContext(1) && c.isConstructed()) {
                expected = 2;
            } else {
                extra.add(c);
            }
        }
        extraElements(extra, label + ": the SignedData", sink);
        if (expectedContentType != null && !expectedContentType.equals(content.eContentType)) {
            sink.add(CertificateIssueType.WRONG_CONTENT_TYPE, label + ": the signed content type is "
                            + Oids.nameOrOid(content.eContentType) + " instead of "
                            + Oids.nameOrOid(expectedContentType),
                    encap.child(0).location(), AuthenticodeFieldKey.CONTENT_TYPE);
        }
        return content;
    }

    private List<AuthenticodeCertificate> parseCertificates(DerElement certificates, IssueSink sink,
                                                            String label) {
        List<AuthenticodeCertificate> result = new ArrayList<>();
        if (certificates == null) {
            return result;
        }
        int n = 0;
        for (DerElement c : certificates.children()) {
            if (!c.isSequence()) {
                continue; // other CertificateChoices, e.g. attribute certificates
            }
            if (++n > CertificateTable.MAX_CERTIFICATES) {
                sink.add(CertificateIssueType.LIMIT_EXCEEDED, label + ": more than "
                        + CertificateTable.MAX_CERTIFICATES + " certificates, the rest is not parsed",
                        c.location(), null);
                break;
            }
            Interruption.checkInterrupt();
            try {
                result.add(CertificateParser.parse(c, sink));
            } catch (DerException e) {
                sink.addDerException(label + ": certificate " + n, e);
            }
        }
        return result;
    }

    /* ------------------------------- SignerInfo ------------------------------- */

    private SignerInfo parseSigner(DerElement si, List<AuthenticodeCertificate> bag,
                                   List<AuthenticodeCertificate> fallbackBag, Role role, IssueSink sink,
                                   String label, int entryIndex, int nestingLevel, int number,
                                   List<AuthenticodeSignature> nestedOut) throws DerException {
        si.expectSequence();
        int i = 0;
        int version = si.child(i++).asSmallInteger();
        DerElement sid = si.child(i++);
        String issuerName = "";
        byte[] serial = null;
        byte[] ski = null;
        DerElement issuer = null;
        if (sid.isSequence()) {
            issuer = sid.child(0).expectSequence();
            issuerName = NameRenderer.render(issuer);
            serial = sid.child(1).integerBytes(CertificateTable.MAX_INTEGER_LENGTH);
        } else if (sid.isContext(0) && !sid.isConstructed()) {
            ski = sid.content();
        } else {
            throw new DerException("unknown signer identifier " + sid.tagName(), sid.fileOffset());
        }
        AlgorithmId digestAlgorithm = sink.algorithm(si.child(i++), true);
        DerElement signedAttributes = null;
        if (si.child(i).isContext(0)) {
            signedAttributes = si.child(i++);
        }
        AlgorithmId rawSignatureAlgorithm = sink.algorithm(si.child(i++), false);
        DerElement signatureValue = si.child(i++).expect(DerElement.OCTET_STRING);
        if (signatureValue.isConstructed()) {
            throw new DerException("constructed signature value", signatureValue.fileOffset());
        }
        String who = role == Role.AUTHENTICODE ? label + ": signer"
                : role == Role.COUNTERSIGNER ? label + ": countersigner" : label + ": timestamp signer";
        DerElement unauthenticated = null;
        if (i < si.childCount() && si.child(i).isContext(1)) {
            unauthenticated = si.child(i++);
        }
        extraElements(si, i, who + " (SignerInfo)", sink);
        String jdkSignature = Algorithms.signatureJdkName(rawSignatureAlgorithm.getOid(),
                digestAlgorithm.getOid()).orElse(null);
        AlgorithmId signatureAlgorithm = new AlgorithmId(rawSignatureAlgorithm.getOid(), jdkSignature,
                rawSignatureAlgorithm.parameters(), rawSignatureAlgorithm.getLocation());

        AuthenticodeCertificate certificate = findCertificate(bag, issuer, serial, ski)
                .orElse(findCertificate(fallbackBag, issuer, serial, ski).orElse(null));
        if (certificate == null) {
            sink.add(CertificateIssueType.MISSING_SIGNER_CERTIFICATE, who + " certificate (issuer "
                            + (issuerName.isEmpty() ? "unknown" : issuerName) + ") is not embedded",
                    sid.location(), AuthenticodeFieldKey.SIGNER_CERTIFICATE);
        }

        /* signed attributes */
        List<SignatureAttribute> signedList = parseAttributes(signedAttributes, true, sink, who);
        DerElement messageDigest = null;
        Instant signingTime = null;
        String programName = null;
        String moreInfoUrl = null;
        String contentTypeAttribute = null;
        for (SignatureAttribute attribute : signedList) {
            DerElement values = attribute.valueSet();
            if (values == null || values.childCount() == 0) {
                continue;
            }
            DerElement value = values.child(0);
            try {
                switch (attribute.getOid()) {
                    case Oids.CONTENT_TYPE:
                        contentTypeAttribute = sink.oid(value);
                        break;
                    case Oids.MESSAGE_DIGEST:
                        value.expect(DerElement.OCTET_STRING);
                        if (value.isConstructed()) {
                            throw new DerException("constructed messageDigest", value.fileOffset());
                        }
                        messageDigest = value;
                        break;
                    case Oids.SIGNING_TIME:
                        signingTime = value.asTime().orElse(null);
                        break;
                    case Oids.SPC_SP_OPUS_INFO:
                        for (DerElement c : value.expectSequence().children()) {
                            if (c.isContext(0) && c.isConstructed()) {
                                programName = spcString(c.explicitContent());
                            } else if (c.isContext(1) && c.isConstructed()) {
                                moreInfoUrl = spcLink(c.explicitContent());
                            }
                        }
                        break;
                    case Oids.SPC_RELAXED_PE_MARKER_CHECK:
                        relaxedMarker(attribute, sink, who);
                        break;
                    default:
                        break;
                }
            } catch (DerException e) {
                sink.addDerException(who + " attribute " + Oids.nameOrOid(attribute.getOid()), e);
            }
        }
        checkRequiredAttributes(role, signedAttributes, contentTypeAttribute, messageDigest, si, sink, who);

        /* unauthenticated attributes */
        List<SignatureAttribute> unauthList = parseAttributes(unauthenticated, false, sink, who);
        List<Timestamp> timestamps = new ArrayList<>();
        boolean intentToSeal = false;
        for (SignatureAttribute attribute : signedList) {
            intentToSeal |= Oids.INTENT_TO_SEAL.equals(attribute.getOid());
        }
        for (SignatureAttribute attribute : unauthList) {
            if (attribute.getSize() > CertificateTable.LARGE_UNAUTHENTICATED_ATTRIBUTE_SIZE) {
                sink.add(CertificateIssueType.LARGE_UNAUTH_ATTRIBUTE, who + ": unauthenticated attribute "
                                + Oids.nameOrOid(attribute.getOid()) + " has " + attribute.getSize()
                                + " bytes, data outside of the signature",
                        attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
            }
            if (role != Role.AUTHENTICODE) {
                notUsedByRole(attribute, sink, who);
                continue;
            }
            try {
                interpretUnauthenticated(attribute, bag, sink, who, label, entryIndex, nestingLevel, number,
                        timestamps, nestedOut, intentToSeal);
            } catch (DerException e) {
                sink.addDerException(who + " attribute " + Oids.nameOrOid(attribute.getOid()), e);
            }
        }
        return new SignerInfo(si, version, issuerName, serial, ski, digestAlgorithm, signatureAlgorithm,
                jdkSignature, signedList, unauthList, signedAttributes, messageDigest, signingTime, programName,
                moreInfoUrl, timestamps, certificate, signatureValue);
    }

    private void interpretUnauthenticated(SignatureAttribute attribute, List<AuthenticodeCertificate> bag,
                                          IssueSink sink, String who, String label, int entryIndex,
                                          int nestingLevel, int number, List<Timestamp> timestamps,
                                          List<AuthenticodeSignature> nestedOut, boolean intentToSeal)
            throws DerException {
        DerElement values = attribute.valueSet();
        if (values == null) {
            throw new DerException("attribute without value set", attribute.element().fileOffset());
        }
        switch (attribute.getOid()) {
            case Oids.COUNTER_SIGNATURE:
                for (DerElement value : values.children()) {
                    if (!roomForTimestamp(timestamps, value, sink, who)) {
                        break;
                    }
                    try {
                        SignerInfo countersigner = parseSigner(value, bag, Collections.<AuthenticodeCertificate>emptyList(),
                                Role.COUNTERSIGNER, sink, label, entryIndex, nestingLevel, number, nestedOut);
                        timestamps.add(new Timestamp(Timestamp.Kind.COUNTERSIGNATURE,
                                countersigner.getSigningTime().orElse(null), countersigner,
                                Collections.<AuthenticodeCertificate>emptyList(), countersigner.getDigestAlgorithm(),
                                countersigner.messageDigestElement(), null, null, value, null));
                    } catch (DerException e) {
                        sink.addDerException(who + " countersignature", e);
                    }
                }
                break;
            case Oids.MS_RFC3161_TIMESTAMP:
            case Oids.TIMESTAMP_TOKEN:
                for (DerElement value : values.children()) {
                    if (!roomForTimestamp(timestamps, value, sink, who)) {
                        break;
                    }
                    try {
                        Timestamp t = parseRfc3161(value, bag, sink, label);
                        if (t != null) {
                            timestamps.add(t);
                        }
                    } catch (DerException e) {
                        sink.addDerException(who + " RFC 3161 timestamp", e);
                    }
                }
                break;
            case Oids.NESTED_SIGNATURE:
                int level = nestingLevel + 1;
                if (level > 1 || values.childCount() > UNUSUAL_NESTED_COUNT) {
                    sink.add(CertificateIssueType.UNUSUAL_NESTING, who + " has " + values.childCount()
                                    + " nested signature(s) at nesting level " + level,
                            attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
                }
                if (level > CertificateTable.MAX_NESTING_DEPTH) {
                    sink.add(CertificateIssueType.LIMIT_EXCEEDED, who + ": signatures nested deeper than "
                            + CertificateTable.MAX_NESTING_DEPTH + " levels are not parsed",
                            attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
                    break;
                }
                for (DerElement value : values.children()) {
                    AuthenticodeSignature signature = parseAuthenticode(value, entryIndex, level, number);
                    if (signature != null) {
                        nestedOut.add(signature);
                    }
                }
                break;
            case Oids.SPC_RELAXED_PE_MARKER_CHECK:
                relaxedMarker(attribute, sink, who);
                signedAttributeType(attribute, sink, who);
                break;
            case Oids.INTENT_TO_SEAL:
            case Oids.PLATFORM_MANIFEST_BINARY_ID:
                signedAttributeType(attribute, sink, who);
                break;
            case Oids.SEALING_SIGNATURE:
            case Oids.SEALING_TIMESTAMP:
                // signtool seals a signature in a second step if the signer has the signed attribute intent to seal
                if (!intentToSeal) {
                    sink.add(CertificateIssueType.UNEXPECTED_UNAUTH_ATTRIBUTE, who + " has the unauthenticated"
                                    + " attribute " + Oids.nameOrOid(attribute.getOid())
                                    + " without the signed attribute intent to seal",
                            attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
                }
                extraElements(values, 1, who + " attribute " + Oids.nameOrOid(attribute.getOid()), sink);
                break;
            case Oids.SPC_ENCRYPTED_DIGEST_RETRY_COUNT:
                extraElements(values, 1, who + " attribute " + Oids.nameOrOid(attribute.getOid()), sink);
                if (values.childCount() > 0) {
                    values.child(0).asSmallInteger();
                }
                break;
            default:
                sink.add(CertificateIssueType.UNKNOWN_UNAUTH_ATTRIBUTE, who + " has the unknown unauthenticated"
                                + " attribute " + attribute.getOid() + ", which is not covered by the signature",
                        attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
                break;
        }
    }

    private boolean roomForTimestamp(List<Timestamp> timestamps, DerElement value, IssueSink sink, String who) {
        if (timestamps.size() >= CertificateTable.MAX_TIMESTAMPS) {
            sink.add(CertificateIssueType.LIMIT_EXCEEDED, who + ": more than " + CertificateTable.MAX_TIMESTAMPS
                    + " timestamps, the rest is not parsed", value.location(), AuthenticodeFieldKey.TIMESTAMP);
            return false;
        }
        return true;
    }

    private static void relaxedMarker(SignatureAttribute attribute, IssueSink sink, String who) {
        sink.add(CertificateIssueType.RELAXED_PE_MARKER_CHECK, who + " has the SpcRelaxedPEMarkerCheck attribute",
                attribute.getLocation(), attribute.isAuthenticated() ? AuthenticodeFieldKey.SIGNED_ATTRIBUTES
                        : AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
    }

    /** reports an attribute that signers have as signed attribute, but that is unauthenticated here */
    private static void signedAttributeType(SignatureAttribute attribute, IssueSink sink, String who) {
        sink.add(CertificateIssueType.UNEXPECTED_UNAUTH_ATTRIBUTE, who + " has " + Oids.nameOrOid(attribute.getOid())
                        + " as unauthenticated attribute, it is a signed attribute and here the signature does"
                        + " not cover it",
                attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
    }

    /** countersigners and timestamp signers of Authenticode signatures have no unauthenticated attributes */
    private static void notUsedByRole(SignatureAttribute attribute, IssueSink sink, String who) {
        if (Oids.name(attribute.getOid()).isPresent()) {
            sink.add(CertificateIssueType.UNEXPECTED_UNAUTH_ATTRIBUTE, who + " has the unauthenticated attribute "
                            + Oids.nameOrOid(attribute.getOid()) + ", Authenticode does not use unauthenticated"
                            + " attributes there and its content is not parsed",
                    attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
        } else {
            sink.add(CertificateIssueType.UNKNOWN_UNAUTH_ATTRIBUTE, who + " has the unknown unauthenticated"
                            + " attribute " + attribute.getOid() + ", which is not covered by the signature",
                    attribute.getLocation(), AuthenticodeFieldKey.UNAUTHENTICATED_ATTRIBUTES);
        }
    }

    /** reports the children of the parent from the index on, which its format does not define */
    private static void extraElements(DerElement parent, int from, String what, IssueSink sink) {
        List<DerElement> children = parent.children();
        if (children.size() > from) {
            extraElements(children.subList(from, children.size()), what, sink);
        }
    }

    /** reports elements that the format of a structure does not define, e.g. hidden data */
    private static void extraElements(List<DerElement> extra, String what, IssueSink sink) {
        if (extra.isEmpty()) {
            return;
        }
        List<PhysicalLocation> locations = new ArrayList<>();
        long bytes = 0;
        for (DerElement e : extra) {
            locations.add(e.location());
            bytes += e.encodedLength();
        }
        sink.add(CertificateIssueType.EXTRA_SIGNATURE_ELEMENT, what + " has " + extra.size() + " element(s) with "
                        + bytes + " bytes at " + Hex.offset(extra.get(0).fileOffset())
                        + " that its format does not define",
                locations, null, AuthenticodeFieldKey.SIGNATURE_ENCODING);
    }

    private static void checkRequiredAttributes(Role role, DerElement signedAttributes, String contentType,
                                                DerElement messageDigest, DerElement si, IssueSink sink,
                                                String who) {
        if (signedAttributes == null) {
            sink.add(CertificateIssueType.MISSING_SIGNED_ATTRIBUTE, who + " has no signed attributes",
                    si.location(), AuthenticodeFieldKey.SIGNED_ATTRIBUTES);
            return;
        }
        // countersignatures must not have a contentType (RFC 5652), legacy ones have pkcs7-data
        if (role != Role.COUNTERSIGNER) {
            String expected = role == Role.AUTHENTICODE ? Oids.SPC_INDIRECT_DATA : Oids.TST_INFO;
            if (contentType == null) {
                sink.add(CertificateIssueType.MISSING_SIGNED_ATTRIBUTE, who + " has no contentType attribute",
                        signedAttributes.location(), AuthenticodeFieldKey.SIGNED_ATTRIBUTES);
            } else if (!expected.equals(contentType)) {
                sink.add(CertificateIssueType.WRONG_CONTENT_TYPE, who + ": the contentType attribute is "
                                + Oids.nameOrOid(contentType) + " instead of " + Oids.nameOrOid(expected),
                        signedAttributes.location(), AuthenticodeFieldKey.CONTENT_TYPE);
            }
        }
        if (messageDigest == null) {
            sink.add(CertificateIssueType.MISSING_SIGNED_ATTRIBUTE, who + " has no messageDigest attribute",
                    signedAttributes.location(), AuthenticodeFieldKey.SIGNED_ATTRIBUTES);
        }
    }

    private List<SignatureAttribute> parseAttributes(DerElement set, boolean authenticated, IssueSink sink,
                                                     String who) {
        List<SignatureAttribute> result = new ArrayList<>();
        if (set == null) {
            return result;
        }
        int n = 0;
        for (DerElement attribute : set.children()) {
            if (++n > CertificateTable.MAX_ATTRIBUTES) {
                sink.add(CertificateIssueType.LIMIT_EXCEEDED, who + ": more than " + CertificateTable.MAX_ATTRIBUTES
                        + " attributes, the rest is not parsed", attribute.location(), null);
                break;
            }
            try {
                attribute.expectSequence();
                String oid = sink.oid(attribute.child(0));
                attribute.child(1).expectSet();
                extraElements(attribute, 2, who + (authenticated ? " signed" : " unauthenticated") + " attribute "
                        + Oids.nameOrOid(oid), sink);
                result.add(new SignatureAttribute(oid, authenticated, attribute));
            } catch (DerException e) {
                sink.addDerException(who + " attribute " + n, e);
            }
        }
        return result;
    }

    private static Optional<AuthenticodeCertificate> findCertificate(List<AuthenticodeCertificate> bag,
                                                                     DerElement issuer, byte[] serial,
                                                                     byte[] ski) {
        if (issuer != null && serial != null) {
            return CertificateParser.findByIssuerAndSerial(bag, issuer, serial);
        }
        if (ski != null) {
            return CertificateParser.findBySki(bag, ski);
        }
        return Optional.empty();
    }

    /** SpcString ::= CHOICE { unicode [0] IMPLICIT BMPString, ascii [1] IMPLICIT IA5String } */
    private static String spcString(DerElement e) {
        if (e.isContext(0) && !e.isConstructed()) {
            return e.decode(StandardCharsets.UTF_16BE, 2, CertificateTable.MAX_STRING_LENGTH);
        }
        if (e.isContext(1) && !e.isConstructed()) {
            return e.decode(StandardCharsets.ISO_8859_1, 1, CertificateTable.MAX_STRING_LENGTH);
        }
        return e.asString(CertificateTable.MAX_STRING_LENGTH).orElse(null);
    }

    /** SpcLink ::= CHOICE { url [0] IMPLICIT IA5String, moniker [1], file [2] EXPLICIT SpcString } */
    private static String spcLink(DerElement e) throws DerException {
        if (e.isContext(0) && !e.isConstructed()) {
            return e.decode(StandardCharsets.ISO_8859_1, 1, CertificateTable.MAX_STRING_LENGTH);
        }
        if (e.isContext(2) && e.isConstructed()) {
            return spcString(e.explicitContent());
        }
        return null;
    }

    /* -------------------------------- RFC 3161 -------------------------------- */

    private Timestamp parseRfc3161(DerElement contentInfo, List<AuthenticodeCertificate> outerBag,
                                   IssueSink sink, String label) throws DerException {
        String tsLabel = label + " timestamp";
        Content content = parseContent(contentInfo, sink, tsLabel, Oids.TST_INFO);
        if (content == null) {
            return null;
        }
        List<AuthenticodeCertificate> bag = parseCertificates(content.certificates, sink, tsLabel);
        SignerInfo signer = null;
        if (content.signerInfos.childCount() != 1) {
            sink.add(CertificateIssueType.UNUSUAL_SIGNER_COUNT, tsLabel + " has "
                    + content.signerInfos.childCount() + " signers instead of one",
                    content.signerInfos.location(), AuthenticodeFieldKey.TIMESTAMP);
        }
        if (content.signerInfos.childCount() > 0) {
            try {
                signer = parseSigner(content.signerInfos.child(0), bag, outerBag, Role.TIMESTAMP_TOKEN, sink,
                        tsLabel, 0, 0, 0, new ArrayList<AuthenticodeSignature>());
            } catch (DerException e) {
                sink.addDerException(tsLabel + " signer", e);
            }
        }
        Instant genTime = null;
        AlgorithmId imprintAlgorithm = null;
        DerElement imprint = null;
        String policy = null;
        byte[] serial = null;
        DerElement tstInfoOctets = content.eContent;
        if (tstInfoOctets != null && tstInfoOctets.isPrimitiveOctetString()) {
            try {
                DerElement tst = tstInfoOctets.parseEncapsulated().root().expectSequence();
                policy = sink.oid(tst.child(1));
                DerElement messageImprint = tst.child(2).expectSequence();
                imprintAlgorithm = sink.algorithm(messageImprint.child(0), true);
                imprint = messageImprint.child(1).expect(DerElement.OCTET_STRING);
                serial = tst.child(3).integerBytes(CertificateTable.MAX_INTEGER_LENGTH);
                genTime = tst.child(4).asTime().orElse(null);
            } catch (DerException e) {
                sink.addDerException(tsLabel + " TSTInfo", e);
                tstInfoOctets = null;
            }
        } else {
            sink.add(CertificateIssueType.MALFORMED_PKCS7, tsLabel + " has no TSTInfo", contentInfo.location(),
                    AuthenticodeFieldKey.TIMESTAMP);
            tstInfoOctets = null;
        }
        return new Timestamp(Timestamp.Kind.RFC3161, genTime, signer, bag, imprintAlgorithm, imprint, policy,
                serial, contentInfo, tstInfoOctets);
    }

    /* ------------------------------- page hashes ------------------------------- */

    /**
     * SpcPeImageData ::= SEQUENCE { flags BIT STRING OPTIONAL, file [0] EXPLICIT SpcLink }, where the
     * moniker of the link is an SpcSerializedObject that holds the page hashes.
     */
    private static PageHashes parsePageHashes(DerElement peImageData, IssueSink sink, String label) {
        try {
            peImageData.expectSequence();
            for (DerElement child : peImageData.children()) {
                if (!child.isContext(0) || !child.isConstructed()) {
                    continue;
                }
                DerElement link = child.explicitContent();
                if (!link.isContext(1) || !link.isConstructed()) {
                    return null;
                }
                byte[] classId = link.child(0).asOctets(64);
                if (!Oids.SPC_SERIALIZED_PAGE_HASHES_CLASS_ID.equals(Hex.of(classId))) {
                    return null;
                }
                DerElement set = link.child(1).parseEncapsulated().root().expectSet();
                for (DerElement attribute : set.children()) {
                    String oid = sink.oid(attribute.expectSequence().child(0));
                    int version = Oids.PAGE_HASHES_V1.equals(oid) ? 1 : Oids.PAGE_HASHES_V2.equals(oid) ? 2 : 0;
                    if (version == 0) {
                        continue;
                    }
                    DerElement data = attribute.child(1).expectSet().child(0).expect(DerElement.OCTET_STRING);
                    int digestLength = version == 1 ? 20 : 32;
                    long length = data.contentLength();
                    long entries = length / (4 + digestLength);
                    boolean wellFormed = length > 0 && length % (4 + digestLength) == 0;
                    if (!wellFormed) {
                        sink.add(CertificateIssueType.INVALID_PAGE_HASHES, label + ": page hashes of " + length
                                        + " bytes are no whole number of entries",
                                data.location(), AuthenticodeFieldKey.PAGE_HASHES);
                    }
                    return new PageHashes(version, version == 1 ? "SHA-1" : "SHA-256", entries, wellFormed,
                            data.contentLocation());
                }
            }
        } catch (DerException e) {
            sink.add(CertificateIssueType.INVALID_PAGE_HASHES, label + ": page hashes are malformed: "
                    + e.getMessage(), peImageData.location(), AuthenticodeFieldKey.PAGE_HASHES);
        }
        return null;
    }

    /* --------------------------------- checks --------------------------------- */

    private static void checkDigestConsistency(Content content, AlgorithmId imageAlgorithm,
                                               List<SignerInfo> signers, IssueSink sink, String label) {
        Set<String> listed = new HashSet<>();
        for (AlgorithmId a : content.digestAlgorithms) {
            listed.add(a.getOid());
        }
        for (SignerInfo signer : signers) {
            String digest = signer.getDigestAlgorithm().getOid();
            List<String> problems = new ArrayList<>();
            if (!listed.contains(digest)) {
                problems.add("the signer digest " + signer.getDigestAlgorithm()
                        + " is not listed in the SignedData digest algorithms");
            }
            if (imageAlgorithm != null && !imageAlgorithm.getOid().equals(digest)) {
                problems.add("the image digest uses " + imageAlgorithm + " but the signer uses "
                        + signer.getDigestAlgorithm());
            }
            Optional<String> implied = Algorithms.impliedDigest(signer.getSignatureAlgorithm().getOid());
            if (implied.isPresent() && !implied.get().equals(digest)) {
                problems.add("the signature algorithm " + signer.getSignatureAlgorithm()
                        + " does not match the signer digest " + signer.getDigestAlgorithm());
            }
            if (!problems.isEmpty()) {
                sink.add(CertificateIssueType.DIGEST_ALGORITHM_MISMATCH, label + ": " + String.join("; ", problems),
                        signer.getDigestAlgorithm().getLocation(), AuthenticodeFieldKey.DIGEST_ALGORITHM);
            }
        }
    }

    /**
     * Reports MD2, MD5 and SHA-1 once per signature and unsupported
     * algorithms. Signatures of self-issued certificates are ignored, because
     * the trust in a root does not depend on its self-signature.
     */
    private static void checkAlgorithms(AlgorithmId imageAlgorithm, DerElement imageDigest,
                                        List<SignerInfo> signers, List<AuthenticodeCertificate> bag,
                                        IssueSink sink, String label) {
        AlgorithmUsages usages = new AlgorithmUsages();
        if (imageAlgorithm != null) {
            usages.consider(imageAlgorithm, "image digest");
            if (!imageAlgorithm.getJdkName().isPresent()) {
                sink.add(CertificateIssueType.UNSUPPORTED_ALGORITHM, label + ": the image digest algorithm "
                                + imageAlgorithm.getOid() + " is not supported",
                        imageAlgorithm.getLocation(), AuthenticodeFieldKey.DIGEST_ALGORITHM);
            }
        }
        for (SignerInfo signer : signers) {
            usages.consider(signer.getDigestAlgorithm(), "signer digest");
            usages.consider(signer.getSignatureAlgorithm(), "signer signature");
            if (!signer.getJdkSignatureAlgorithm().isPresent()) {
                sink.add(CertificateIssueType.UNSUPPORTED_ALGORITHM, label + ": the signer signature algorithm "
                                + signer.getSignatureAlgorithm() + " is not supported",
                        signer.getSignatureAlgorithm().getLocation(), AuthenticodeFieldKey.SIGNATURE_ALGORITHM);
            }
            for (Timestamp t : signer.getTimestamps()) {
                if (t.getImprintAlgorithm().isPresent()) {
                    usages.consider(t.getImprintAlgorithm().get(), "timestamp imprint");
                }
                if (t.getSigner().isPresent()) {
                    usages.consider(t.getSigner().get().getSignatureAlgorithm(), "timestamp signature");
                }
                for (AuthenticodeCertificate c : t.getCertificates()) {
                    if (!c.isSelfIssued()) {
                        usages.consider(c.getSignatureAlgorithm(), "signature of certificate " + c.displayName());
                    }
                }
            }
        }
        for (AuthenticodeCertificate c : bag) {
            if (!c.isSelfIssued()) {
                usages.consider(c.getSignatureAlgorithm(), "signature of certificate " + c.displayName());
            }
        }
        if (!usages.weak.isEmpty()) {
            sink.add(CertificateIssueType.WEAK_DIGEST, label + ": MD2 or MD5 is used for "
                    + String.join(", ", usages.weak), usages.weakLocations, null,
                    AuthenticodeFieldKey.DIGEST_ALGORITHM);
        }
        if (!usages.sha1.isEmpty()) {
            sink.add(CertificateIssueType.SHA1_DIGEST, label + ": SHA-1 is used for "
                    + String.join(", ", usages.sha1), usages.sha1Locations, null,
                    AuthenticodeFieldKey.DIGEST_ALGORITHM);
        }
    }

    private static final class AlgorithmUsages {
        private final List<String> weak = new ArrayList<>();
        private final List<String> sha1 = new ArrayList<>();
        private final List<PhysicalLocation> weakLocations = new ArrayList<>();
        private final List<PhysicalLocation> sha1Locations = new ArrayList<>();

        private void consider(AlgorithmId algorithm, String usage) {
            if (algorithm.isWeak()) {
                weak.add(usage + " (" + algorithm + ")");
                weakLocations.add(algorithm.getLocation());
            } else if (algorithm.isSha1()) {
                sha1.add(usage);
                sha1Locations.add(algorithm.getLocation());
            }
        }
    }

    private static void checkIsolatedCertificates(List<AuthenticodeCertificate> bag, List<SignerInfo> signers,
                                                  IssueSink sink, String label) {
        Set<AuthenticodeCertificate> used = Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (SignerInfo signer : signers) {
            signer.getSignerCertificate().ifPresent(used::add);
            for (Timestamp t : signer.getTimestamps()) {
                if (t.getSigner().isPresent()) {
                    t.getSigner().get().getSignerCertificate().ifPresent(used::add);
                }
            }
        }
        for (AuthenticodeCertificate c : bag) {
            if (used.contains(c)) {
                continue;
            }
            boolean connected = false;
            for (AuthenticodeCertificate other : bag) {
                if (other != c && (other.issuerNameElement().equalEncoding(c.subjectNameElement())
                        || c.issuerNameElement().equalEncoding(other.subjectNameElement()))) {
                    connected = true;
                    break;
                }
            }
            if (!connected) {
                sink.add(CertificateIssueType.ISOLATED_CERTIFICATE, label + ": " + c
                                + " is not related to the signers or the other certificates",
                        c.getLocation(), null);
            }
        }
    }

    private static void checkSignerCertificates(List<SignerInfo> signers, IssueSink sink, String label) {
        for (SignerInfo signer : signers) {
            if (!signer.getSignerCertificate().isPresent()) {
                continue;
            }
            AuthenticodeCertificate c = signer.getSignerCertificate().get();
            if (c.isSelfIssued()) {
                sink.add(CertificateIssueType.SELF_SIGNED_SIGNER, label + ": the signer certificate "
                        + c.displayName() + " is self-signed", c.getLocation(), AuthenticodeFieldKey.SIGNER_CERTIFICATE);
            }
            Optional<Instant> time = signer.getEffectiveSigningTime();
            if (time.isPresent() && c.getNotBefore().isPresent() && c.getNotAfter().isPresent()
                    && !c.isValidAt(time.get())) {
                sink.add(CertificateIssueType.SIGNER_NOT_VALID_AT_SIGNING_TIME, label + ": the signer certificate "
                                + c.displayName() + " is valid from " + c.getNotBefore().get() + " to "
                                + c.getNotAfter().get() + ", but the signing time is " + time.get(),
                        c.getLocation(), AuthenticodeFieldKey.SIGNER_CERTIFICATE);
            }
        }
    }
}
