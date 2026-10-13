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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static io.github.struppigel.parser.sections.cert.DerBuilder.*;

/**
 * Creates Authenticode signed copies of unsigned PE files for tests: a leaf
 * certificate issued by a test CA signs the image digest. Options produce
 * malformed and manipulated signatures.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class TestSigner {

    enum KeyType { RSA, EC }

    private static KeyPair rsaCa;
    private static KeyPair rsaLeaf;
    private static KeyPair ecCa;
    private static KeyPair ecLeaf;

    private static final Instant NOT_BEFORE = Instant.parse("2020-01-01T00:00:00Z");
    private static final Instant NOT_AFTER = Instant.parse("2040-01-01T00:00:00Z");
    private static final byte[] CA_NAME = name("PortEx Test CA");
    private static final byte[] LEAF_NAME = name("PortEx Test Signer");
    private static final byte[] CA_SERIAL = BigInteger.valueOf(0x1001).toByteArray();

    String digest = "SHA-256";
    KeyType keyType = KeyType.RSA;
    boolean zeroEcdsa;
    boolean wrongMessageDigest;
    boolean wrongContentType;
    boolean digestMismatch;
    boolean missingMessageDigest;
    boolean twoSigners;
    boolean omitSignerCertificate;
    boolean relaxedMarker;
    boolean nonMinimalLength;
    boolean explicitEcParameters;
    boolean isolatedCertificate;
    boolean longSerial;
    int nestingDepth;
    String unauthenticatedOid;
    int unauthenticatedSize;
    /** adds a countersignature whose SignerInfo has an unauthenticated attribute of this type */
    String countersignerUnauthenticatedOid;
    /** adds the signed attribute intent to seal */
    boolean intentToSeal;
    /** adds an unauthenticated attribute with an element after its values */
    boolean extraAttributeElement;
    /** adds an element after the unauthenticated attributes of the SignerInfo */
    boolean extraSignerInfoElement;
    /** adds an element before the SignerInfos of the SignedData */
    boolean extraSignedDataElement;

    private static synchronized void initKeys() throws GeneralSecurityException {
        if (rsaCa != null) {
            return;
        }
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        rsaCa = rsa.generateKeyPair();
        rsaLeaf = rsa.generateKeyPair();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        ecCa = ec.generateKeyPair();
        ecLeaf = ec.generateKeyPair();
    }

    /**
     * @param source an unsigned PE file
     * @param dir    the directory of the signed copy
     * @return the signed copy
     */
    File sign(File source, Path dir) throws IOException, GeneralSecurityException {
        initKeys();
        byte[] pe = Files.readAllBytes(source.toPath());
        int peOffset = le32(pe, 0x3c);
        int opt = peOffset + 24;
        int magic = (pe[opt] & 0xff) | ((pe[opt + 1] & 0xff) << 8);
        int checksumOffset = opt + 64;
        int certEntryOffset = opt + (magic == 0x10b ? 96 : 112) + 4 * 8;
        byte[] image = Arrays.copyOf(pe, (pe.length + 7) & ~7);
        MessageDigest md = MessageDigest.getInstance(digest);
        md.update(image, 0, checksumOffset);
        md.update(image, checksumOffset + 4, certEntryOffset - checksumOffset - 4);
        md.update(image, certEntryOffset + 8, image.length - certEntryOffset - 8);
        byte[] imageDigest = md.digest();

        byte[] contentInfo = signature(imageDigest, 0);
        if (nonMinimalLength) {
            byte[] content = Arrays.copyOfRange(contentInfo, headerLength(contentInfo), contentInfo.length);
            contentInfo = concat(new byte[]{0x30, (byte) 0x84, (byte) (content.length >>> 24),
                    (byte) (content.length >>> 16), (byte) (content.length >>> 8), (byte) content.length}, content);
        }
        int dwLength = 8 + contentInfo.length;
        int aligned = (dwLength + 7) & ~7;
        byte[] entry = new byte[aligned];
        putLe32(entry, 0, dwLength);
        entry[4] = 0x00;
        entry[5] = 0x02;
        entry[6] = 0x02;
        entry[7] = 0x00;
        System.arraycopy(contentInfo, 0, entry, 8, contentInfo.length);
        putLe32(image, certEntryOffset, image.length);
        putLe32(image, certEntryOffset + 4, aligned);
        File out = Files.createTempFile(dir, "signed-", "-" + source.getName()).toFile();
        Files.write(out.toPath(), concat(image, entry));
        return out;
    }

    /** builds a ContentInfo with an Authenticode SignedData */
    private byte[] signature(byte[] imageDigest, int level) throws GeneralSecurityException {
        String digestOid = digestOid(digest);
        byte[] peImageData = seq(new byte[]{0x03, 0x01, 0x00},
                ctx(0, ctx(2, ctxPrimitive(0, bmp("<<<Obsolete>>>")))));
        byte[] indirect = seq(seq(oid(Oids.SPC_PE_IMAGE_DATA), peImageData),
                seq(algorithm(digestOid), octets(imageDigest)));
        byte[] indirectContent = Arrays.copyOfRange(indirect, headerLength(indirect), indirect.length);
        byte[] messageDigest = MessageDigest.getInstance(digest).digest(indirectContent);
        if (wrongMessageDigest) {
            messageDigest[0] ^= 1;
        }
        List<byte[]> signed = new ArrayList<>();
        signed.add(attribute(Oids.CONTENT_TYPE, oid(wrongContentType ? Oids.DATA : Oids.SPC_INDIRECT_DATA)));
        if (!missingMessageDigest) {
            signed.add(attribute(Oids.MESSAGE_DIGEST, octets(messageDigest)));
        }
        signed.add(attribute(Oids.SPC_SP_OPUS_INFO, seq(ctx(0, ctxPrimitive(0, bmp("PortEx Test"))),
                ctx(1, ctxPrimitive(0, "https://example.org".getBytes(java.nio.charset.StandardCharsets.US_ASCII))))));
        if (relaxedMarker) {
            signed.add(attribute(Oids.SPC_RELAXED_PE_MARKER_CHECK, integer(0)));
        }
        if (intentToSeal) {
            signed.add(attribute(Oids.INTENT_TO_SEAL, integer(1)));
        }
        signed.sort(TestSigner::compareBytes);
        byte[] signedSet = set(signed.toArray(new byte[0][]));
        byte[] signedImplicit = Arrays.copyOf(signedSet, signedSet.length);
        signedImplicit[0] = (byte) 0xa0;

        KeyPair ca = keyType == KeyType.RSA ? rsaCa : ecCa;
        KeyPair leaf = keyType == KeyType.RSA ? rsaLeaf : ecLeaf;
        byte[] signatureValue = sign(signedSet, leaf.getPrivate(), digest);
        if (zeroEcdsa) {
            signatureValue = seq(integer(0), integer(0));
        }
        byte[] signatureAlgorithm = keyType == KeyType.RSA ? algorithm(Oids.RSA_ENCRYPTION)
                : algorithmNoParams(ecdsaOid(digest));

        byte[] leafSerial = longSerial ? concat(new byte[]{0x01}, new byte[20]) : BigInteger.valueOf(0x2002).toByteArray();
        List<byte[]> unauthenticated = new ArrayList<>();
        if (level < nestingDepth) {
            unauthenticated.add(attribute(Oids.NESTED_SIGNATURE, signature(imageDigest, level + 1)));
        }
        if (unauthenticatedOid != null && level == 0) {
            unauthenticated.add(attribute(unauthenticatedOid, octets(new byte[unauthenticatedSize])));
        }
        if (countersignerUnauthenticatedOid != null && level == 0) {
            unauthenticated.add(attribute(Oids.COUNTER_SIGNATURE,
                    countersigner(signatureValue, leafSerial, leaf.getPrivate(), signatureAlgorithm)));
        }
        if (extraAttributeElement && level == 0) {
            unauthenticated.add(seq(oid(Oids.SPC_ENCRYPTED_DIGEST_RETRY_COUNT), set(integer(1)), octets(new byte[16])));
        }
        byte[] signerInfo = seq(integer(1), seq(CA_NAME, integerBytes(leafSerial)), algorithm(digestOid),
                signedImplicit, signatureAlgorithm, octets(signatureValue),
                unauthenticated.isEmpty() ? new byte[0] : tlv(0xa1, unauthenticated.toArray(new byte[0][])),
                extraSignerInfoElement && level == 0 ? octets(new byte[16]) : new byte[0]);

        List<byte[]> certificates = new ArrayList<>();
        if (!omitSignerCertificate) {
            certificates.add(certificate(CA_NAME, LEAF_NAME, leafSerial, spki(leaf.getPublic()), ca.getPrivate()));
        }
        certificates.add(certificate(CA_NAME, CA_NAME, CA_SERIAL, ca.getPublic().getEncoded(), ca.getPrivate()));
        if (isolatedCertificate) {
            byte[] unrelated = name("Unrelated Certificate");
            certificates.add(certificate(unrelated, unrelated, BigInteger.valueOf(0x3003).toByteArray(),
                    ca.getPublic().getEncoded(), ca.getPrivate()));
        }
        byte[] signedData = seq(integer(1), set(algorithm(digestMismatch ? Oids.SHA1 : digestOid)),
                seq(oid(Oids.SPC_INDIRECT_DATA), ctx(0, indirect)),
                ctx(0, certificates.toArray(new byte[0][])),
                extraSignedDataElement && level == 0 ? octets(new byte[16]) : new byte[0],
                twoSigners ? set(signerInfo, signerInfo) : set(signerInfo));
        return seq(oid(Oids.SIGNED_DATA), ctx(0, signedData));
    }

    /** a countersignature of the signature value by the leaf certificate, with an unauthenticated attribute */
    private byte[] countersigner(byte[] signatureValue, byte[] leafSerial, PrivateKey key, byte[] signatureAlgorithm)
            throws GeneralSecurityException {
        List<byte[]> signed = new ArrayList<>();
        signed.add(attribute(Oids.MESSAGE_DIGEST, octets(MessageDigest.getInstance(digest).digest(signatureValue))));
        signed.add(attribute(Oids.SIGNING_TIME, utcTime(NOT_BEFORE.plusSeconds(86400))));
        signed.sort(TestSigner::compareBytes);
        byte[] signedSet = set(signed.toArray(new byte[0][]));
        byte[] signedImplicit = Arrays.copyOf(signedSet, signedSet.length);
        signedImplicit[0] = (byte) 0xa0;
        return seq(integer(1), seq(CA_NAME, integerBytes(leafSerial)), algorithm(digestOid(digest)), signedImplicit,
                signatureAlgorithm, octets(sign(signedSet, key, digest)),
                tlv(0xa1, attribute(countersignerUnauthenticatedOid, octets(new byte[16]))));
    }

    private byte[] spki(PublicKey key) {
        byte[] encoded = key.getEncoded();
        if (!explicitEcParameters || keyType != KeyType.EC) {
            return encoded;
        }
        try {
            DerElement point = DerReader.read(encoded, 0, encoded.length, 0).root().child(1);
            // a SEQUENCE instead of a named curve OID: explicit curve parameters
            return seq(seq(oid(Oids.EC_PUBLIC_KEY), seq(integer(1), seq(oid("1.2.840.10045.1.1"), integer(23)))),
                    bitString(point.asBitString()));
        } catch (DerException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] certificate(byte[] issuer, byte[] subject, byte[] serial, byte[] spki,
                                      PrivateKey issuerKey) throws GeneralSecurityException {
        boolean rsa = issuerKey instanceof RSAPrivateKey;
        byte[] algorithm = rsa ? algorithm(Oids.SHA256_WITH_RSA) : algorithmNoParams(Oids.ECDSA_WITH_SHA256);
        byte[] tbs = seq(ctx(0, integer(2)), integerBytes(serial), algorithm, issuer,
                seq(utcTime(NOT_BEFORE), utcTime(NOT_AFTER)), subject, spki);
        return seq(tbs, algorithm, bitString(sign(tbs, issuerKey, "SHA-256")));
    }

    private static byte[] sign(byte[] data, PrivateKey key, String digest) throws GeneralSecurityException {
        String name = digest.replace("-", "") + "with" + (key instanceof RSAPrivateKey ? "RSA" : "ECDSA");
        Signature s = Signature.getInstance(name);
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    static String digestOid(String digest) {
        switch (digest) {
            case "MD5": return Oids.MD5;
            case "SHA-1": return Oids.SHA1;
            case "SHA-256": return Oids.SHA256;
            case "SHA-384": return Oids.SHA384;
            default: throw new IllegalArgumentException(digest);
        }
    }

    private static String ecdsaOid(String digest) {
        switch (digest) {
            case "SHA-1": return Oids.ECDSA_WITH_SHA1;
            case "SHA-256": return Oids.ECDSA_WITH_SHA256;
            case "SHA-384": return Oids.ECDSA_WITH_SHA384;
            default: throw new IllegalArgumentException(digest);
        }
    }

    private static int headerLength(byte[] der) {
        int first = der[1] & 0xff;
        return first < 0x80 ? 2 : 2 + (first & 0x7f);
    }

    private static int compareBytes(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0) {
                return d;
            }
        }
        return a.length - b.length;
    }

    static int le32(byte[] b, int p) {
        return (b[p] & 0xff) | ((b[p + 1] & 0xff) << 8) | ((b[p + 2] & 0xff) << 16) | ((b[p + 3] & 0xff) << 24);
    }

    static void putLe32(byte[] b, int p, long value) {
        b[p] = (byte) value;
        b[p + 1] = (byte) (value >>> 8);
        b[p + 2] = (byte) (value >>> 16);
        b[p + 3] = (byte) (value >>> 24);
    }
}
