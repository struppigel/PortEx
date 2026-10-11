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

import io.github.struppigel.parser.PhysicalLocation;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * A timestamp of a signer: a legacy PKCS#9 countersignature or an RFC 3161
 * timestamp token.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class Timestamp {

    /**
     * The kind of a timestamp.
     */
    public enum Kind {
        /** a PKCS#9 countersignature (1.2.840.113549.1.9.6) */
        COUNTERSIGNATURE,
        /** an RFC 3161 timestamp token */
        RFC3161
    }

    private final Kind kind;
    private final Instant time;
    private final SignerInfo signer;
    private final List<AuthenticodeCertificate> certificates;
    private final AlgorithmId imprintAlgorithm;
    private final DerElement imprint;
    private final String policy;
    private final byte[] serialBytes;
    private final DerElement element;
    private final DerElement tstInfo;

    Timestamp(Kind kind, Instant time, SignerInfo signer, List<AuthenticodeCertificate> certificates,
              AlgorithmId imprintAlgorithm, DerElement imprint, String policy, byte[] serialBytes,
              DerElement element, DerElement tstInfo) {
        this.kind = kind;
        this.time = time;
        this.signer = signer;
        this.certificates = Collections.unmodifiableList(new ArrayList<>(certificates));
        this.imprintAlgorithm = imprintAlgorithm;
        this.imprint = imprint;
        this.policy = policy;
        this.serialBytes = serialBytes;
        this.element = element;
        this.tstInfo = tstInfo;
    }

    /**
     * @return the kind of the timestamp
     */
    public Kind getKind() {
        return kind;
    }

    /**
     * @return the time of the timestamp: genTime for RFC 3161 tokens, the
     *         signingTime attribute for countersignatures
     */
    public Optional<Instant> getTime() {
        return Optional.ofNullable(time);
    }

    /**
     * @return the signer of the timestamp, empty if the token has no
     *         parseable signer
     */
    public Optional<SignerInfo> getSigner() {
        return Optional.ofNullable(signer);
    }

    /**
     * @return the certificates of the RFC 3161 token, empty for
     *         countersignatures, which use the certificates of the signature
     */
    public List<AuthenticodeCertificate> getCertificates() {
        return certificates;
    }

    /**
     * @return the algorithm of the timestamped digest: the message imprint
     *         algorithm of RFC 3161 tokens, the digest algorithm of
     *         countersignatures
     */
    public Optional<AlgorithmId> getImprintAlgorithm() {
        return Optional.ofNullable(imprintAlgorithm);
    }

    /**
     * @return a copy of the timestamped digest of the signature value
     */
    public Optional<byte[]> getImprint() {
        return imprint == null ? Optional.<byte[]>empty() : Optional.of(imprint.content());
    }

    /**
     * @return the policy OID of an RFC 3161 token
     */
    public Optional<String> getPolicy() {
        return Optional.ofNullable(policy);
    }

    /**
     * @return the serial number of an RFC 3161 token
     */
    public Optional<BigInteger> getSerialNumber() {
        return serialBytes == null ? Optional.<BigInteger>empty() : Optional.of(new BigInteger(serialBytes));
    }

    /**
     * @return the location of the countersignature or token
     */
    public PhysicalLocation getLocation() {
        return element.location();
    }

    DerElement imprintElement() {
        return imprint;
    }

    DerElement element() {
        return element;
    }

    /**
     * @return the eContent OCTET STRING that holds the TSTInfo, null for
     *         countersignatures
     */
    DerElement tstInfoElement() {
        return tstInfo;
    }

    @Override
    public String toString() {
        String who = signer != null && signer.getSignerCertificate().isPresent()
                ? signer.getSignerCertificate().get().displayName() : "unknown signer";
        return (kind == Kind.RFC3161 ? "RFC 3161 timestamp" : "countersignature")
                + (time != null ? " " + time : "") + " by " + who;
    }
}
