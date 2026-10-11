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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * One ASN.1 element (tag, length, value) inside a buffer that was validated by
 * {@link DerReader}.
 * <p>
 * All accessors are bounded. The element is only modified by the reader while
 * the tree is built.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class DerElement {

    static final int UNIVERSAL = 0;
    static final int APPLICATION = 1;
    static final int CONTEXT = 2;
    static final int PRIVATE = 3;

    static final int BOOLEAN = 1;
    static final int INTEGER = 2;
    static final int BIT_STRING = 3;
    static final int OCTET_STRING = 4;
    static final int NULL = 5;
    static final int OID = 6;
    static final int UTF8_STRING = 12;
    static final int SEQUENCE = 16;
    static final int SET = 17;
    static final int NUMERIC_STRING = 18;
    static final int PRINTABLE_STRING = 19;
    static final int T61_STRING = 20;
    static final int IA5_STRING = 22;
    static final int UTC_TIME = 23;
    static final int GENERALIZED_TIME = 24;
    static final int VISIBLE_STRING = 26;
    static final int UNIVERSAL_STRING = 28;
    static final int BMP_STRING = 30;

    /** returned by {@link #asOid()} for OIDs that exceed the limits */
    static final String OVERSIZED_OID = "<oversized OID>";

    private static final int MAX_TIME_LENGTH = 32;

    private final byte[] buf;
    private final long baseOffset;
    private final int start;
    private final int tagClass;
    private final boolean constructed;
    private final long tagNumber;
    private final int contentStart;
    private final boolean indefinite;
    private final boolean nonMinimal;
    private final int depth;
    private int contentEnd;
    private int end;
    private List<DerElement> children;

    DerElement(byte[] buf, long baseOffset, int start, int tagClass, boolean constructed,
               long tagNumber, int contentStart, long length, boolean nonMinimal, int depth) {
        this.buf = buf;
        this.baseOffset = baseOffset;
        this.start = start;
        this.tagClass = tagClass;
        this.constructed = constructed;
        this.tagNumber = tagNumber;
        this.contentStart = contentStart;
        this.indefinite = length < 0;
        this.nonMinimal = nonMinimal;
        this.depth = depth;
        if (!indefinite) {
            this.contentEnd = (int) (contentStart + length);
            this.end = contentEnd;
        }
    }

    /* ----------------------------- construction ----------------------------- */

    void finishIndefinite(int eocStart) {
        this.contentEnd = eocStart;
        this.end = eocStart + 2;
    }

    void addChild(DerElement child) {
        if (children == null) {
            children = new ArrayList<>();
        }
        children.add(child);
    }

    /* -------------------------------- tags -------------------------------- */

    int tagClass() {
        return tagClass;
    }

    long tagNumber() {
        return tagNumber;
    }

    boolean isConstructed() {
        return constructed;
    }

    boolean isIndefinite() {
        return indefinite;
    }

    boolean isNonMinimal() {
        return nonMinimal;
    }

    int depth() {
        return depth;
    }

    boolean isUniversal(int number) {
        return tagClass == UNIVERSAL && tagNumber == number;
    }

    boolean isContext(int number) {
        return tagClass == CONTEXT && tagNumber == number;
    }

    boolean isSequence() {
        return isUniversal(SEQUENCE) && constructed;
    }

    boolean isSet() {
        return isUniversal(SET) && constructed;
    }

    /**
     * @return a short tag description for messages, e.g. "SEQUENCE" or "[0]"
     */
    String tagName() {
        if (tagClass == CONTEXT) {
            return "[" + tagNumber + "]";
        }
        if (tagClass != UNIVERSAL) {
            return (tagClass == APPLICATION ? "APPLICATION " : "PRIVATE ") + tagNumber;
        }
        switch ((int) tagNumber) {
            case BOOLEAN: return "BOOLEAN";
            case INTEGER: return "INTEGER";
            case BIT_STRING: return "BIT STRING";
            case OCTET_STRING: return "OCTET STRING";
            case NULL: return "NULL";
            case OID: return "OBJECT IDENTIFIER";
            case SEQUENCE: return "SEQUENCE";
            case SET: return "SET";
            case UTC_TIME: return "UTCTime";
            case GENERALIZED_TIME: return "GeneralizedTime";
            default: return "UNIVERSAL " + tagNumber;
        }
    }

    /* ------------------------------ navigation ------------------------------ */

    List<DerElement> children() {
        return children == null ? Collections.<DerElement>emptyList()
                : Collections.unmodifiableList(children);
    }

    int childCount() {
        return children == null ? 0 : children.size();
    }

    /**
     * @param index the index of the child
     * @return the child
     * @throws DerException if there is no such child
     */
    DerElement child(int index) throws DerException {
        if (children == null || index < 0 || index >= children.size()) {
            throw new DerException(tagName() + " has no element at index " + index, fileOffset());
        }
        return children.get(index);
    }

    Optional<DerElement> optChild(int index) {
        if (children == null || index < 0 || index >= children.size()) {
            return Optional.empty();
        }
        return Optional.of(children.get(index));
    }

    /**
     * @param universalTag the expected universal tag number
     * @return this element
     * @throws DerException if this element has another tag
     */
    DerElement expect(int universalTag) throws DerException {
        if (!isUniversal(universalTag)) {
            throw new DerException("expected universal tag " + universalTag + " but found "
                    + tagName(), fileOffset());
        }
        return this;
    }

    /**
     * @return this element, which is a constructed SEQUENCE
     * @throws DerException if this element is not a constructed SEQUENCE
     */
    DerElement expectSequence() throws DerException {
        if (!isSequence()) {
            throw new DerException("expected SEQUENCE but found " + tagName(), fileOffset());
        }
        return this;
    }

    /**
     * @return this element, which is a constructed SET
     * @throws DerException if this element is not a constructed SET
     */
    DerElement expectSet() throws DerException {
        if (!isSet()) {
            throw new DerException("expected SET but found " + tagName(), fileOffset());
        }
        return this;
    }

    /**
     * @return the single child of an explicitly tagged element
     * @throws DerException if this element is primitive or has no child
     */
    DerElement explicitContent() throws DerException {
        if (!constructed || childCount() == 0) {
            throw new DerException("explicitly tagged element " + tagName() + " is empty", fileOffset());
        }
        return child(0);
    }

    /* -------------------------------- bytes -------------------------------- */

    /** @return the buffer index of the identifier byte */
    int startIndex() {
        return start;
    }

    /** @return the buffer index of the first content byte */
    int contentIndex() {
        return contentStart;
    }

    /** @return the buffer index after the last content byte */
    int contentEndIndex() {
        return contentEnd;
    }

    /** @return the buffer index after the element, including end-of-contents */
    int endIndex() {
        return end;
    }

    long fileOffset() {
        return baseOffset + start;
    }

    long contentFileOffset() {
        return baseOffset + contentStart;
    }

    int encodedLength() {
        return end - start;
    }

    int contentLength() {
        return contentEnd - contentStart;
    }

    int headerLength() {
        return contentStart - start;
    }

    /**
     * @return a copy of the full encoding (tag, length, value)
     */
    byte[] encoded() {
        return Arrays.copyOfRange(buf, start, end);
    }

    /**
     * @return a copy of the content octets
     */
    byte[] content() {
        return Arrays.copyOfRange(buf, contentStart, contentEnd);
    }

    /**
     * @return the first byte of the encoding
     */
    int identifierByte() {
        return buf[start] & 0xff;
    }

    byte contentByte(int index) {
        return buf[contentStart + index];
    }

    PhysicalLocation location() {
        return new PhysicalLocation(fileOffset(), encodedLength());
    }

    PhysicalLocation contentLocation() {
        return new PhysicalLocation(contentFileOffset(), contentLength());
    }

    void updateEncoded(MessageDigest md) {
        md.update(buf, start, end - start);
    }

    void updateContent(MessageDigest md) {
        md.update(buf, contentStart, contentEnd - contentStart);
    }

    /**
     * Returns the encoding with another identifier byte, e.g. the [0] IMPLICIT
     * signed attributes re-tagged as SET (0x31) for signature verification.
     *
     * @param identifier the new first byte
     * @return a copy of the encoding with the replaced identifier byte
     */
    byte[] encodedWithIdentifier(int identifier) {
        byte[] copy = encoded();
        copy[0] = (byte) identifier;
        return copy;
    }

    boolean equalEncoding(DerElement other) {
        int len = encodedLength();
        if (len != other.encodedLength()) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            if (buf[start + i] != other.buf[other.start + i]) {
                return false;
            }
        }
        return true;
    }

    /* -------------------------------- values -------------------------------- */

    /**
     * Decodes the OBJECT IDENTIFIER in dotted notation.
     *
     * @return the OID, or {@link #OVERSIZED_OID} if the content exceeds
     *         {@link CertificateTable#MAX_OID_LENGTH} bytes or an arc exceeds
     *         the long range
     * @throws DerException if this is not a valid OID
     */
    String asOid() throws DerException {
        expect(OID);
        if (constructed) {
            throw new DerException("constructed OBJECT IDENTIFIER", fileOffset());
        }
        int len = contentLength();
        if (len == 0) {
            throw new DerException("empty OBJECT IDENTIFIER", fileOffset());
        }
        if (len > CertificateTable.MAX_OID_LENGTH) {
            return OVERSIZED_OID;
        }
        StringBuilder sb = new StringBuilder();
        long value = 0;
        boolean first = true;
        boolean arcStart = true;
        for (int i = contentStart; i < contentEnd; i++) {
            int b = buf[i] & 0xff;
            if (arcStart && b == 0x80) {
                throw new DerException("non-minimal OBJECT IDENTIFIER arc", fileOffset());
            }
            if (value > (Long.MAX_VALUE >>> 7)) {
                return OVERSIZED_OID;
            }
            value = (value << 7) | (b & 0x7f);
            arcStart = (b & 0x80) == 0;
            if (arcStart) {
                if (first) {
                    if (value < 40) {
                        sb.append("0.").append(value);
                    } else if (value < 80) {
                        sb.append("1.").append(value - 40);
                    } else {
                        sb.append("2.").append(value - 80);
                    }
                    first = false;
                } else {
                    sb.append('.').append(value);
                }
                value = 0;
            }
        }
        if (!arcStart) {
            throw new DerException("truncated OBJECT IDENTIFIER", fileOffset());
        }
        return sb.toString();
    }

    /**
     * @param maxLength the maximum number of content bytes
     * @return the INTEGER value
     * @throws DerException if this is no INTEGER or it is too long
     */
    BigInteger asInteger(int maxLength) throws DerException {
        return new BigInteger(integerBytes(maxLength));
    }

    /**
     * @param maxLength the maximum number of content bytes
     * @return the content octets of the INTEGER
     * @throws DerException if this is no INTEGER or it is too long
     */
    byte[] integerBytes(int maxLength) throws DerException {
        expect(INTEGER);
        int len = contentLength();
        if (constructed || len == 0) {
            throw new DerException("invalid INTEGER", fileOffset());
        }
        if (len > maxLength) {
            throw new DerException("INTEGER of " + len + " bytes exceeds the maximum of "
                    + maxLength, fileOffset(), true);
        }
        return content();
    }

    /**
     * @return the value of a small INTEGER
     * @throws DerException if this is no INTEGER or it does not fit into an int
     */
    int asSmallInteger() throws DerException {
        BigInteger value = asInteger(CertificateTable.MAX_INTEGER_LENGTH);
        if (value.bitLength() > 31) {
            throw new DerException("INTEGER too large", fileOffset());
        }
        return value.intValue();
    }

    /**
     * @return the number of unused bits of the BIT STRING
     * @throws DerException if this is no valid BIT STRING
     */
    int unusedBits() throws DerException {
        expect(BIT_STRING);
        if (constructed || contentLength() == 0) {
            throw new DerException("invalid BIT STRING", fileOffset());
        }
        int unused = buf[contentStart] & 0xff;
        if (unused > 7 || (contentLength() == 1 && unused != 0)) {
            throw new DerException("invalid number of unused bits in BIT STRING", fileOffset());
        }
        return unused;
    }

    /**
     * @return the bytes of the BIT STRING without the unused-bits byte
     * @throws DerException if this is no valid BIT STRING
     */
    byte[] asBitString() throws DerException {
        unusedBits();
        return Arrays.copyOfRange(buf, contentStart + 1, contentEnd);
    }

    /**
     * Returns the octets of an OCTET STRING. Constructed (BER) octet strings
     * are joined.
     *
     * @param maxLength the maximum number of octets
     * @return the octets
     * @throws DerException if this is no OCTET STRING or exceeds the maximum
     */
    byte[] asOctets(int maxLength) throws DerException {
        expect(OCTET_STRING);
        if (!constructed) {
            if (contentLength() > maxLength) {
                throw new DerException("OCTET STRING exceeds " + maxLength + " bytes", fileOffset(), true);
            }
            return content();
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        appendOctets(out, maxLength);
        return out.toByteArray();
    }

    private void appendOctets(ByteArrayOutputStream out, int maxLength) throws DerException {
        // the depth is bounded by the reader's maximum depth
        for (DerElement segment : children()) {
            segment.expect(OCTET_STRING);
            if (segment.constructed) {
                segment.appendOctets(out, maxLength);
            } else {
                if ((long) out.size() + segment.contentLength() > maxLength) {
                    throw new DerException("OCTET STRING exceeds " + maxLength + " bytes",
                            fileOffset(), true);
                }
                out.write(segment.buf, segment.contentStart, segment.contentLength());
            }
        }
    }

    /**
     * Parses the DER structure that is encapsulated in a BIT STRING or OCTET
     * STRING, e.g. an RSA key, an ECDSA signature value or a TSTInfo.
     *
     * @return the validated inner document
     * @throws DerException if this is no string or the content is malformed
     */
    DerDocument parseEncapsulated() throws DerException {
        if (isUniversal(BIT_STRING) && !constructed) {
            if (unusedBits() != 0) {
                throw new DerException("BIT STRING with unused bits does not contain DER", fileOffset());
            }
            return DerReader.read(buf, contentStart + 1, contentEnd, baseOffset);
        }
        if (isPrimitiveOctetString()) {
            return DerReader.read(buf, contentStart, contentEnd, baseOffset);
        }
        if (isUniversal(OCTET_STRING)) {
            byte[] octets = asOctets(CertificateTable.MAX_TABLE_READ_SIZE);
            // the joined octets have no file offsets, the content offset approximates them
            return DerReader.read(octets, 0, octets.length, contentFileOffset());
        }
        throw new DerException(tagName() + " does not encapsulate DER", fileOffset());
    }

    /**
     * @return true iff this is a primitive OCTET STRING
     */
    boolean isPrimitiveOctetString() {
        return isUniversal(OCTET_STRING) && !constructed;
    }

    /**
     * Decodes UTCTime or GeneralizedTime.
     *
     * @return the time, empty if this is no valid time
     */
    Optional<Instant> asTime() {
        if (constructed || contentLength() > MAX_TIME_LENGTH || contentLength() < 10) {
            return Optional.empty();
        }
        String s = new String(buf, contentStart, contentLength(), StandardCharsets.US_ASCII);
        try {
            if (isUniversal(UTC_TIME)) {
                int yy = digits(s, 0, 2);
                int year = yy >= 50 ? 1900 + yy : 2000 + yy;
                return parseTime(year, s, 2);
            }
            if (isUniversal(GENERALIZED_TIME)) {
                return parseTime(digits(s, 0, 4), s, 4);
            }
        } catch (NumberFormatException | DateTimeException | IndexOutOfBoundsException e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /**
     * Parses MMDDHHMM[SS][.fff](Z|+hhmm|-hhmm) after the year.
     */
    private static Optional<Instant> parseTime(int year, String s, int pos) {
        int month = digits(s, pos, 2);
        int day = digits(s, pos + 2, 2);
        int hour = digits(s, pos + 4, 2);
        int minute = digits(s, pos + 6, 2);
        int p = pos + 8;
        int second = 0;
        if (p + 1 < s.length() && Character.isDigit(s.charAt(p))) {
            second = digits(s, p, 2);
            p += 2;
        }
        int nanos = 0;
        if (p < s.length() && (s.charAt(p) == '.' || s.charAt(p) == ',')) {
            p++;
            int fractionStart = p;
            while (p < s.length() && Character.isDigit(s.charAt(p))) {
                p++;
            }
            String fraction = s.substring(fractionStart, Math.min(p, fractionStart + 9));
            if (fraction.isEmpty()) {
                throw new NumberFormatException("empty fraction");
            }
            nanos = Integer.parseInt(fraction);
            for (int i = fraction.length(); i < 9; i++) {
                nanos *= 10;
            }
        }
        int offsetSeconds = 0;
        if (p < s.length()) {
            char c = s.charAt(p);
            if (c == 'Z') {
                p++;
            } else if (c == '+' || c == '-') {
                int offHours = digits(s, p + 1, 2);
                int offMinutes = digits(s, p + 3, 2);
                offsetSeconds = (offHours * 3600 + offMinutes * 60) * (c == '-' ? -1 : 1);
                p += 5;
            } else {
                throw new NumberFormatException("invalid time zone");
            }
        }
        if (p != s.length()) {
            throw new NumberFormatException("trailing characters");
        }
        LocalDateTime time = LocalDateTime.of(year, month, day, hour, minute, second, nanos);
        return Optional.of(time.toInstant(ZoneOffset.ofTotalSeconds(offsetSeconds)));
    }

    private static int digits(String s, int pos, int count) {
        int value = 0;
        for (int i = pos; i < pos + count; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                throw new NumberFormatException("not a digit");
            }
            value = value * 10 + (c - '0');
        }
        return value;
    }

    /**
     * @return true iff this is a primitive universal string type
     */
    boolean isString() {
        if (tagClass != UNIVERSAL || constructed) {
            return false;
        }
        switch ((int) tagNumber) {
            case UTF8_STRING:
            case NUMERIC_STRING:
            case PRINTABLE_STRING:
            case T61_STRING:
            case IA5_STRING:
            case VISIBLE_STRING:
            case UNIVERSAL_STRING:
            case BMP_STRING:
                return true;
            default:
                return false;
        }
    }

    /**
     * Decodes a universal string type.
     *
     * @param maxChars the maximum number of characters to return
     * @return the string, empty if this is no string type
     */
    Optional<String> asString(int maxChars) {
        if (!isString()) {
            return Optional.empty();
        }
        switch ((int) tagNumber) {
            case UTF8_STRING:
                return Optional.of(decode(StandardCharsets.UTF_8, 4, maxChars));
            case T61_STRING:
                return Optional.of(decode(StandardCharsets.ISO_8859_1, 1, maxChars));
            case BMP_STRING:
                return Optional.of(decode(StandardCharsets.UTF_16BE, 2, maxChars));
            case UNIVERSAL_STRING:
                return Optional.of(decodeUtf32(maxChars));
            default:
                return Optional.of(decode(StandardCharsets.ISO_8859_1, 1, maxChars));
        }
    }

    /**
     * Decodes the content octets with the given charset, regardless of the
     * tag. Used for implicitly tagged strings like SpcString.
     *
     * @param charset      the charset
     * @param bytesPerChar the maximum bytes per character, bounds the input
     * @param maxChars     the maximum number of characters to return
     * @return the decoded string
     */
    String decode(Charset charset, int bytesPerChar, int maxChars) {
        int len = (int) Math.min(contentLength(), (long) maxChars * bytesPerChar);
        String s = new String(buf, contentStart, len, charset);
        return s.length() > maxChars ? s.substring(0, maxChars) : s;
    }

    private String decodeUtf32(int maxChars) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(contentLength(), maxChars * 4);
        for (int i = contentStart; i + 3 < contentStart + len; i += 4) {
            int cp = ((buf[i] & 0xff) << 24) | ((buf[i + 1] & 0xff) << 16)
                    | ((buf[i + 2] & 0xff) << 8) | (buf[i + 3] & 0xff);
            if (Character.isValidCodePoint(cp)) {
                sb.appendCodePoint(cp);
            } else {
                sb.append('�');
            }
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return tagName() + " at 0x" + Long.toHexString(fileOffset()) + " (" + encodedLength() + " bytes)";
    }
}
