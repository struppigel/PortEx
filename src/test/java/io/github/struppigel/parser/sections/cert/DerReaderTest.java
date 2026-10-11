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

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

import static io.github.struppigel.parser.sections.cert.DerBuilder.*;
import static org.testng.Assert.*;

/**
 * Tests the bounded ASN.1 reader with crafted data.
 *
 * @author Karsten Philipp Boris Hahn
 */
public class DerReaderTest {

    private static DerElement read(byte[] bytes) throws DerException {
        return DerReader.read(bytes, 0, bytes.length, 0).root();
    }

    private static DerException assertMalformed(byte[] bytes) {
        try {
            read(bytes);
        } catch (DerException e) {
            return e;
        }
        fail("expected DerException");
        return null;
    }

    private static byte[] bytes(int... values) {
        byte[] b = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            b[i] = (byte) values[i];
        }
        return b;
    }

    @Test
    public void shortAndLongLengths() throws DerException {
        DerElement seq = read(bytes(0x30, 0x03, 0x02, 0x01, 0x05));
        assertTrue(seq.isSequence());
        assertEquals(seq.child(0).asInteger(4), BigInteger.valueOf(5));
        byte[] octets = new byte[200];
        DerDocument doc = DerReader.read(octets(octets), 0, octets(octets).length, 0);
        assertEquals(doc.root().contentLength(), 200);
        assertFalse(doc.isBer());
    }

    @Test
    public void nonMinimalLengthIsBer() throws DerException {
        byte[] b = bytes(0x04, 0x81, 0x05, 1, 2, 3, 4, 5);
        DerDocument doc = DerReader.read(b, 0, b.length, 0x100);
        assertTrue(doc.isBer());
        assertEquals(doc.firstBerOffset(), 0x100);
        assertEquals(doc.root().contentLength(), 5);
    }

    @Test
    public void indefiniteLength() throws DerException {
        byte[] b = bytes(0x30, 0x80, 0x02, 0x01, 0x01, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00);
        DerDocument doc = DerReader.read(b, 0, b.length, 0);
        assertTrue(doc.isBer());
        assertEquals(doc.root().childCount(), 2);
        assertEquals(doc.root().endIndex(), b.length);
        assertEquals(doc.trailingBytes(), 0);
    }

    @Test
    public void indefiniteLengthOfPrimitiveIsMalformed() {
        assertMalformed(bytes(0x04, 0x80, 0x01, 0x00, 0x00));
    }

    @Test
    public void missingEndOfContentsIsMalformed() {
        assertMalformed(bytes(0x30, 0x80, 0x02, 0x01, 0x01));
    }

    @Test
    public void lengthBeyondTheDataIsMalformed() {
        assertMalformed(bytes(0x30, 0x05, 0x02, 0x01));
        assertMalformed(bytes(0x30, 0x03, 0x02, 0x05, 0x01));
    }

    @Test
    public void hugeLengthsDoNotOverflow() {
        assertMalformed(bytes(0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01));
        assertMalformed(bytes(0x04, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x00));
        assertMalformed(bytes(0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00));
        assertMalformed(bytes(0x04, 0xff, 0x00));
    }

    @Test
    public void deepNestingHitsTheLimit() {
        byte[] nested = nul();
        for (int i = 0; i < 70; i++) {
            nested = seq(nested);
        }
        assertTrue(assertMalformed(nested).isLimitExceeded());
        // 10000 nested indefinite length elements: no stack overflow
        byte[] indefinite = new byte[20000];
        for (int i = 0; i < indefinite.length; i += 2) {
            indefinite[i] = 0x30;
            indefinite[i + 1] = (byte) 0x80;
        }
        assertTrue(assertMalformed(indefinite).isLimitExceeded());
    }

    @Test
    public void maximumDepthIsAccepted() throws DerException {
        byte[] nested = nul();
        for (int i = 0; i < CertificateTable.MAX_DER_DEPTH; i++) {
            nested = seq(nested);
        }
        read(nested);
    }

    @Test
    public void manyElementsHitTheLimit() {
        byte[] nulls = new byte[(CertificateTable.MAX_DER_ELEMENTS + 1) * 2];
        for (int i = 0; i < nulls.length; i += 2) {
            nulls[i] = 0x05;
        }
        assertTrue(assertMalformed(seq(nulls)).isLimitExceeded());
    }

    @Test
    public void highTagNumbers() throws DerException {
        DerElement e = read(bytes(0xbf, 0x81, 0x00, 0x00));
        assertTrue(e.isContext(128));
        assertTrue(e.isConstructed());
        assertMalformed(bytes(0xbf, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00));
        assertMalformed(bytes(0xbf, 0x80, 0x01, 0x00));
    }

    @Test
    public void endOfContentsOutsideOfIndefiniteLengthIsMalformed() {
        assertMalformed(bytes(0x30, 0x02, 0x00, 0x00));
    }

    @Test
    public void objectIdentifiers() throws DerException {
        assertEquals(read(oid(Oids.SIGNED_DATA)).asOid(), Oids.SIGNED_DATA);
        assertEquals(read(oid("2.999.3")).asOid(), "2.999.3");
        byte[] longOid = new byte[CertificateTable.MAX_OID_LENGTH + 1];
        Arrays.fill(longOid, (byte) 0x01);
        assertEquals(read(tlv(0x06, longOid)).asOid(), DerElement.OVERSIZED_OID);
        // an arc larger than 2^63
        assertEquals(read(bytes(0x06, 0x0b, 0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f))
                .asOid(), DerElement.OVERSIZED_OID);
        try {
            read(bytes(0x06, 0x02, 0x80, 0x01)).asOid();
            fail("non-minimal arc must be rejected");
        } catch (DerException expected) {
            // expected
        }
        try {
            read(bytes(0x06, 0x02, 0x2a, 0x86)).asOid();
            fail("truncated arc must be rejected");
        } catch (DerException expected) {
            // expected
        }
    }

    @Test
    public void integers() throws DerException {
        assertEquals(read(bytes(0x02, 0x01, 0xff)).asInteger(4), BigInteger.valueOf(-1));
        assertEquals(read(bytes(0x02, 0x02, 0x00, 0x80)).asInteger(4), BigInteger.valueOf(128));
        try {
            read(bytes(0x02, 0x03, 1, 2, 3)).asInteger(2);
            fail("too long INTEGER must be rejected");
        } catch (DerException e) {
            assertTrue(e.isLimitExceeded());
        }
    }

    @Test
    public void bitStrings() throws DerException {
        DerElement bits = read(bytes(0x03, 0x02, 0x07, 0x80));
        assertEquals(bits.unusedBits(), 7);
        assertEquals(bits.asBitString(), new byte[]{(byte) 0x80});
        try {
            read(bytes(0x03, 0x01, 0x01)).unusedBits();
            fail("unused bits without data must be rejected");
        } catch (DerException expected) {
            // expected
        }
        try {
            read(bytes(0x03, 0x02, 0x08, 0x00)).unusedBits();
            fail("more than 7 unused bits must be rejected");
        } catch (DerException expected) {
            // expected
        }
    }

    @Test
    public void times() throws DerException {
        assertEquals(read(tlv(0x17, "200417183746Z".getBytes())).asTime().get(),
                Instant.parse("2020-04-17T18:37:46Z"));
        assertEquals(read(tlv(0x17, "490101000000Z".getBytes())).asTime().get(),
                Instant.parse("2049-01-01T00:00:00Z"));
        assertEquals(read(tlv(0x17, "500101000000Z".getBytes())).asTime().get(),
                Instant.parse("1950-01-01T00:00:00Z"));
        assertEquals(read(tlv(0x18, "20200417183746.462Z".getBytes())).asTime().get(),
                Instant.parse("2020-04-17T18:37:46.462Z"));
        assertEquals(read(tlv(0x18, "20200417183746+0200".getBytes())).asTime().get(),
                Instant.parse("2020-04-17T16:37:46Z"));
        assertFalse(read(tlv(0x17, "201317183746Z".getBytes())).asTime().isPresent());
        assertFalse(read(tlv(0x17, "2004171837xxZ".getBytes())).asTime().isPresent());
        assertFalse(read(tlv(0x17, "2004".getBytes())).asTime().isPresent());
        assertFalse(read(integer(5)).asTime().isPresent());
    }

    @Test
    public void constructedOctetStringsAreJoined() throws DerException {
        DerElement e = read(bytes(0x24, 0x80, 0x04, 0x02, 0xaa, 0xbb, 0x04, 0x01, 0xcc, 0x00, 0x00));
        assertEquals(e.asOctets(16), new byte[]{(byte) 0xaa, (byte) 0xbb, (byte) 0xcc});
        try {
            e.asOctets(2);
            fail("too long OCTET STRING must be rejected");
        } catch (DerException ex) {
            assertTrue(ex.isLimitExceeded());
        }
    }

    @Test
    public void strings() throws DerException {
        assertEquals(read(utf8("Grüße")).asString(100).get(), "Grüße");
        assertEquals(read(tlv(0x1e, bmp("BMP"))).asString(100).get(), "BMP");
        assertEquals(read(tlv(0x1c, bytes(0, 0, 0, 0x41, 0x7f, 0xff, 0xff, 0xff))).asString(100).get(), "A�");
        assertEquals(read(utf8("abcdef")).asString(3).get(), "abc");
        assertFalse(read(integer(1)).asString(10).isPresent());
    }

    @Test
    public void prefixesOfARealSignatureNeverThrowUnchecked() throws IOException {
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/testfiles/strings.exe"));
        byte[] content = CertificateTable.load(data).getEntries().get(0).getContent();
        for (int length = 0; length < content.length; length += 13) {
            try {
                DerReader.read(content, 0, length, 0);
            } catch (DerException expected) {
                // expected for every prefix that cuts the structure
            }
        }
    }
}
