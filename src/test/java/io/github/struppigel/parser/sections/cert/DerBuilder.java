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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Builds DER encoded ASN.1 data for tests.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class DerBuilder {

    private DerBuilder() {
    }

    static byte[] tlv(int tag, byte[]... contents) {
        byte[] content = concat(contents);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, content.length);
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else if (length < 0x10000) {
            out.write(0x82);
            out.write(length >>> 8);
            out.write(length);
        } else {
            out.write(0x83);
            out.write(length >>> 16);
            out.write(length >>> 8);
            out.write(length);
        }
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
        }
        return out.toByteArray();
    }

    static byte[] seq(byte[]... contents) {
        return tlv(0x30, contents);
    }

    static byte[] set(byte[]... contents) {
        return tlv(0x31, contents);
    }

    /** constructed context specific tag [n] */
    static byte[] ctx(int n, byte[]... contents) {
        return tlv(0xa0 | n, contents);
    }

    /** primitive context specific tag [n] */
    static byte[] ctxPrimitive(int n, byte[] content) {
        return tlv(0x80 | n, content);
    }

    static byte[] integer(long value) {
        return integer(BigInteger.valueOf(value));
    }

    static byte[] integer(BigInteger value) {
        return tlv(0x02, value.toByteArray());
    }

    /** INTEGER with the given content octets */
    static byte[] integerBytes(byte[] content) {
        return tlv(0x02, content);
    }

    static byte[] octets(byte[] value) {
        return tlv(0x04, value);
    }

    static byte[] bitString(byte[] value) {
        return tlv(0x03, new byte[]{0}, value);
    }

    static byte[] nul() {
        return new byte[]{0x05, 0x00};
    }

    static byte[] utf8(String s) {
        return tlv(0x0c, s.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] bmp(String s) {
        return s.getBytes(StandardCharsets.UTF_16BE);
    }

    static byte[] utcTime(Instant time) {
        String s = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC).format(time);
        return tlv(0x17, s.getBytes(StandardCharsets.US_ASCII));
    }

    static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeArc(out, Long.parseLong(arcs[0]) * 40 + Long.parseLong(arcs[1]));
        for (int i = 2; i < arcs.length; i++) {
            writeArc(out, Long.parseLong(arcs[i]));
        }
        return tlv(0x06, out.toByteArray());
    }

    private static void writeArc(ByteArrayOutputStream out, long value) {
        int groups = 1;
        for (long v = value >>> 7; v != 0; v >>>= 7) {
            groups++;
        }
        for (int i = groups - 1; i >= 0; i--) {
            int b = (int) ((value >>> (7 * i)) & 0x7f);
            out.write(i > 0 ? b | 0x80 : b);
        }
    }

    /** AlgorithmIdentifier with NULL parameters */
    static byte[] algorithm(String oid) {
        return seq(oid(oid), nul());
    }

    /** AlgorithmIdentifier without parameters */
    static byte[] algorithmNoParams(String oid) {
        return seq(oid(oid));
    }

    /** Name with one common name */
    static byte[] name(String commonName) {
        return seq(set(seq(oid(Oids.COMMON_NAME), utf8(commonName))));
    }

    /** Attribute ::= SEQUENCE { type, SET OF values } */
    static byte[] attribute(String oid, byte[]... values) {
        return seq(oid(oid), set(values));
    }
}
