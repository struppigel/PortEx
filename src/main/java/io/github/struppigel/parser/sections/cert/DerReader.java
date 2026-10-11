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

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Validates and parses ASN.1 data in DER or BER encoding.
 * <p>
 * The reader walks the element tree iteratively with an explicit stack, so
 * deeply nested data can not overflow the call stack. Every length is checked
 * as a long against the bytes that are actually available before it is used,
 * so huge or negative lengths can not cause overflows or large allocations.
 * The depth and the number of elements are bounded.
 * <p>
 * BER features (indefinite lengths, non-minimal lengths and tag numbers) are
 * accepted and recorded. Constructed strings are kept as constructed elements.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class DerReader {

    private static final int INTERRUPT_CHECK_MASK = 0xfff;
    private static final int MAX_TAG_BYTES = 4;
    private static final int MAX_LENGTH_BYTES = 4;

    private DerReader() {
    }

    /**
     * Reads one element and its subtree with the default limits.
     *
     * @param buf        the buffer
     * @param from       the index of the first byte of the element
     * @param to         the index after the last byte that may be used
     * @param baseOffset the file offset of buf[0]
     * @return the validated document
     * @throws DerException if the data is malformed or exceeds a limit
     */
    static DerDocument read(byte[] buf, int from, int to, long baseOffset) throws DerException {
        return read(buf, from, to, baseOffset, CertificateTable.MAX_DER_DEPTH,
                CertificateTable.MAX_DER_ELEMENTS);
    }

    /**
     * Reads one element and its subtree.
     *
     * @param buf         the buffer
     * @param from        the index of the first byte of the element
     * @param to          the index after the last byte that may be used
     * @param baseOffset  the file offset of buf[0]
     * @param maxDepth    the maximum nesting depth, the root has depth 0
     * @param maxElements the maximum number of elements
     * @return the validated document
     * @throws DerException if the data is malformed or exceeds a limit
     */
    static DerDocument read(byte[] buf, int from, int to, long baseOffset, int maxDepth,
                            int maxElements) throws DerException {
        if (from < 0 || to > buf.length || from > to) {
            throw new DerException("invalid range", baseOffset + Math.max(from, 0));
        }
        long firstBer = -1;
        DerElement root = readElement(buf, from, to, baseOffset, 0);
        if (root.isNonMinimal() || root.isIndefinite()) {
            firstBer = root.fileOffset();
        }
        int count = 1;
        Deque<Frame> stack = new ArrayDeque<>();
        if (root.isConstructed()) {
            stack.push(new Frame(root, root.isIndefinite() ? to : -1));
        }
        while (!stack.isEmpty()) {
            Frame frame = stack.peek();
            DerElement element = frame.element;
            int limit = element.isIndefinite() ? frame.limit : element.contentEndIndex();
            if (element.isIndefinite()) {
                if (frame.pos + 2 <= limit && buf[frame.pos] == 0 && buf[frame.pos + 1] == 0) {
                    element.finishIndefinite(frame.pos);
                    pop(stack, element);
                    continue;
                }
                if (frame.pos >= limit) {
                    throw new DerException("missing end-of-contents for " + element.tagName(),
                            element.fileOffset());
                }
            } else if (frame.pos >= limit) {
                pop(stack, element);
                continue;
            }
            int depth = element.depth() + 1;
            if (depth > maxDepth) {
                throw new DerException("ASN.1 nesting is deeper than " + maxDepth,
                        baseOffset + frame.pos, true);
            }
            if (++count > maxElements) {
                throw new DerException("more than " + maxElements + " ASN.1 elements",
                        baseOffset + frame.pos, true);
            }
            if ((count & INTERRUPT_CHECK_MASK) == 0) {
                Interruption.checkInterrupt();
            }
            DerElement child = readElement(buf, frame.pos, limit, baseOffset, depth);
            element.addChild(child);
            if (firstBer < 0 && (child.isNonMinimal() || child.isIndefinite())) {
                firstBer = child.fileOffset();
            }
            if (child.isConstructed()) {
                stack.push(new Frame(child, child.isIndefinite() ? limit : -1));
            } else {
                frame.pos = child.endIndex();
            }
        }
        return new DerDocument(root, firstBer, to - root.endIndex(), count);
    }

    /**
     * Removes the finished element and moves its parent behind it.
     */
    private static void pop(Deque<Frame> stack, DerElement finished) {
        stack.pop();
        Frame parent = stack.peek();
        if (parent != null) {
            parent.pos = finished.endIndex();
        }
    }

    /**
     * Reads the identifier and length octets at pos.
     */
    private static DerElement readElement(byte[] buf, int pos, int limit, long base, int depth)
            throws DerException {
        if (pos >= limit) {
            throw new DerException("unexpected end of ASN.1 data", base + pos);
        }
        int p = pos;
        int identifier = buf[p++] & 0xff;
        int tagClass = identifier >>> 6;
        boolean constructed = (identifier & 0x20) != 0;
        long tagNumber = identifier & 0x1f;
        boolean nonMinimal = false;
        if (tagNumber == 0x1f) {
            tagNumber = 0;
            int n = 0;
            while (true) {
                if (p >= limit) {
                    throw new DerException("truncated tag", base + pos);
                }
                int t = buf[p++] & 0xff;
                n++;
                if (n == 1 && t == 0x80) {
                    throw new DerException("non-minimal tag number", base + pos);
                }
                if (n > MAX_TAG_BYTES) {
                    throw new DerException("tag number too large", base + pos);
                }
                tagNumber = (tagNumber << 7) | (t & 0x7f);
                if ((t & 0x80) == 0) {
                    break;
                }
            }
            if (tagNumber < 0x1f) {
                nonMinimal = true;
            }
        }
        if (p >= limit) {
            throw new DerException("truncated length", base + pos);
        }
        int lengthByte = buf[p++] & 0xff;
        long length;
        if (lengthByte < 0x80) {
            length = lengthByte;
        } else if (lengthByte == 0x80) {
            if (!constructed) {
                throw new DerException("indefinite length for a primitive element", base + pos);
            }
            length = -1;
        } else if (lengthByte == 0xff) {
            throw new DerException("reserved length octet 0xff", base + pos);
        } else {
            int n = lengthByte & 0x7f;
            if (n > MAX_LENGTH_BYTES) {
                throw new DerException("length field of " + n + " bytes", base + pos);
            }
            if (p + n > limit) {
                throw new DerException("truncated length", base + pos);
            }
            length = 0;
            for (int i = 0; i < n; i++) {
                length = (length << 8) | (buf[p++] & 0xff);
            }
            if (buf[p - n] == 0 || length < 0x80) {
                nonMinimal = true;
            }
        }
        if (tagClass == DerElement.UNIVERSAL && tagNumber == 0) {
            throw new DerException("unexpected end-of-contents", base + pos);
        }
        if (length >= 0 && length > (long) limit - p) {
            throw new DerException("length 0x" + Long.toHexString(length) + " of "
                    + describe(tagClass, tagNumber) + " exceeds the 0x"
                    + Long.toHexString((long) limit - p) + " available bytes", base + pos);
        }
        return new DerElement(buf, base, pos, tagClass, constructed, tagNumber, p, length,
                nonMinimal, depth);
    }

    private static String describe(int tagClass, long tagNumber) {
        if (tagClass == DerElement.CONTEXT) {
            return "[" + tagNumber + "]";
        }
        return "tag " + tagNumber;
    }

    private static final class Frame {
        private final DerElement element;
        /** only for indefinite length elements: the limit of the parent */
        private final int limit;
        private int pos;

        private Frame(DerElement element, int limit) {
            this.element = element;
            this.limit = limit;
            this.pos = element.contentIndex();
        }
    }
}
