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
package io.github.struppigel.tools.sigscanner.pattern;

import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.*;

public class PatternLanguageTest {

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) result[i] = (byte) values[i];
        return result;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] utf16(String s) {
        return s.getBytes(StandardCharsets.UTF_16LE);
    }

    private static void assertSyntaxError(String pattern, int column) {
        try {
            Pattern.parse(pattern);
            fail("expected a syntax error for " + pattern);
        } catch (PatternSyntaxException e) {
            assertEquals(e.getColumn(), column, "column of error for " + pattern + ": " + e.getMessage());
        }
    }

    @Test
    public void hexBytes() {
        Pattern p = Pattern.parse("CA FE ba be");
        assertTrue(p.matches(bytes(0xCA, 0xFE, 0xBA, 0xBE, 0x00)));
        assertFalse(p.matches(bytes(0xCA, 0xFE, 0xBA)));
        assertEquals(Pattern.parse("CAFEBABE"), p);
        assertEquals(p.getMinLength(), 4);
        assertEquals(p.getMaxLength(), 4);
        assertEquals(p.matchAt(bytes(0, 0xCA, 0xFE, 0xBA, 0xBE), 1), 5);
    }

    @Test
    public void wildcards() {
        Pattern p = Pattern.parse("01 ?? .. 04");
        assertTrue(p.matches(bytes(1, 0xFF, 0x00, 4)));
        assertFalse(p.matches(bytes(1, 2, 3, 5)));
        assertTrue(p.compiled().isFlat());
    }

    @Test
    public void nibbleWildcards() {
        // regression: v2 compared the high nibble without shifting it
        Pattern high = Pattern.parse("4?");
        assertTrue(high.matches(bytes(0x40)));
        assertTrue(high.matches(bytes(0x4F)));
        assertFalse(high.matches(bytes(0x54)));
        Pattern low = Pattern.parse("?A");
        assertTrue(low.matches(bytes(0x1A)));
        assertTrue(low.matches(bytes(0xFA)));
        assertFalse(low.matches(bytes(0xAB)));
        assertTrue(Pattern.parse("01 2? ?3").matches(bytes(0x01, 0x2E, 0xF3)));
    }

    @Test
    public void byteClasses() {
        assertTrue(Pattern.parse("01 **").matches(bytes(1, 0x80)));
        assertFalse(Pattern.parse("01 **").matches(bytes(1, 0)));
        assertTrue(Pattern.parse("%%").matches(bytes(0x20)));
        assertTrue(Pattern.parse("%%").matches(bytes(0x7F)));
        assertFalse(Pattern.parse("%%").matches(bytes(0x1F)));
        assertTrue(Pattern.parse("'v' %& '.' %&").matches(ascii("v3.1")));
        assertFalse(Pattern.parse("'v' %& '.' %&").matches(ascii("v3.x")));
        assertTrue(Pattern.parse("!%").matches(bytes(0)));
        assertFalse(Pattern.parse("!%").matches(bytes(0x41)));
        assertTrue(Pattern.parse("_%").matches(bytes(0x80)));
        assertFalse(Pattern.parse("_%").matches(bytes(0)));
        assertFalse(Pattern.parse("_%").matches(bytes(0x41)));
    }

    @Test
    public void boundlessRange() {
        byte[] input = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        assertFalse(Pattern.parse("01 02 03 04 05 [3-] 08 09 0A").matches(input));
        assertTrue(Pattern.parse("01 02 03 04 05 [2-] 08 09 0A").matches(input));
    }

    @Test
    public void limitedRange() {
        byte[] input = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        assertFalse(Pattern.parse("01 02 03 04 05 [-2] 09 0A").matches(input));
        assertTrue(Pattern.parse("01 02 03 04 05 [-3] 09 0A").matches(input));
        assertTrue(Pattern.parse("01 02 03 04 05 [2-3] 09 0A").matches(input));
        assertTrue(Pattern.parse("01 [3] 05").matches(input));
        assertFalse(Pattern.parse("01 [2] 05").matches(input));
        assertTrue(Pattern.parse("01 [0x3] 05").matches(input));
    }

    @Test
    public void trailingRangeAtEndOfInput() {
        // regression: v2 failed if a range was the last element at the end of the buffer
        assertTrue(Pattern.parse("01 02 [1-]").matches(bytes(1, 2, 3)));
        assertEquals(Pattern.parse("01 02 [1-]").matchAt(bytes(1, 2, 3), 0), 3);
        assertFalse(Pattern.parse("01 02 [2-]").matches(bytes(1, 2, 3)));
    }

    @Test
    public void alternatives() {
        Pattern p = Pattern.parse("CA (FE | ?F BA | CA ?? 11 [1-2] BE)");
        assertTrue(p.matches(bytes(0xCA, 0xFE)));
        assertTrue(p.matches(bytes(0xCA, 0x0F, 0xBA)));
        assertTrue(p.matches(bytes(0xCA, 0xCA, 0x00, 0x11, 0x00, 0xBE)));
        assertTrue(p.matches(bytes(0xCA, 0xCA, 0x00, 0x11, 0x00, 0x00, 0xBE)));
        assertFalse(p.matches(bytes(0xCA, 0xCA, 0x00, 0x11, 0xBE)));
        assertFalse(p.matches(bytes(0xCA, 0x0F, 0xBB)));
    }

    @Test
    public void multiElementAlternativeWithTail() {
        // regression: v2 consumed only the first element of a branch
        Pattern p = Pattern.parse("01 (02 03 | 05) 03");
        assertFalse(p.matches(bytes(1, 2, 3)));
        assertTrue(p.matches(bytes(1, 2, 3, 3)));
        assertTrue(p.matches(bytes(1, 5, 3)));
        assertEquals(p.getMinLength(), 3);
        assertEquals(p.getMaxLength(), 4);
    }

    @Test
    public void alternativesBacktrackIntoLaterBranch() {
        // the first branch matches but the continuation fails, the second branch must be tried
        Pattern p = Pattern.parse("(01 | 01 02) 03");
        assertTrue(p.matches(bytes(1, 2, 3)));
        Pattern nested = Pattern.parse("(01 (02 | 02 02) | 04) 03");
        assertTrue(nested.matches(bytes(1, 2, 2, 3)));
        assertTrue(nested.matches(bytes(4, 3)));
        assertFalse(nested.matches(bytes(1, 3)));
    }

    @Test
    public void jumpsBacktrack() {
        Pattern p = Pattern.parse("01 [0-4] 02 03");
        assertTrue(p.matches(bytes(1, 2, 9, 2, 3)));
        assertEquals(p.matchAt(bytes(1, 2, 9, 2, 3), 0), 5);
    }

    @Test
    public void asciiStrings() {
        assertTrue(Pattern.parse("'Inno'").matches(ascii("Inno Setup")));
        assertTrue(Pattern.parse("\"Inno\"").matches(ascii("Inno Setup")));
        assertTrue(Pattern.parse("EF BE AD DE 'Null' ?? 'oftInst'").matches(
                concat(bytes(0xEF, 0xBE, 0xAD, 0xDE), ascii("NullsoftInst"))));
        // '?' is literal inside quotes
        assertTrue(Pattern.parse("'PK??'").matches(ascii("PK??")));
        assertFalse(Pattern.parse("'PK??'").matches(ascii("PKab")));
        assertTrue(Pattern.parse("'PK' ?? ??").matches(ascii("PKab")));
    }

    @Test
    public void stringEscapes() {
        assertTrue(Pattern.parse("'MEI\\x0C\\x0B\\x0A\\x0B\\x0E'").matches(
                bytes('M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E)));
        assertTrue(Pattern.parse("'a\\'b\\\\c\\\"'").matches(ascii("a'b\\c\"")));
        assertTrue(Pattern.parse("'\\n\\r\\t\\0'").matches(bytes('\n', '\r', '\t', 0)));
        assertTrue(Pattern.parse("\"it's\"").matches(ascii("it's")));
    }

    @Test
    public void nonAsciiStringsAreUtf8() {
        assertTrue(Pattern.parse("'é'").matches(bytes(0xC3, 0xA9)));
        assertFalse(Pattern.parse("'é'").matches(bytes(0xE9)));
        assertTrue(Pattern.parse("'\\xE9'").matches(bytes(0xE9)));
    }

    @Test
    public void wideStrings() {
        Pattern p = Pattern.parse("w'Setup'");
        assertTrue(p.matches(utf16("Setup")));
        assertFalse(p.matches(ascii("Setup")));
        assertTrue(Pattern.parse("w'***messages***'").matches(utf16("***messages***")));
        assertTrue(Pattern.parse("w'\\x41'").matches(bytes(0x41, 0x00)));
    }

    @Test
    public void caseInsensitiveStrings() {
        Pattern p = Pattern.parse("i'kernel32'");
        assertTrue(p.matches(ascii("KERNEL32")));
        assertTrue(p.matches(ascii("kernel32")));
        assertTrue(p.matches(ascii("KeRnEl32")));
        assertFalse(p.matches(ascii("kernel33")));
        // letters differ from their case only in bit 0x20, but so do '@' and '`'
        Pattern at = Pattern.parse("i'a@'");
        assertTrue(at.matches(ascii("A@")));
        assertFalse(at.matches(ascii("A`")));
        Pattern wide = Pattern.parse("wi'Ab'");
        assertTrue(wide.matches(utf16("aB")));
        assertTrue(wide.matches(utf16("AB")));
        assertFalse(wide.matches(ascii("AB")));
        // the case insensitive pattern stays on the flat fast path
        assertTrue(p.compiled().isFlat());
    }

    @Test
    public void asciiOrWideStrings() {
        Pattern p = Pattern.parse("aw'Setup'");
        assertTrue(p.matches(ascii("Setup")));
        assertTrue(p.matches(utf16("Setup")));
        assertFalse(p.matches(utf16("setup")));
        Pattern both = Pattern.parse("awi'Setup'");
        assertTrue(both.matches(ascii("SETUP")));
        assertTrue(both.matches(utf16("setup")));
        assertEquals(Pattern.parse("wa'x'"), Pattern.parse("aw'x'"));
    }

    @Test
    public void modifierAfterHexBytes() {
        assertTrue(Pattern.parse("AB aw'x'").matches(bytes(0xAB, 'x')));
        assertTrue(Pattern.parse("aB 01").matches(bytes(0xAB, 0x01)));
        assertSyntaxError("a'x'", 1);
    }

    @Test
    public void followRelativeJumps() {
        // E8 rel32 -> target at 5 + 3 = 8
        byte[] call = bytes(0xE8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x55, 0x8B, 0xEC);
        Pattern p = Pattern.parse("E8 $$$$$$$$ 55 8B EC");
        assertTrue(p.matches(call));
        assertTrue(p.hasFollowTokens());
        assertEquals(p.matchAt(call, 0), 11);
        assertFalse(Pattern.parse("E8 $$$$$$$$ 55 8B ED").matches(call));
        // rel8 backwards: EB FC jumps from 4 to 0
        byte[] back = bytes(0x55, 0x90, 0x90, 0xEB, 0xFB);
        assertTrue(Pattern.parse("EB $$ 55").matchAt(back, 3) > 0);
        // target outside of the data
        assertFalse(Pattern.parse("EB $$ 55").matches(bytes(0xEB, 0x7F)));
        // rel16
        assertTrue(Pattern.parse("$$$$ 'x'").matches(bytes(0x01, 0x00, 0x00, 'x')));
    }

    @Test
    public void followAbsoluteAddresses() {
        // push 0x00000006 with identity mapping and image base 0
        byte[] push = bytes(0x68, 0x06, 0x00, 0x00, 0x00, 0x00, 'M', 'Z');
        assertTrue(Pattern.parse("68 ######## 'MZ'").matches(push));
        assertFalse(Pattern.parse("68 ######## 'PE'").matches(push));
    }

    @Test
    public void syntaxErrors() {
        assertSyntaxError("", 1);
        assertSyntaxError("?? ?? [3]", 1);
        assertSyntaxError("CA F", 4);
        assertSyntaxError("CA FG", 4);
        assertSyntaxError("CA ?", 4);
        assertSyntaxError("CA .", 4);
        assertSyntaxError("CA (FE", 4);
        assertSyntaxError("CA (FE |)", 9);
        assertSyntaxError("CA FE)", 6);
        assertSyntaxError("CA [5-2] FE", 4);
        assertSyntaxError("CA [0] FE", 4);
        assertSyntaxError("CA [-] FE", 4);
        assertSyntaxError("CA [0x200000] FE", 5);
        assertSyntaxError("CA 'abc", 4);
        assertSyntaxError("CA ''", 4);
        assertSyntaxError("CA '\\q'", 5);
        assertSyntaxError("CA $$$", 4);
        assertSyntaxError("CA ** %x", 7);
        assertSyntaxError("CA ww'x'", 5);
        assertSyntaxError("CA wx'x'", 4);
        assertSyntaxError("CA Z", 4);
    }

    @Test
    public void atomsAreLiteralRuns() {
        Atom[] atoms = Pattern.parse("?? ?? 60 BE 11 22 [2-4] 8D BE").compiled().atoms();
        assertEquals(atoms.length, 1);
        assertEquals(atoms[0].bytes(), bytes(0x60, 0xBE, 0x11, 0x22));
        assertEquals(atoms[0].offMin(), 2);
        assertEquals(atoms[0].offMax(), 2);
    }

    @Test
    public void atomsPreferRareBytes() {
        Atom[] atoms = Pattern.parse("00 00 00 00 ?? 'MZ'").compiled().atoms();
        assertEquals(atoms.length, 1);
        assertEquals(atoms[0].bytes(), ascii("MZ"));
        assertEquals(atoms[0].offMin(), 5);
    }

    @Test
    public void atomsAfterJumpHaveOffsetRange() {
        Atom[] atoms = Pattern.parse("01 [2-5] 'PYZ'").compiled().atoms();
        assertEquals(atoms.length, 1);
        assertEquals(atoms[0].bytes(), ascii("PYZ"));
        assertEquals(atoms[0].offMin(), 3);
        assertEquals(atoms[0].offMax(), 6);
    }

    @Test
    public void atomsStopAtFollowTokens() {
        Atom[] atoms = Pattern.parse("E8 $$$$$$$$ 'long literal after follow'").compiled().atoms();
        assertEquals(atoms.length, 0);
        Atom[] prefix = Pattern.parse("60 E8 11 22 $$$$$$$$ 'long literal after follow'").compiled().atoms();
        assertEquals(prefix.length, 1);
        assertEquals(prefix[0].bytes(), bytes(0x60, 0xE8, 0x11, 0x22));
    }

    @Test
    public void atomsForEachBranch() {
        Atom[] atoms = Pattern.parse("aw'Setup'").compiled().atoms();
        assertEquals(atoms.length, 2);
        Set<String> found = new HashSet<>();
        for (Atom a : atoms) found.add(Arrays.toString(a.bytes()));
        assertTrue(found.contains(Arrays.toString(ascii("Setup"))));
        assertTrue(found.contains(Arrays.toString(Arrays.copyOf(utf16("Setup"), 8))));
    }

    @Test
    public void atomsExpandCaseVariants() {
        Atom[] atoms = Pattern.parse("i'ab1'").compiled().atoms();
        assertEquals(atoms.length, 4);
        Set<String> found = new HashSet<>();
        for (Atom a : atoms) found.add(new String(a.bytes(), StandardCharsets.ISO_8859_1));
        assertEquals(found, new HashSet<>(Arrays.asList("AB1", "Ab1", "aB1", "ab1")));
        // two case insensitive letters are not selective enough for an atom
        assertEquals(Pattern.parse("i'ab'").compiled().atoms().length, 0);
        // at most 4 case insensitive letters per atom
        assertEquals(Pattern.parse("i'abcdefgh'").compiled().atoms().length, 16);
    }

    @Test
    public void noAtomForShortOrCommonLiterals() {
        assertEquals(Pattern.parse("4D ?? ?? 5A").compiled().atoms().length, 0);
        assertEquals(Pattern.parse("00 00 00").compiled().atoms().length, 0);
    }

    @Test
    public void atomsBeforeWideJumpsArePreferred() {
        // every start in the range of the jump has to be checked for an atom behind it
        Atom[] before = Pattern.parse("'abcd' [0-30000] 'wxyz'").compiled().atoms();
        assertEquals(before.length, 1);
        assertEquals(before[0].bytes(), ascii("abcd"));
        assertEquals(before[0].offMax(), 0);
        // unless the atom behind it is much more selective
        Atom[] behind = Pattern.parse("'AB' [0-30000] 'longer literal'").compiled().atoms();
        assertEquals(behind.length, 1);
        assertEquals(behind[0].bytes(), ascii("longer l"));
        assertEquals(behind[0].offMin(), 2);
        assertEquals(behind[0].offMax(), 30002);
    }

    @Test
    public void caseInsensitiveAsciiOrWideTextHasAtoms() {
        // 16 case variants of 4 letters for each branch, as often written in YARA rules
        assertEquals(Pattern.parse("awi'password'").compiled().atoms().length, 32);
        assertEquals(Pattern.parse("(55 8B EC | 53 56 57)").compiled().atoms().length, 2);
    }

    @Test
    public void firstBytes() {
        CompiledPattern p = Pattern.parse("(55 | 6?) 8B").compiled();
        assertFalse(p.anyFirst());
        assertTrue(p.firstBytes()[0x55]);
        assertTrue(p.firstBytes()[0x6A]);
        assertFalse(p.firstBytes()[0x56]);
        assertTrue(Pattern.parse("?? 8B").compiled().anyFirst());
        assertTrue(Pattern.parse("[2] 8B").compiled().anyFirst());
    }

    @Test
    public void stepBudgetBoundsBacktracking() {
        byte[] input = new byte[4096];
        Pattern p = Pattern.parse("[0-] [0-] [0-] 01");
        assertFalse(p.matches(input));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
