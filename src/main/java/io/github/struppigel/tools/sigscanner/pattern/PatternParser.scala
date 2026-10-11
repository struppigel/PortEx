/**
 * *****************************************************************************
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
 * ****************************************************************************
 */
package io.github.struppigel.tools.sigscanner.pattern

import java.nio.charset.StandardCharsets
import scala.collection.mutable.ArrayBuffer

/**
 * Recursive descent parser for signature patterns. See docs/SIGNATURES.md for
 * the syntax.
 */
private[sigscanner] object PatternParser {

  /** largest allowed jump, also the cap of open ranges like [5-] */
  val MaxSpan: Int = 0x100000

  def parse(source: String): Vector[PNode] = parseHexOnly(source).getOrElse(new Parser(source).parsePattern())

  private def hexDigit(c: Char): Int =
    if (c >= '0' && c <= '9') c - '0'
    else if (c >= 'A' && c <= 'F') c - 'A' + 10
    else if (c >= 'a' && c <= 'f') c - 'a' + 10
    else -1

  /**
   * Fast path for the most common patterns, which only consist of hex bytes,
   * nibble wildcards and ??. Returns None for everything else, including
   * errors, which the full parser reports.
   */
  private def parseHexOnly(source: String): Option[Vector[PNode]] = {
    val values = new Array[Byte](source.length / 2 + 1)
    val masks = new Array[Byte](source.length / 2 + 1)
    var n = 0
    var i = 0
    var concrete = false
    while (i < source.length) {
      val c = source.charAt(i)
      if (c == ' ' || c == '\t') i += 1
      else {
        if (i + 1 >= source.length) return None
        val c2 = source.charAt(i + 1)
        val h1 = hexDigit(c)
        val h2 = hexDigit(c2)
        if (h1 >= 0 && h2 >= 0) { values(n) = (h1 << 4 | h2).toByte; masks(n) = 0xFF.toByte }
        else if (c == '?' && c2 == '?') { values(n) = 0; masks(n) = 0 }
        else if (h1 >= 0 && c2 == '?') { values(n) = (h1 << 4).toByte; masks(n) = 0xF0.toByte }
        else if (c == '?' && h2 >= 0) { values(n) = h2.toByte; masks(n) = 0x0F }
        else return None
        concrete |= masks(n) != 0
        n += 1
        i += 2
      }
    }
    if (n == 0 || !concrete) None
    else Some(Vector(PBytes(java.util.Arrays.copyOf(values, n), java.util.Arrays.copyOf(masks, n))))
  }

  private class Parser(src: String) {
    private var i = 0

    private def error(msg: String, at: Int = i): Nothing =
      throw new PatternSyntaxException(msg, at + 1)

    private def peek: Char = if (i < src.length) src.charAt(i) else '\u0000'

    private def peekAt(k: Int): Char = if (i + k < src.length) src.charAt(i + k) else '\u0000'

    private def atEnd: Boolean = i >= src.length

    private def skipWhitespace(): Unit =
      while (!atEnd && Character.isWhitespace(peek)) i += 1

    def parsePattern(): Vector[PNode] = {
      val seq = parseSequence(topLevel = true)
      if (seq.isEmpty) error("empty pattern", 0)
      if (!seq.exists(constrains)) error("pattern has no concrete byte, only wildcards and jumps", 0)
      seq
    }

    /** true if the node restricts the input somehow */
    private def constrains(node: PNode): Boolean = node match {
      case PBytes(_, masks) => masks.exists(_ != 0)
      case PClass(_) => true
      case PAlt(branches) => branches.forall(_.exists(constrains))
      case _ => false
    }

    private def parseSequence(topLevel: Boolean): Vector[PNode] = {
      val nodes = ArrayBuffer[PNode]()
      var continue = true
      while (continue) {
        skipWhitespace()
        if (atEnd) {
          continue = false
        } else peek match {
          case '|' | ')' =>
            if (topLevel) error(s"unexpected '$peek' outside of a group")
            continue = false
          case _ => nodes ++= parseElement()
        }
      }
      merge(nodes)
    }

    /** merges consecutive PBytes nodes */
    private def merge(nodes: ArrayBuffer[PNode]): Vector[PNode] = {
      val result = Vector.newBuilder[PNode]
      val values = new scala.collection.mutable.ArrayBuilder.ofByte
      val masks = new scala.collection.mutable.ArrayBuilder.ofByte
      var pending = false
      def flush(): Unit = if (pending) {
        result += PBytes(values.result(), masks.result())
        values.clear()
        masks.clear()
        pending = false
      }
      for (node <- nodes) node match {
        case PBytes(v, m) =>
          values ++= v
          masks ++= m
          pending = true
        case other =>
          flush()
          result += other
      }
      flush()
      result.result()
    }

    private def isHex(c: Char): Boolean =
      (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')

    private def hexValue(c: Char): Int = Character.digit(c, 16)

    private def single(value: Int, mask: Int): PBytes = PBytes(Array(value.toByte), Array(mask.toByte))

    private def parseElement(): Seq[PNode] = {
      val start = i
      val c = peek
      c match {
        case '\'' | '"' => Seq(parseString(Set.empty, start))
        case 'w' | 'i' => parseModifiedString(start)
        case 'a' if peekAt(1) == 'w' || peekAt(1) == 'i' || peekAt(1) == '\'' || peekAt(1) == '"' =>
          parseModifiedString(start)
        case _ if isHex(c) =>
          val c2 = peekAt(1)
          if (isHex(c2)) {
            i += 2
            Seq(single(hexValue(c) << 4 | hexValue(c2), 0xFF))
          } else if (c2 == '?') {
            i += 2
            Seq(single(hexValue(c) << 4, 0xF0))
          } else error("incomplete byte, expected a second hex digit or '?'")
        case '?' =>
          val c2 = peekAt(1)
          if (c2 == '?') {
            i += 2
            Seq(single(0, 0))
          } else if (isHex(c2)) {
            i += 2
            Seq(single(hexValue(c2), 0x0F))
          } else error("expected '??' or a nibble wildcard like '?A'")
        case '.' =>
          if (peekAt(1) == '.') {
            i += 2
            Seq(single(0, 0))
          } else error("expected '..'")
        case '*' | '%' | '!' | '_' =>
          val token = src.substring(i, math.min(i + 2, src.length))
          ByteClass.byToken(token) match {
            case Some(cls) =>
              i += 2
              Seq(PClass(cls))
            case None => error(s"unknown byte class '$token', expected one of ${ByteClass.all.mkString(" ")}")
          }
        case '$' | '#' =>
          var n = 0
          while (peekAt(n) == c) n += 1
          if (n != 2 && n != 4 && n != 8 && n != 16)
            error(s"'$c' must appear 2, 4, 8 or 16 times in a row (1, 2, 4 or 8 byte value), found $n")
          i += n
          Seq(PFollow(absolute = c == '#', size = n / 2))
        case '[' => Seq(parseJump())
        case '(' => parseGroup()
        case _ => error(s"unexpected character '$c'")
      }
    }

    private def parseModifiedString(start: Int): Seq[PNode] = {
      val mods = scala.collection.mutable.Set[Char]()
      while (!atEnd && (peek == 'a' || peek == 'w' || peek == 'i')) {
        if (!mods.add(peek)) error(s"duplicate string modifier '$peek'")
        i += 1
      }
      if (peek != '\'' && peek != '"') error("expected a quoted string after the string modifiers", start)
      if (mods.contains('a') && !mods.contains('w'))
        error("modifier 'a' is only allowed together with 'w' (aw = ASCII or UTF-16LE)", start)
      Seq(parseString(mods.toSet, start))
    }

    /**
     * Parses a quoted string. The resulting code units are encoded as UTF-8,
     * UTF-16LE (w) or both (aw), letters are case insensitive with modifier i.
     */
    private def parseString(mods: Set[Char], start: Int): PNode = {
      val quote = peek
      i += 1
      // each element is either a code unit of the text or a raw byte from \xHH
      val units = ArrayBuffer[(Int, Boolean)]() // (value, isRawByte)
      val text = new StringBuilder
      def flushText(): Unit = {
        var k = 0
        while (k < text.length) {
          val cp = Character.codePointAt(text, k)
          units += ((cp, false))
          k += Character.charCount(cp)
        }
        text.clear()
      }
      var closed = false
      while (!closed) {
        if (atEnd) error("unterminated string", start)
        val c = peek
        if (c == quote) {
          i += 1
          closed = true
        } else if (c == '\\') {
          val e = peekAt(1)
          e match {
            case '\\' | '\'' | '"' => text += e; i += 2
            case 'n' => text += '\n'; i += 2
            case 'r' => text += '\r'; i += 2
            case 't' => text += '\t'; i += 2
            case '0' => text += '\u0000'; i += 2
            case 'x' =>
              if (!isHex(peekAt(2)) || !isHex(peekAt(3))) error("expected two hex digits after \\x")
              flushText()
              units += ((hexValue(peekAt(2)) << 4 | hexValue(peekAt(3)), true))
              i += 4
            case _ => error(s"unknown escape sequence '\\$e'")
          }
        } else {
          text += c
          i += 1
        }
      }
      flushText()
      if (units.isEmpty) error("empty string", start)
      val caseInsensitive = mods.contains('i')
      val ascii = encode(units, wide = false, caseInsensitive)
      val wide = encode(units, wide = true, caseInsensitive)
      if (mods.contains('a')) PAlt(Vector(Vector(ascii), Vector(wide)))
      else if (mods.contains('w')) wide
      else ascii
    }

    private def isAsciiLetter(cp: Int): Boolean = (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z')

    private def encode(units: Seq[(Int, Boolean)], wide: Boolean, caseInsensitive: Boolean): PBytes = {
      val values = ArrayBuffer[Byte]()
      val masks = ArrayBuffer[Byte]()
      def add(v: Int, m: Int): Unit = { values += v.toByte; masks += m.toByte }
      for ((cp, raw) <- units) {
        val letterMask = if (caseInsensitive && !raw && isAsciiLetter(cp)) 0xDF else 0xFF
        val v = if (letterMask == 0xDF) Character.toUpperCase(cp) else cp
        if (raw) {
          add(v, 0xFF)
          if (wide) add(0, 0xFF)
        } else if (wide) {
          val chars = Character.toChars(cp)
          for (ch <- chars) {
            add(if (letterMask == 0xDF) v & 0xFF else ch & 0xFF, letterMask)
            add((ch >> 8) & 0xFF, 0xFF)
          }
        } else if (cp < 0x80) {
          add(v, letterMask)
        } else {
          for (b <- new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) add(b & 0xFF, 0xFF)
        }
      }
      PBytes(values.toArray, masks.toArray)
    }

    private def parseInt(): Int = {
      val start = i
      val hex = peek == '0' && (peekAt(1) == 'x' || peekAt(1) == 'X')
      if (hex) i += 2
      val digitsStart = i
      while (!atEnd && (if (hex) isHex(peek) else Character.isDigit(peek))) i += 1
      if (i == digitsStart) error("expected a number", start)
      val digits = src.substring(digitsStart, i)
      val value = try java.lang.Long.parseLong(digits, if (hex) 16 else 10)
        catch { case _: NumberFormatException => error("number too large", start) }
      if (value > MaxSpan) error(s"jump is larger than the maximum of 0x${MaxSpan.toHexString} bytes", start)
      value.toInt
    }

    private def parseJump(): PNode = {
      val start = i
      i += 1 // '['
      skipWhitespace()
      val min = if (peek == '-') 0 else parseInt()
      skipWhitespace()
      val node = if (peek == '-') {
        val dash = i
        i += 1
        skipWhitespace()
        if (peek == ']') {
          if (dash == start + 1) error("a range needs at least one bound", start)
          PJump(min, PJump.Unbounded)
        } else {
          val max = parseInt()
          if (max < min) error(s"range [$min-$max] has a lower bound greater than its upper bound", start)
          PJump(min, max)
        }
      } else PJump(min, min)
      skipWhitespace()
      if (peek != ']') error("expected ']' to close the range")
      i += 1
      if (node == PJump(0, 0)) error("empty range [0]", start)
      node
    }

    /** a group without alternatives is returned as plain sequence */
    private def parseGroup(): Seq[PNode] = {
      val start = i
      i += 1 // '('
      val branches = ArrayBuffer[Vector[PNode]]()
      var done = false
      while (!done) {
        val branchStart = i
        val branch = parseSequence(topLevel = false)
        if (branch.isEmpty) error("empty branch in group", branchStart)
        branches += branch
        if (atEnd) error("unclosed group, expected ')'", start)
        if (peek == '|') i += 1
        else { // ')'
          i += 1
          done = true
        }
      }
      if (branches.length == 1) branches.head
      else Seq(PAlt(branches.toVector))
    }
  }
}
