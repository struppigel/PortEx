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

/**
 * A set of byte values that one pattern position may match, e.g. "any non-zero
 * byte". The token spellings are the ones of Detect It Easy.
 */
private[sigscanner] final class ByteClass private (val token: String, accepts: Int => Boolean) {

  private val table: Array[Boolean] = Array.tabulate(256)(accepts)

  def contains(b: Int): Boolean = table(b & 0xFF)

  override def toString: String = token
}

private[sigscanner] object ByteClass {
  private def isPrintable(b: Int): Boolean = b >= 0x20 && b <= 0x7F

  /** "**" any byte except 00 */
  val NonZero = new ByteClass("**", _ != 0)
  /** "%%" printable ASCII 20-7F */
  val Printable = new ByteClass("%%", isPrintable)
  /** "%&" ASCII digit 30-39 */
  val Digit = new ByteClass("%&", b => b >= 0x30 && b <= 0x39)
  /** "!%" not printable ASCII */
  val NotPrintable = new ByteClass("!%", b => !isPrintable(b))
  /** "_%" neither printable ASCII nor 00 */
  val NotPrintableNonZero = new ByteClass("_%", b => !isPrintable(b) && b != 0)

  val all: List[ByteClass] = List(NonZero, Printable, Digit, NotPrintable, NotPrintableNonZero)

  def byToken(token: String): Option[ByteClass] = all.find(_.token == token)
}

/**
 * Syntax tree of a parsed pattern. Consecutive byte elements (hex bytes, nibbles,
 * wildcards and strings) are merged into one PBytes node.
 */
private[sigscanner] sealed trait PNode

/**
 * A sequence of bytes that match if (input & mask) == value at every position.
 * A mask of 0 is a wildcard, F0/0F are nibble wildcards and DF is a case
 * insensitive ASCII letter.
 */
private[sigscanner] final case class PBytes(values: Array[Byte], masks: Array[Byte]) extends PNode {
  def length: Int = values.length

  override def equals(other: Any): Boolean = other match {
    case o: PBytes => java.util.Arrays.equals(values, o.values) && java.util.Arrays.equals(masks, o.masks)
    case _ => false
  }

  override def hashCode(): Int = java.util.Arrays.hashCode(values) * 31 + java.util.Arrays.hashCode(masks)
}

/** one byte that must be in the given byte class */
private[sigscanner] final case class PClass(cls: ByteClass) extends PNode

/** skips min to max bytes, max == PJump.Unbounded for an open range */
private[sigscanner] final case class PJump(min: Int, max: Int) extends PNode {
  def isUnbounded: Boolean = max == PJump.Unbounded
}

private[sigscanner] object PJump {
  val Unbounded: Int = -1
}

/** one of the branches must match */
private[sigscanner] final case class PAlt(branches: Vector[Vector[PNode]]) extends PNode

/**
 * Reads a little endian value with the given size in bytes and continues
 * matching at the address it refers to. If absolute is false the value is a
 * signed displacement relative to the end of the field, otherwise it is a
 * virtual address.
 */
private[sigscanner] final case class PFollow(absolute: Boolean, size: Int) extends PNode
