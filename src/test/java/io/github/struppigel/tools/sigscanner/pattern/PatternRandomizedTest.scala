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

import org.testng.Assert._
import org.testng.annotations.Test

import scala.util.Random

/**
 * Compares the compiled matcher with a naive reference matcher that computes
 * all possible match ends, on random patterns and inputs.
 */
class PatternRandomizedTest {

  private val alphabet = Array[Int](0x41, 0x42, 0x43, 0x00)

  /** all end positions of matches of the sequence starting at pos */
  private def ends(nodes: Seq[PNode], pos: Int, input: Array[Byte]): Set[Int] = nodes match {
    case Seq() => Set(pos)
    case head +: tail =>
      val afterHead: Set[Int] = head match {
        case PBytes(v, m) =>
          if (pos + v.length > input.length) Set()
          else if (v.indices.forall(k => (input(pos + k) & m(k) & 0xFF) == (v(k) & 0xFF))) Set(pos + v.length)
          else Set()
        case PClass(c) => if (pos < input.length && c.contains(input(pos) & 0xFF)) Set(pos + 1) else Set()
        case PJump(min, max) =>
          val upper = if (max == PJump.Unbounded) input.length - pos else max
          (min to upper).map(pos + _).filter(_ <= input.length).toSet
        case PAlt(branches) => branches.flatMap(b => ends(b, pos, input)).toSet
        case PFollow(_, _) => throw new IllegalStateException("not generated")
      }
      afterHead.flatMap(p => ends(tail, p, input))
  }

  private def hex(b: Int): String = "%02X".format(b)

  private def randomElement(rnd: Random, depth: Int): String = rnd.nextInt(if (depth > 1) 6 else 7) match {
    case 0 | 1 => hex(alphabet(rnd.nextInt(alphabet.length)))
    case 2 => "??"
    case 3 => if (rnd.nextBoolean()) hex(alphabet(rnd.nextInt(3))).substring(0, 1) + "?" else "?" + hex(alphabet(rnd.nextInt(3))).substring(1)
    case 4 => List("**", "%%", "!%")(rnd.nextInt(3))
    case 5 =>
      val min = rnd.nextInt(3)
      rnd.nextInt(3) match {
        case 0 => s"[${min + 1}]"
        case 1 => s"[$min-${min + rnd.nextInt(3) + 1}]"
        case _ => s"[$min-]"
      }
    case 6 =>
      val branches = (0 until 2 + rnd.nextInt(2)).map(_ => randomSequence(rnd, depth + 1, 1 + rnd.nextInt(3)))
      branches.mkString("(", " | ", ")")
  }

  private def randomSequence(rnd: Random, depth: Int, length: Int): String =
    (0 until length).map(_ => randomElement(rnd, depth)).mkString(" ")

  @Test
  def compiledMatcherAgreesWithReference(): Unit = {
    val rnd = new Random(0x5EED)
    var compared = 0
    var matched = 0
    for (_ <- 0 until 3000) {
      val source = randomSequence(rnd, 0, 1 + rnd.nextInt(5))
      val maybePattern = try Some(Pattern.parse(source)) catch { case _: PatternSyntaxException => None }
      for (pattern <- maybePattern; _ <- 0 until 10) {
        val input = Array.fill(rnd.nextInt(16))(alphabet(rnd.nextInt(alphabet.length)).toByte)
        for (start <- input.indices) {
          val expected = ends(pattern.nodes, start, input)
          val actual = pattern.matchAt(input, start)
          compared += 1
          if (expected.isEmpty) assertEquals(actual, -1, s"pattern '$source' at $start of ${input.mkString(",")}")
          else {
            matched += 1
            assertTrue(expected.contains(actual), s"pattern '$source' at $start of ${input.mkString(",")}: $actual not in $expected")
          }
        }
      }
    }
    assertTrue(compared > 10000, s"only $compared comparisons")
    assertTrue(matched > 1000, s"only $matched matches")
  }

  @Test
  def minAndMaxLengthBoundMatches(): Unit = {
    val rnd = new Random(42)
    for (_ <- 0 until 2000) {
      val source = randomSequence(rnd, 0, 1 + rnd.nextInt(5))
      val maybePattern = try Some(Pattern.parse(source)) catch { case _: PatternSyntaxException => None }
      for (pattern <- maybePattern; _ <- 0 until 5) {
        val input = Array.fill(rnd.nextInt(16))(alphabet(rnd.nextInt(alphabet.length)).toByte)
        val lengths = ends(pattern.nodes, 0, input)
        for (len <- lengths) {
          assertTrue(len >= pattern.getMinLength, s"'$source' match length $len < min ${pattern.getMinLength}")
          if (pattern.getMaxLength >= 0)
            assertTrue(len <= pattern.getMaxLength, s"'$source' match length $len > max ${pattern.getMaxLength}")
        }
        // atoms must occur in every match within their offset range
        val atoms = pattern.compiled.atoms
        if (atoms.nonEmpty && pattern.matchAt(input, 0) >= 0) {
          val found = atoms.exists { a =>
            (a.offMin to a.offMax).exists(off =>
              off + a.bytes.length <= input.length && a.bytes.indices.forall(k => input(off + k) == a.bytes(k)))
          }
          assertTrue(found, s"no atom of '$source' found in ${input.mkString(",")}")
        }
        // the first byte table must allow the first byte of every match
        if (input.nonEmpty && lengths.exists(_ > 0) && !pattern.compiled.anyFirst)
          assertTrue(pattern.compiled.firstBytes(input(0) & 0xFF), s"first byte of '$source' rejected")
      }
    }
  }
}
