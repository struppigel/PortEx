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

import scala.collection.mutable.ArrayBuffer

/**
 * Linked matcher program. Every node continues with next, null means the
 * pattern is complete. Branches of an MAlt link to the continuation of the
 * group, so that failing continuations backtrack into the next branch.
 */
private[sigscanner] sealed abstract class MNode {
  var next: MNode = _
}

private[sigscanner] final class MBytes(val values: Array[Byte], val masks: Array[Byte]) extends MNode {
  val length: Int = values.length
}

private[sigscanner] final class MClass(val cls: ByteClass) extends MNode

/** max is PJump.Unbounded for open ranges */
private[sigscanner] final class MJump(val min: Int, val max: Int) extends MNode

private[sigscanner] final class MAlt(val branches: Array[MNode]) extends MNode

private[sigscanner] final class MFollow(val absolute: Boolean, val size: Int) extends MNode

/**
 * A literal byte sequence that occurs in every match of a pattern. The
 * sequence starts between offMin and offMax bytes after the start of the match.
 */
private[sigscanner] final class Atom(val bytes: Array[Byte], val offMin: Int, val offMax: Int) {
  override def toString: String =
    bytes.map("%02X".format(_)).mkString(" ") + s" @[$offMin-$offMax]"
}

/**
 * Result of the pattern compilation.
 *
 * @param flatValues values of a pattern that is only a byte sequence, null otherwise
 * @param flatMasks masks of a pattern that is only a byte sequence, null otherwise
 * @param program head of the matcher program
 * @param minLength minimum number of bytes a match occupies before the first follow token
 * @param maxLength maximum number of bytes a match occupies before the first
 *                  follow token, -1 if unknown or unbounded
 * @param hasFollow true if the pattern contains follow tokens ($$ or ##)
 * @param firstBytes possible values of the first byte
 * @param anyFirst true if the first byte may have any value
 * @param nodes the syntax tree, used to compute the atoms on first use
 */
private[sigscanner] final class CompiledPattern(
    val flatValues: Array[Byte],
    val flatMasks: Array[Byte],
    val program: MNode,
    val minLength: Int,
    val maxLength: Int,
    val hasFollow: Boolean,
    val firstBytes: Array[Boolean],
    val anyFirst: Boolean,
    nodes: Vector[PNode]) {

  // only searches need atoms, so they are computed on first use
  private lazy val atomSet = PatternCompiler.bestAtoms(nodes)

  /**
   * literal sequences of which at least one occurs in every match, empty if the
   * pattern has no usable atom
   */
  lazy val atoms: Array[Atom] = atomSet.map(_.atoms.toArray).getOrElse(Array.empty)

  /** quality of the atoms, higher is more selective */
  lazy val atomScore: Double = atomSet.map(_.score).getOrElse(0.0)

  def isFlat: Boolean = flatValues != null

  /** number of positions that require a specific byte value, used to rank patterns */
  lazy val exactBytes: Int = if (isFlat) flatMasks.count(_ == 0xFF.toByte) else 0
}

private[sigscanner] object PatternCompiler {

  /** sentinel for unknown or unbounded lengths */
  val Unknown: Int = -1

  /** longest atom that is extracted */
  val AtomMaxLength = 8

  /** case insensitive letters per atom, each doubles the number of atom variants */
  val AtomMaxCaseFolds = 4

  /** atoms below this score are not selective enough for the atom search */
  val MinAtomScore = 2.0

  private val Log256 = math.log(256)

  def compile(nodes: Vector[PNode]): CompiledPattern = {
    if (nodes.length == 1 && nodes(0).isInstanceOf[PBytes]) compileFlat(nodes)
    else compileGeneral(nodes)
  }

  /** direct path for byte sequences, the most common patterns */
  private def compileFlat(nodes: Vector[PNode]): CompiledPattern = {
    val bytes = nodes(0).asInstanceOf[PBytes]
    val program = new MBytes(bytes.values, bytes.masks)
    val first = new Array[Boolean](256)
    val value = bytes.values(0) & 0xFF
    val mask = bytes.masks(0) & 0xFF
    val anyFirst = mask == 0
    if (anyFirst) java.util.Arrays.fill(first, true)
    else if (mask == 0xFF) first(value) = true
    else {
      var b = 0
      while (b < 256) {
        if ((b & mask) == value) first(b) = true
        b += 1
      }
    }
    new CompiledPattern(bytes.values, bytes.masks, program, bytes.length, bytes.length, false, first, anyFirst, nodes)
  }

  private def compileGeneral(nodes: Vector[PNode]): CompiledPattern = {
    val program = link(nodes, null)
    val (flatValues, flatMasks) = (null, null)
    val bounds = segmentBounds(nodes)
    val first = new Array[Boolean](256)
    val anyFirst = !addFirstBytes(nodes, first)
    if (anyFirst) java.util.Arrays.fill(first, true)
    new CompiledPattern(flatValues, flatMasks, program, bounds.min,
      if (bounds.max >= 0) bounds.max else Unknown, hasFollow(nodes), first, anyFirst, nodes)
  }

  private def hasFollow(nodes: Seq[PNode]): Boolean = nodes.exists {
    case PFollow(_, _) => true
    case PAlt(branches) => branches.exists(hasFollow)
    case _ => false
  }

  /** builds the matcher program for nodes followed by continuation */
  private def link(nodes: Seq[PNode], continuation: MNode): MNode = {
    var cur = continuation
    for (node <- nodes.reverseIterator) {
      val m: MNode = node match {
        case PBytes(v, mk) => new MBytes(v, mk)
        case PClass(c) => new MClass(c)
        case PJump(min, max) => new MJump(min, max)
        case PFollow(abs, size) => new MFollow(abs, size)
        case PAlt(branches) => new MAlt(branches.map(b => link(b, cur)).toArray)
      }
      m.next = cur
      cur = m
    }
    cur
  }

  /**
   * Bounds of the number of bytes a match occupies from its start up to and
   * including the first follow token. max is negative if unknown.
   */
  private case class Bounds(min: Int, max: Int, followSeen: Boolean)

  private def add(a: Int, b: Int): Int = if (a < 0 || b < 0) -1 else a + b

  private def segmentBounds(nodes: Seq[PNode]): Bounds = {
    var min = 0
    var max = 0
    for (node <- nodes) {
      node match {
        case PBytes(v, _) => min += v.length; max = add(max, v.length)
        case PClass(_) => min += 1; max = add(max, 1)
        case PJump(a, b) => min += a; max = if (b == PJump.Unbounded) -1 else add(max, b)
        case PFollow(_, size) => return Bounds(min + size, add(max, size), followSeen = true)
        case PAlt(branches) =>
          val bs = branches.map(segmentBounds)
          min += bs.map(_.min).min
          max = if (bs.exists(_.max < 0)) -1 else add(max, bs.map(_.max).max)
          // what follows a branch with a follow token is elsewhere in the file
          if (bs.exists(_.followSeen)) return Bounds(min, -1, followSeen = true)
      }
    }
    Bounds(min, max, followSeen = false)
  }

  /**
   * Adds the possible first bytes of the sequence to the table.
   *
   * @return false if any byte value is possible
   */
  private def addFirstBytes(nodes: Seq[PNode], table: Array[Boolean]): Boolean = {
    nodes.headOption match {
      case None => false // empty branch, the continuation decides
      case Some(PBytes(v, m)) =>
        val value = v(0) & 0xFF
        val mask = m(0) & 0xFF
        if (mask == 0) false
        else if (mask == 0xFF) {
          table(value) = true
          true
        } else {
          for (b <- 0 until 256 if (b & mask) == value) table(b) = true
          true
        }
      case Some(PClass(c)) =>
        for (b <- 0 until 256 if c.contains(b)) table(b) = true
        true
      case Some(PAlt(branches)) => branches.forall(b => addFirstBytes(b, table))
      case _ => false // jumps and follow tokens
    }
  }

  /** a set of atoms of which one occurs in every match */
  private[pattern] case class AtomSet(atoms: Vector[Atom], score: Double) {
    def width: Int = atoms.map(a => a.offMax - a.offMin).max

    def shift(min: Int, max: Int): AtomSet =
      AtomSet(atoms.map(a => new Atom(a.bytes, a.offMin + min, a.offMax + max)), score)

    def usable: Boolean = score >= MinAtomScore

    /**
     * The score minus the cost of checking every start in the offset range of
     * an atom hit: an atom behind a jump of 255 bytes is worth one byte less.
     * So atoms before wide jumps are preferred, unless the atom behind is much
     * more selective.
     */
    def effectiveScore: Double = score - math.log(width + 1.0) / Log256

    def betterThan(other: AtomSet): Boolean =
      if (score != other.score) score > other.score
      else if (width != other.width) width < other.width
      else atoms.map(_.offMin).min < other.atoms.map(_.offMin).min

    /** like betterThan, but usable sets and narrow offset ranges first, see effectiveScore */
    def betterNarrow(other: AtomSet): Boolean =
      if (usable != other.usable) usable
      else if (effectiveScore != other.effectiveScore) effectiveScore > other.effectiveScore
      else betterThan(other)
  }

  private def isCommon(b: Int): Boolean = b == 0x00 || b == 0xFF || b == 0x90 || b == 0xCC

  private def byteScore(value: Int, mask: Int): Double =
    if (mask == 0xDF) 0.9 else if (isCommon(value)) 0.25 else 1.0

  /**
   * The atoms that are searched for the pattern. Atoms with a narrow offset
   * range are preferred; if that yields no usable atoms, the atoms are chosen
   * as by former versions, so that no pattern is checked at every position
   * because of the preference.
   */
  private[pattern] def bestAtoms(nodes: Seq[PNode]): Option[AtomSet] =
    atomsOf(nodes, narrow = true).filter(_.usable).orElse(atomsOf(nodes, narrow = false).filter(_.usable))

  /**
   * Determines the best atom set of the sequence, with offsets relative to the
   * start of the sequence. Stops at follow tokens and unbounded jumps.
   *
   * @param narrow if true, prefer atoms with narrow offset ranges and score
   *               alternatives by their expected number of hits
   */
  private def atomsOf(nodes: Seq[PNode], narrow: Boolean): Option[AtomSet] = {
    var best: Option[AtomSet] = None
    def consider(candidate: Option[AtomSet]): Unit = candidate.foreach { c =>
      if (best.forall(b => if (narrow) c.betterNarrow(b) else c.betterThan(b))) best = Some(c)
    }
    var offMin = 0
    var offMax = 0
    val it = nodes.iterator
    var stop = false
    while (it.hasNext && !stop) {
      it.next() match {
        case PBytes(v, m) =>
          consider(windowAtoms(v, m).map(_.shift(offMin, offMax)))
          offMin += v.length
          offMax += v.length
        case PClass(_) =>
          offMin += 1
          offMax += 1
        case PJump(a, b) =>
          if (b == PJump.Unbounded) stop = true
          else {
            offMin += a
            offMax += b
          }
        case PFollow(_, _) => stop = true
        case PAlt(branches) =>
          val sets = branches.map(atomsOf(_, narrow))
          if (sets.forall(_.isDefined)) {
            val all = sets.flatten
            // every additional atom adds work for the search
            val score =
              if (narrow) {
                // the score of a single atom with as many expected hits as all atoms together, an atom of score s
                // hits about every 256^s bytes; case variants of letters do not make letters-only strings unusable
                -math.log(all.map(s => s.atoms.size * math.pow(256, -s.score)).sum) / Log256
              } else all.map(_.score).min - 0.1 * (all.map(_.atoms.size).sum - 1)
            consider(Some(AtomSet(all.flatMap(_.atoms), score).shift(offMin, offMax)))
          }
          val bs = branches.map(segmentBounds)
          if (bs.exists(b => b.followSeen || b.max < 0)) stop = true
          else {
            offMin += bs.map(_.min).min
            offMax += bs.map(_.max).max
          }
      }
    }
    best
  }

  /** best window of literal or case insensitive bytes within a byte sequence */
  private def windowAtoms(values: Array[Byte], masks: Array[Byte]): Option[AtomSet] = {
    def usable(i: Int): Boolean = {
      val m = masks(i) & 0xFF
      m == 0xFF || m == 0xDF
    }
    var best: Option[AtomSet] = None
    var start = 0
    while (start < values.length) {
      if (usable(start)) {
        var end = start
        var folds = 0
        var score = 0.0
        while (end < values.length && end - start < AtomMaxLength && usable(end) &&
          (folds < AtomMaxCaseFolds || (masks(end) & 0xFF) != 0xDF)) {
          if ((masks(end) & 0xFF) == 0xDF) folds += 1
          score += byteScore(values(end) & 0xFF, masks(end) & 0xFF)
          end += 1
        }
        val candidate = AtomSet(caseVariants(values, masks, start, end).map(new Atom(_, start, start)), score)
        if (best.forall(candidate.betterThan)) best = Some(candidate)
      }
      start += 1
    }
    best
  }

  /** all byte sequences a window with case insensitive letters matches */
  private def caseVariants(values: Array[Byte], masks: Array[Byte], start: Int, end: Int): Vector[Array[Byte]] = {
    var variants = Vector(new ArrayBuffer[Byte]())
    for (i <- start until end) {
      val v = values(i)
      if ((masks(i) & 0xFF) == 0xDF) {
        variants = variants.flatMap { prefix =>
          Vector(prefix.clone() += v, prefix.clone() += (v | 0x20).toByte)
        }
      } else variants.foreach(_ += v)
    }
    variants.map(_.toArray)
  }
}
