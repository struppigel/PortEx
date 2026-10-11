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
package io.github.struppigel.tools.sigscanner.engine

import io.github.struppigel.tools.sigscanner._
import io.github.struppigel.tools.sigscanner.pattern.{Atom, CompiledPattern, PatternParser}
import org.apache.logging.log4j.LogManager

import scala.collection.mutable
import scala.collection.mutable.ArrayBuffer

/**
 * One location of one clause of a signature.
 *
 * @param id index of the entry within the plan
 * @param sigIndex index of the signature within the database
 */
private[sigscanner] final class SigEntry(
    val id: Int,
    val sigIndex: Int,
    val signature: Signature,
    val clause: Clause,
    val spec: LocationSpec) {

  val compiled: CompiledPattern = clause.pattern.compiled

  /** conditions of the signature, cheapest first */
  val conditions: IndexedSeq[Condition] =
    if (signature.conditions.isEmpty) signature.conditions else signature.conditions.sortBy(PEFacts.cost)

  /** true if a cheap check of the file can exclude the signature, see PEFacts.excludedCheaply */
  val mayBeExcludedCheaply: Boolean = conditions.nonEmpty && conditions.exists(PEFacts.isCheapExclusion)

  def excludedCheaply(facts: PEFacts): Boolean = conditions.exists(facts.excludedCheaply)
}

/** entries with the same location kind and selector that are scanned together */
private[sigscanner] sealed abstract class Group(val kind: LocationKind, val selector: Selector, val entries: Array[SigEntry]) {
  /** resolves the regions of the group */
  def spec: LocationSpec = entries(0).spec

  /** true if a cheap check may exclude all entries, so that the group can be skipped */
  val allMayBeExcludedCheaply: Boolean = entries.forall(_.mayBeExcludedCheaply)
}

/** at = loc + offset, candidates are selected by the first byte */
private[sigscanner] final class AnchoredGroup(kind: LocationKind, selector: Selector, val offset: Long, entries: Array[SigEntry])
  extends Group(kind, selector, entries) {

  val (dispatch: Array[Array[SigEntry]], anyFirst: Array[SigEntry]) = {
    val table = new Array[ArrayBuffer[SigEntry]](256)
    def add(b: Int, e: SigEntry): Unit = {
      if (table(b) == null) table(b) = new ArrayBuffer[SigEntry](4)
      table(b) += e
    }
    val any = ArrayBuffer[SigEntry]()
    var i = 0
    while (i < entries.length) {
      val e = entries(i)
      val c = e.compiled
      if (c.anyFirst) any += e
      else if (c.isFlat && c.flatMasks(0) == 0xFF.toByte) add(c.flatValues(0) & 0xFF, e)
      else {
        var b = 0
        while (b < 256) {
          if (c.firstBytes(b)) add(b, e)
          b += 1
        }
      }
      i += 1
    }
    val result = new Array[Array[SigEntry]](256)
    var b = 0
    while (b < 256) {
      result(b) = if (table(b) == null) ScanPlan.NoEntries else table(b).toArray
      b += 1
    }
    (result, any.toArray)
  }

  /** bytes to read at the anchor, the matcher reads the rest if needed */
  val maxRead: Int = {
    var max = 0
    for (e <- entries) max = math.max(max, if (e.compiled.maxLength >= 0) e.compiled.maxLength else ScanPlan.UnboundedRead)
    max
  }
}

/** at = eof, the match must end at the end of the file */
private[sigscanner] final class EndAnchoredGroup(entries: Array[SigEntry])
  extends Group(LocationKind.EOF, AllSelector, entries)

/** in = loc[window], candidates are found with an Aho-Corasick search for atoms */
private[sigscanner] final class SearchGroup(kind: LocationKind, selector: Selector, entries: Array[SigEntry])
  extends Group(kind, selector, entries) {

  /** entries without atom, checked at every position with a fitting first byte */
  val bruteForce: Array[SigEntry] = entries.filter(_.compiled.atoms.isEmpty)

  /** owner entry and atom of each automaton key */
  val owners: Array[(SigEntry, Atom)] =
    entries.filter(_.compiled.atoms.nonEmpty).flatMap(e => e.compiled.atoms.map(a => (e, a)))

  private val localIndex: Map[Int, Int] = entries.map(_.id).zipWithIndex.toMap

  /** index within entries of the owner of each automaton key */
  val ownerLocal: Array[Int] = owners.map { case (e, _) => localIndex(e.id) }

  /** indices within entries of the brute force entries */
  val bruteLocal: Array[Int] = bruteForce.map(e => localIndex(e.id))

  lazy val automaton: AhoCorasick = new AhoCorasick(owners.map(_._2.bytes).toIndexedSeq)

  /** longest distance from a match start to the end of one of its atoms */
  val maxAtomReach: Long = if (owners.isEmpty) 0 else owners.map { case (_, a) => a.offMax.toLong + a.bytes.length }.max
}

/**
 * The compiled form of a signature database: the first clauses of all
 * signatures grouped by location, so that each region is read once.
 */
private[sigscanner] final class ScanPlan(val database: SignatureDatabase) {

  private val logger = LogManager.getLogger(classOf[ScanPlan].getName)

  val signatures: IndexedSeq[Signature] = database.signatures

  private val entries = ArrayBuffer[SigEntry]()

  private def entry(sigIndex: Int, clause: Clause, spec: LocationSpec): SigEntry = {
    val e = new SigEntry(entries.size, sigIndex, signatures(sigIndex), clause, spec)
    entries += e
    e
  }

  private sealed trait GroupKey
  private case class AnchorKey(kind: LocationKind, selector: Selector, offset: Long) extends GroupKey
  private case object EndKey extends GroupKey
  private case class SearchKey(kind: LocationKind, selector: Selector) extends GroupKey

  private def keyOf(spec: LocationSpec): GroupKey = spec.mode match {
    case Anchored(offset) => AnchorKey(spec.kind, spec.selector, offset)
    case EndAnchored => EndKey
    case Search(_, _) => SearchKey(spec.kind, spec.selector)
  }

  private def buildGroups(list: Seq[SigEntry]): IndexedSeq[Group] = {
    val grouped = mutable.LinkedHashMap[GroupKey, ArrayBuffer[SigEntry]]()
    for (e <- list) grouped.getOrElseUpdate(keyOf(e.spec), ArrayBuffer()) += e
    grouped.toIndexedSeq.map {
      case (AnchorKey(kind, selector, offset), es) => new AnchoredGroup(kind, selector, offset, es.toArray)
      case (EndKey, es) => new EndAnchoredGroup(es.toArray)
      case (SearchKey(kind, selector), es) => new SearchGroup(kind, selector, es.toArray)
    }
  }

  // plain loops, the plan is built while the first file waits for its scan
  private val primaryEntries = ArrayBuffer[SigEntry]()
  private val secondary = mutable.HashMap[(Int, Int), IndexedSeq[Group]]()
  private val conditionOnlyBuffer = ArrayBuffer[(Int, Signature)]()
  locally {
    var i = 0
    while (i < signatures.size) {
      val sig = signatures(i)
      if (sig.clauses.isEmpty) conditionOnlyBuffer += ((i, sig))
      else {
        val first = sig.clauses.head
        for (spec <- first.locations) primaryEntries += entry(i, first, spec)
        for (clause <- sig.clauses.drop(1)) {
          val groups = ArrayBuffer[Group]()
          for (spec <- clause.locations) groups ++= buildGroups(Seq(entry(i, clause, spec)))
          secondary((i, clause.number)) = groups.toIndexedSeq
        }
      }
      i += 1
    }
  }

  /** groups of first clauses per location kind */
  val groupsByKind: Map[LocationKind, IndexedSeq[Group]] = {
    val byKind = mutable.LinkedHashMap[LocationKind, ArrayBuffer[Group]]()
    for (g <- buildGroups(primaryEntries)) byKind.getOrElseUpdate(g.kind, ArrayBuffer()) += g
    byKind.map { case (kind, groups) => kind -> groups.toIndexedSeq }.toMap
  }

  /** groups of the further clauses, per signature index and clause number */
  val secondaryGroups: Map[(Int, Int), IndexedSeq[Group]] = secondary.toMap

  /** signatures that only have conditions */
  val conditionOnly: IndexedSeq[(Int, Signature)] = conditionOnlyBuffer.toIndexedSeq

  val entryCount: Int = entries.size

  /** warnings about signatures that will be slow to scan */
  val warnings: IndexedSeq[String] = {
    val result = mutable.LinkedHashSet[String]()
    for (e <- entries) e.spec.mode match {
      case Search(_, until) if until < 0 && e.spec.kind != LocationKind.EOF && e.compiled.atoms.isEmpty =>
        result += s"${e.signature.source}: [${e.signature.name}] has no literal of at least two bytes to search for " +
          s"in ${e.spec.source}, it is checked at every position, consider a search window"
      case _ =>
    }
    result.toIndexedSeq
  }
  warnings.foreach(w => logger.debug(w))

  /** signatures that exceeded the step budget, to warn only once */
  private[engine] val budgetWarnings: java.util.Set[Int] = java.util.concurrent.ConcurrentHashMap.newKeySet[Int]()
}

private[sigscanner] object ScanPlan {
  val NoEntries: Array[SigEntry] = Array.empty


  /** read size for anchored patterns with open jumps */
  val UnboundedRead: Int = 4096

  /** largest number of bytes a pattern without upper bound is tried before the end of file */
  val MaxEndSpan: Int = PatternParser.MaxSpan
}
