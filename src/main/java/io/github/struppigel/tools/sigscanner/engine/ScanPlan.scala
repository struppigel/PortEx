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
 * @param inPass true for a further clause that is searched in the same pass
 *               as the first clauses of its location; it keeps only its
 *               lowest match instead of reporting all
 */
private[sigscanner] final class SigEntry(
    val id: Int,
    val sigIndex: Int,
    val signature: Signature,
    val clause: Clause,
    val spec: LocationSpec,
    val inPass: Boolean) {

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

  /**
   * per entry: true if atom hits may yield the same start more than once, i.e.
   * the entry has several atoms or an atom with an offset range
   */
  val mayRepeatStarts: Array[Boolean] = entries.map { e =>
    val atoms = e.compiled.atoms
    atoms.length > 1 || (atoms.length == 1 && atoms(0).offMin != atoms(0).offMax)
  }

  lazy val automaton: AhoCorasick = new AhoCorasick(owners.map(_._2.bytes).toIndexedSeq)

  /** longest distance from a match start to the end of one of its atoms */
  val maxAtomReach: Long = if (owners.isEmpty) 0 else owners.map { case (_, a) => a.offMax.toLong + a.bytes.length }.max
}

/**
 * One location of a further clause: its entry and a group that searches the
 * entry alone, for scans in which the entry is not searched in a pass of the
 * first clauses.
 */
private[sigscanner] final class FurtherLocation(val entry: SigEntry, val group: Group)

/**
 * The compiled form of a signature database: the first clauses of all
 * signatures grouped by location, so that each region is read once.
 * <p>
 * Like YARA-X, a search reads a region once for many clauses: further clauses
 * that search the same location as first clauses are searched in the same
 * pass, if the first clause of their signature is searched too and they have
 * atoms. The other further clauses are checked only for signatures whose
 * first clause matched.
 */
private[sigscanner] final class ScanPlan(val database: SignatureDatabase) {

  private val logger = LogManager.getLogger(classOf[ScanPlan].getName)

  val signatures: IndexedSeq[Signature] = database.signatures

  private val entries = ArrayBuffer[SigEntry]()

  private def entry(sigIndex: Int, clause: Clause, spec: LocationSpec, inPass: Boolean = false): SigEntry = {
    val e = new SigEntry(entries.size, sigIndex, signatures(sigIndex), clause, spec, inPass)
    entries += e
    e
  }

  private def isSearch(spec: LocationSpec): Boolean = spec.mode.isInstanceOf[Search]

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
  private val conditionOnlyBuffer = ArrayBuffer[(Int, Signature)]()
  locally {
    var i = 0
    while (i < signatures.size) {
      val sig = signatures(i)
      if (sig.clauses.isEmpty) conditionOnlyBuffer += ((i, sig))
      else {
        val first = sig.clauses.head
        for (spec <- first.locations) primaryEntries += entry(i, first, spec)
      }
      i += 1
    }
  }

  // locations that a pass of first clauses searches anyway
  private val searchedKeys: Set[GroupKey] = primaryEntries.filter(e => isSearch(e.spec)).map(e => keyOf(e.spec)).toSet

  private val inPassEntries = ArrayBuffer[SigEntry]()
  private val further = mutable.HashMap[(Int, Int), IndexedSeq[FurtherLocation]]()
  locally {
    var i = 0
    while (i < signatures.size) {
      val sig = signatures(i)
      if (sig.clauses.nonEmpty) {
        val firstIsSearched = sig.clauses.head.locations.exists(isSearch)
        for (clause <- sig.clauses.drop(1)) {
          // clauses without atoms are checked at every position, so only if the first clause matched
          val inPassClause = firstIsSearched && clause.pattern.compiled.atoms.nonEmpty
          further((i, clause.number)) = clause.locations.map { spec =>
            val e = entry(i, clause, spec, inPassClause && isSearch(spec) && searchedKeys.contains(keyOf(spec)))
            if (e.inPass) inPassEntries += e
            new FurtherLocation(e, buildGroups(Seq(e)).head)
          }.toIndexedSeq
        }
      }
      i += 1
    }
  }

  /** groups of first clauses and of the further clauses searched with them, per location kind */
  val groupsByKind: Map[LocationKind, IndexedSeq[Group]] = {
    val byKind = mutable.LinkedHashMap[LocationKind, ArrayBuffer[Group]]()
    // the further clauses join the groups of the first clauses, they create no groups
    for (g <- buildGroups(primaryEntries ++ inPassEntries)) byKind.getOrElseUpdate(g.kind, ArrayBuffer()) += g
    byKind.map { case (kind, groups) => kind -> groups.toIndexedSeq }.toMap
  }

  /** the locations of the further clauses in database order, per signature index and clause number */
  val furtherLocations: Map[(Int, Int), IndexedSeq[FurtherLocation]] = further.toMap

  /** signatures that only have conditions */
  val conditionOnly: IndexedSeq[(Int, Signature)] = conditionOnlyBuffer.toIndexedSeq

  val entryCount: Int = entries.size

  /** warnings about signatures that will be slow to scan, searches without window end only */
  val warnings: IndexedSeq[String] = {
    val result = mutable.LinkedHashSet[String]()
    // in database order, the entries of further clauses were created after all first clauses
    for (e <- entries.sortBy(e => (e.sigIndex, e.clause.number))) e.spec.mode match {
      case Search(_, until) if until < 0 && e.spec.kind != LocationKind.EOF =>
        val c = e.compiled
        val key = if (e.clause.number == 1) "pattern" else "pattern." + e.clause.number
        val what = s"${e.signature.source}: [${e.signature.name}] $key"
        val where = e.spec.source
        if (c.atoms.isEmpty)
          result += s"$what has no literal that is selective enough to search for in $where " +
            "(only wildcards, common bytes, short case insensitive text, or literals behind an open jump), " +
            "it is checked at every position, consider a search window"
        else {
          val width = c.atoms.map(a => a.offMax - a.offMin).max
          if (width >= ScanPlan.WideAtomRange)
            result += s"$what is searched in $where by a literal up to ${c.atoms.map(_.offMax).max} bytes after its " +
              s"start, every occurrence costs up to ${width + 1} checks, start the pattern with a literal or narrow the jump"
          else if (c.atomScore < ScanPlan.WeakAtomScore)
            result += s"$what is searched in $where by the short literal ${ScanPlan.describe(c.atoms(0).bytes)}, " +
              "which is frequent, use a longer literal or a search window"
        }
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

  /** offset range of an atom from which a warning says that each hit costs many checks */
  val WideAtomRange: Int = 256

  /** atom score below which a warning says that the atom is frequent, e.g. two bytes like 'MZ' */
  val WeakAtomScore: Double = 3.0

  /** bytes as 'text' if they are printable ASCII, otherwise as hex bytes */
  def describe(bytes: Array[Byte]): String =
    if (bytes.forall(b => b >= 0x20 && b < 0x7F && b != '\'' && b != '\\')) "'" + new String(bytes, "US-ASCII") + "'"
    else bytes.map(b => "%02X".format(b & 0xFF)).mkString(" ")

  /** read size for anchored patterns with open jumps */
  val UnboundedRead: Int = 4096

  /** largest number of bytes a pattern without upper bound is tried before the end of file */
  val MaxEndSpan: Int = PatternParser.MaxSpan
}
