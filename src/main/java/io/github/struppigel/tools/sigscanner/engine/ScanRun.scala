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

import io.github.struppigel.parser.Interruption
import io.github.struppigel.tools.sigscanner._
import io.github.struppigel.tools.sigscanner.pattern.{ByteSource, PatternMatcher}
import org.apache.logging.log4j.LogManager

import scala.collection.mutable
import scala.collection.mutable.ArrayBuffer

/**
 * Scans one file with a plan. Not thread-safe, create one run per scan.
 */
private[sigscanner] final class ScanRun(
    plan: ScanPlan,
    options: ScanOptions,
    source: ByteSource,
    resolver: RegionResolver,
    facts: PEFacts) {

  import ScanRun.logger

  private val matcher = new PatternMatcher(source, resolver.addressMapper, options.stepBudget)
  private val counts = new Array[Int](plan.signatures.size)
  private val results = ArrayBuffer[(Int, SignatureMatch)]()
  private val seen = mutable.HashSet[(Int, Long, LocationKind)]()
  private val conditionResults = mutable.HashMap[(Int, Boolean), Boolean]()
  private val secondaryResults = mutable.HashMap[(Int, Int), Option[ClauseMatch]]()

  // per entry id: the lowest match of a further clause that was searched in a pass of first clauses
  private val inPassMatches = new Array[ClauseMatch](plan.entryCount)
  // per entry id: true if the entry was searched in a pass of first clauses, so inPassMatches is its result
  private val inPassSearched = new Array[Boolean](plan.entryCount)

  /** number of region passes of search groups, for tests */
  private[sigscanner] var searchPasses = 0

  // per signature: 0 not checked yet, 1 excluded by a cheap condition check, 2 not excluded
  private val exclusion = new Array[Byte](plan.signatures.size)

  /** true if the entry may still produce matches, checked only for candidates */
  private def isActive(e: SigEntry): Boolean =
    counts(e.sigIndex) < options.maxMatchesPerSignature && (!e.mayBeExcludedCheaply || {
      if (exclusion(e.sigIndex) == 0) exclusion(e.sigIndex) = if (e.excludedCheaply(facts)) 1 else 2
      exclusion(e.sigIndex) == 2
    })

  /** scans the location kinds and returns the matches in a deterministic order */
  def run(kinds: Set[LocationKind]): IndexedSeq[SignatureMatch] = {
    // first clause matches of all groups, confirmed after all passes, when the further clauses searched in them are known
    val pending = ArrayBuffer[(SigEntry, ClauseMatch)]()
    for (kind <- LocationKind.values() if kinds.contains(kind)) {
      if (kind == LocationKind.METADATA) matchConditionOnly()
      else for (group <- plan.groupsByKind.getOrElse(kind, IndexedSeq.empty)) {
        Interruption.checkInterrupt()
        // skips groups like the .NET protectors in executable sections of native files without resolving them
        val anyActive = !group.allMayBeExcludedCheaply || group.entries.exists(isActive)
        if (anyActive) {
          scanGroup(group, furtherOnly = false) { (e, m) => pending += ((e, m)) }
          for (e <- group.entries if e.inPass && isActive(e)) inPassSearched(e.id) = true
        }
      }
    }
    pending.foreach { case (e, m) => confirm(e, m) }
    results.sortBy { case (idx, m) => (m.getLocationKind.ordinal, m.getRegionStart, m.getOffset, idx) }.map(_._2).toIndexedSeq
  }

  /**
   * @param furtherOnly true if the group checks a further clause, which only needs its first match
   */
  private def scanGroup(group: Group, furtherOnly: Boolean)(emit: (SigEntry, ClauseMatch) => Unit): Unit = {
    val regions = resolver.resolve(group.spec).sortBy(_.start)
    group match {
      case g: AnchoredGroup => scanAnchored(g, regions, furtherOnly, emit)
      case g: EndAnchoredGroup => scanEnd(g, regions, furtherOnly, emit)
      case g: SearchGroup => scanSearch(g, regions, furtherOnly, emit)
    }
  }

  private def warnBudget(e: SigEntry): Unit =
    if (matcher.budgetExceeded && plan.budgetWarnings.add(e.sigIndex))
      logger.warn(s"${e.signature.source}: [${e.signature.name}] exceeded the backtracking limit, matches may be missing")

  private def scanAnchored(g: AnchoredGroup, regions: IndexedSeq[Region], firstOnly: Boolean,
      emit: (SigEntry, ClauseMatch) => Unit): Unit = {
    var found = false
    var n = 0
    for (r0 <- regions if !(firstOnly && found)) {
      n += 1
      if ((n & 0xFF) == 0) Interruption.checkInterrupt()
      // eof - N anchors at N bytes before the end of the file
      val r = if (g.kind == LocationKind.EOF) Region(LocationKind.EOF, "eof", r0.end - g.offset, r0.end) else r0
      val anchor = if (g.kind == LocationKind.EOF) r.start else r.start + g.offset
      if (anchor >= r.start && anchor < r.end && anchor >= 0) {
        // read ahead only helps if there are more regions, e.g. resources
        source.load(anchor, math.min(g.maxRead.toLong, r.end - anchor).toInt,
          if (regions.size > 1) FileWindowReader.MinRead else 0)
        val b = source.byteAt(anchor)
        if (b >= 0) {
          def tryEntries(candidates: Array[SigEntry]): Unit = {
            var i = 0
            while (i < candidates.length && !(firstOnly && found)) {
              val e = candidates(i)
              if (isActive(e)) {
                val end = matcher.matchAt(e.compiled, anchor, r.end)
                if (end >= 0) {
                  emit(e, new ClauseMatch(e.clause, e.spec, r, anchor, (matcher.lastSegmentEnd - anchor).toInt))
                  found = true
                } else warnBudget(e)
              }
              i += 1
            }
          }
          tryEntries(g.dispatch(b))
          tryEntries(g.anyFirst)
        }
      }
    }
  }

  private def scanEnd(g: EndAnchoredGroup, regions: IndexedSeq[Region], firstOnly: Boolean,
      emit: (SigEntry, ClauseMatch) => Unit): Unit = {
    for (r <- regions; e <- g.entries if isActive(e)) {
      val maxLen = if (e.compiled.maxLength >= 0) e.compiled.maxLength.toLong else ScanPlan.MaxEndSpan.toLong
      val first = math.max(r.start, r.end - maxLen)
      val last = r.end - e.compiled.minLength
      source.load(first, (r.end - first).toInt, FileWindowReader.MinRead)
      var s = first
      var done = false
      while (s <= last && !done) {
        if (matcher.matchAt(e.compiled, s, r.end, r.end) >= 0) {
          emit(e, new ClauseMatch(e.clause, e.spec, Region(LocationKind.EOF, "eof", s, r.end), s, (r.end - s).toInt))
          done = true
        } else warnBudget(e)
        s += 1
      }
    }
  }

  /**
   * Searches the regions for the entries of the group. First clauses report
   * all matches. Further clauses need only one match: the one with the lowest
   * start in the first region that has a match. Those searched in a pass of
   * first clauses are recorded in inPassMatches; if furtherOnly, all entries
   * are further clauses and their match is reported.
   */
  private def scanSearch(g: SearchGroup, regions: IndexedSeq[Region], furtherOnly: Boolean,
      emit: (SigEntry, ClauseMatch) => Unit): Unit = {
    val entries = g.entries
    val winStart = new Array[Long](entries.length)
    val winEnd = new Array[Long](entries.length)
    val ownerLocal = g.ownerLocal
    val bruteLocal = g.bruteLocal
    // per entry: the lowest match in the current region of a further clause, and true after a region with a match
    val lowest = new Array[ClauseMatch](entries.length)
    val done = new Array[Boolean](entries.length)
    var doneCount = 0

    def keepsLowest(local: Int): Boolean = furtherOnly || entries(local).inPass

    // true if no start before the end of the window can be found after pos
    def settled(local: Int, pos: Long): Boolean =
      winEnd(local) <= winStart(local) || (lowest(local) != null && pos > winEnd(local) + g.maxAtomReach)

    var ri = 0
    while (ri < regions.size && !(furtherOnly && doneCount == entries.length)) {
      Interruption.checkInterrupt()
      val r = regions(ri)
      ri += 1
      var scanStart = Long.MaxValue
      var scanEnd = Long.MinValue
      var anyWindow = false
      var i = 0
      while (i < entries.length) {
        val e = entries(i)
        val (ws, we) = e.spec.mode match {
          case Search(from, _) if g.kind == LocationKind.EOF => (math.max(r.start, r.end - from), r.end)
          case Search(from, until) => (r.start + from, if (until < 0) r.end else math.min(r.end, r.start + until))
          case _ => (0L, 0L)
        }
        // the match must end within the region
        val we2 = math.min(we, r.end - e.compiled.minLength + 1)
        winStart(i) = ws
        winEnd(i) = if (!done(i) && isActive(e)) we2 else ws
        if (winStart(i) < winEnd(i)) {
          anyWindow = true
          scanStart = math.min(scanStart, ws)
          val reach = if (e.compiled.atoms.isEmpty) we2 else math.min(r.end, we2 + g.maxAtomReach)
          scanEnd = math.max(scanEnd, reach)
        }
        i += 1
      }
      if (anyWindow) {
        searchPasses += 1
        // starts that were checked already, for entries whose atom hits may repeat a start
        val tried = new LongHashSet()
        val entryCount = entries.length.toLong
        def verify(local: Int, start: Long): Unit = {
          // further clauses after a match only look for lower starts
          if (start >= winEnd(local)) return
          val e = entries(local)
          if (counts(e.sigIndex) >= options.maxMatchesPerSignature) return
          if (g.mayRepeatStarts(local) && !tried.add(start * entryCount + local)) return
          val end = matcher.matchAt(e.compiled, start, r.end)
          if (end >= 0) {
            // report the searched end of the file as region of eof matches
            val region = if (g.kind == LocationKind.EOF) Region(LocationKind.EOF, "eof", winStart(local), r.end) else r
            val m = new ClauseMatch(e.clause, e.spec, region, start, (matcher.lastSegmentEnd - start).toInt)
            if (keepsLowest(local)) {
              lowest(local) = m
              winEnd(local) = start
            } else emit(e, m)
          } else warnBudget(e)
        }
        val hasAtoms = g.owners.nonEmpty && ownerLocal.exists(l => winStart(l) < winEnd(l))
        val automaton = if (hasAtoms) g.automaton else null
        var state = 0
        var pos = scanStart
        while (pos < scanEnd && !(furtherOnly && entries.indices.forall(settled(_, pos)))) {
          Interruption.checkInterrupt()
          val len = math.min(options.chunkSize.toLong, scanEnd - pos).toInt
          // no read ahead, small windows like overlay[0-0x100] read only what they need
          source.load(pos, len, len)
          val buf = source.buffer
          val bufStart = source.bufferStart
          val off = (pos - bufStart).toInt
          if (automaton != null) {
            state = automaton.feed(state, buf, off, off + len) { (key, idx) =>
              val local = ownerLocal(key)
              if (winStart(local) < winEnd(local)) {
                val atom = g.owners(key)._2
                val hitStart = bufStart + idx - atom.bytes.length + 1
                val from = math.max(winStart(local), hitStart - atom.offMax)
                val until = math.min(winEnd(local) - 1, hitStart - atom.offMin)
                if (from == until) verify(local, from)
                else if (from < until) {
                  // an atom behind a jump: only starts with a possible first byte
                  val compiled = entries(local).compiled
                  val first = compiled.firstBytes
                  var s = from
                  while (s <= until) {
                    if (compiled.anyFirst) verify(local, s)
                    else {
                      val b = source.byteAt(s)
                      if (b >= 0 && first(b)) verify(local, s)
                    }
                    s += 1
                  }
                }
              }
            }
          }
          var b = 0
          while (b < bruteLocal.length) {
            val local = bruteLocal(b)
            val first = entries(local).compiled.firstBytes
            var p = math.max(pos, winStart(local))
            val end = math.min(pos + len, winEnd(local))
            var count = 0
            while (p < end) {
              if (first(buf((p - bufStart).toInt) & 0xFF)) verify(local, p)
              p += 1
              count += 1
              if ((count & 0xFFFF) == 0) Interruption.checkInterrupt()
            }
            b += 1
          }
          pos += len
        }
      }
      // the region decides the match of further clauses that matched in it
      i = 0
      while (i < entries.length) {
        if (lowest(i) != null) {
          if (furtherOnly) emit(entries(i), lowest(i)) else inPassMatches(entries(i).id) = lowest(i)
          lowest(i) = null
          done(i) = true
          doneCount += 1
        }
        i += 1
      }
    }
  }

  private def conditionsHold(e: SigEntry, cheap: Boolean): Boolean =
    conditionResults.getOrElseUpdate((e.sigIndex, cheap),
      e.conditions.filter(c => (PEFacts.cost(c) <= 2) == cheap).forall(facts.holds))

  /**
   * The match of a further clause, cached per run: the match of its first
   * location in database order that has one.
   */
  private def findClause(sigIndex: Int, clause: Clause): Option[ClauseMatch] =
    secondaryResults.getOrElseUpdate((sigIndex, clause.number), {
      var result: Option[ClauseMatch] = None
      val locations = plan.furtherLocations.getOrElse((sigIndex, clause.number), IndexedSeq.empty)
      var i = 0
      while (result.isEmpty && i < locations.size) {
        val location = locations(i)
        val e = location.entry
        if (e.inPass && inPassSearched(e.id)) result = Option(inPassMatches(e.id))
        else scanGroup(location.group, furtherOnly = true) { (_, m) => if (result.isEmpty) result = Some(m) }
        i += 1
      }
      result
    })

  /** checks conditions and further clauses of a first clause match */
  private def confirm(e: SigEntry, m: ClauseMatch): Unit = {
    val idx = e.sigIndex
    if (counts(idx) >= options.maxMatchesPerSignature) return
    val key = (idx, m.offset, m.region.kind)
    if (seen.contains(key)) return
    if (!conditionsHold(e, cheap = true)) return
    val clauses = e.signature.clauses
    val further = new Array[ClauseMatch](clauses.size - 1)
    var i = 1
    while (i < clauses.size) {
      // the remaining clauses are not needed if one is missing
      findClause(idx, clauses(i)) match {
        case Some(c) => further(i - 1) = c
        case None => return
      }
      i += 1
    }
    if (!conditionsHold(e, cheap = false)) return
    seen += key
    counts(idx) += 1
    results += ((idx, new SignatureMatch(e.signature, m +: further.toIndexedSeq)))
  }

  private def matchConditionOnly(): Unit = {
    for ((idx, sig) <- plan.conditionOnly) {
      Interruption.checkInterrupt()
      if (sig.conditions.sortBy(PEFacts.cost).forall(c => !facts.excludedCheaply(c) && facts.holds(c))) {
        counts(idx) += 1
        results += ((idx, new SignatureMatch(sig, IndexedSeq.empty)))
      }
    }
  }
}

private[sigscanner] object ScanRun {
  private val logger = LogManager.getLogger(classOf[ScanRun].getName)
}
