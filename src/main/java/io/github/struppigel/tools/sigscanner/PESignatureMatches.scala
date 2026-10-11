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
package io.github.struppigel.tools.sigscanner

import io.github.struppigel.parser.PEData

import scala.collection.JavaConverters._
import scala.collection.mutable

/**
 * The matches of the default signatures for one PE file, used by PEData.
 * Each location kind is scanned on first request and cached.
 *
 * @param pe the PE file
 */
final class PESignatureMatches(pe: PEData) {

  private val cache = mutable.Map[LocationKind, IndexedSeq[SignatureMatch]]()

  /**
   * The matches in the given location kinds, ordered by location kind,
   * region, offset and database order.
   */
  def _getMatches(kinds: Set[LocationKind]): IndexedSeq[SignatureMatch] = synchronized {
    val missing = kinds.filterNot(cache.contains)
    if (missing.nonEmpty) {
      val found = DefaultSignatures.peScanner._scan(pe, missing)
      // stored after the scan of all kinds succeeded, an interrupted scan leaves no partial results
      for (kind <- missing) cache(kind) = found.filter(_.getLocationKind == kind)
    }
    LocationKind.values().toIndexedSeq.filter(kinds.contains).flatMap(cache(_))
  }

  /** the matches in the given location kinds */
  def getMatches(kinds: Array[LocationKind]): java.util.List[SignatureMatch] = _getMatches(kinds.toSet).asJava

  /** the matches in all locations except FILE, see LocationKind.peDefaults */
  def getDefaultMatches: java.util.List[SignatureMatch] = _getMatches(LocationKind.peDefaults().asScala.toSet).asJava
}
