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
package io.github.struppigel.tools.sigscanner.perf

import io.github.struppigel.tools.sigscanner.engine.SearchGroup
import io.github.struppigel.tools.sigscanner.legacy.{LegacyScans, LegacySignatureScanner}
import io.github.struppigel.tools.sigscanner.{DefaultSignatures, LocationKind, SignatureDatabase, SignatureScanner}

/**
 * Measures the time from the start of a fresh JVM until all signature
 * databases are loaded and compiled. Started in a separate process by the
 * performance test.
 * <p>
 * Usage: ColdLoadProbe legacy|new|new-all [PE file], prints the nanoseconds.
 * With a PE file, the file is parsed before the time starts. The modes
 * legacy-e2e and new-e2e get the PE signatures of PortEx 5 for the PE file,
 * new-all-e2e all PEData signatures, including the Detect It Easy signatures.
 */
object ColdLoadProbe {

  def loadLegacy(): Int = {
    val scanners = List(
      new LegacySignatureScanner(LegacySignatureScanner.loadDefaultSigs()),
      new LegacySignatureScanner(LegacySignatureScanner.loadOverlaySigs()),
      new LegacySignatureScanner(LegacySignatureScanner.loadFileTypeSigs()),
      new LegacySignatureScanner(LegacySignatureScanner.loadJavaWrapperSigs()))
    scanners.map(_.prebuild()).size
  }

  /** builds everything the first scans need, including the search automata */
  def compile(scanners: List[SignatureScanner]): Int = {
    for (s <- scanners; group <- s.plan.groupsByKind.values.flatten) group match {
      case g: SearchGroup if g.owners.nonEmpty => g.automaton
      case _ =>
    }
    scanners.size
  }

  /** the PE signatures converted from the databases of PortEx 5, without the Detect It Easy signatures */
  lazy val portex5Scanner: SignatureScanner = new SignatureScanner(SignatureDatabase.merge(
    DefaultSignatures.packers, DefaultSignatures.installers, DefaultSignatures.fileTypes))

  /** the databases of PortEx 5 */
  def loadNew(): Int = compile(List(portex5Scanner, DefaultSignatures.fileTypeScanner,
    DefaultSignatures.javaWrapperScanner))

  /** all bundled databases, including the Detect It Easy signatures */
  def loadAll(): Int = compile(List(DefaultSignatures.peScanner, DefaultSignatures.fileTypeScanner,
    DefaultSignatures.javaWrapperScanner))

  private val e2eKinds = Set(LocationKind.ENTRY_POINT, LocationKind.OVERLAY, LocationKind.RESOURCE, LocationKind.MSDOS_HEADER)

  def main(args: Array[String]): Unit = {
    // logging is initialized by the PE parser before signatures are scanned, it is no part of loading them
    org.apache.logging.log4j.LogManager.getLogger("ColdLoadProbe")
    // optionally parse a PE file first, like PortexAnalyzer does before it scans for signatures
    val pe = if (args.length > 1) io.github.struppigel.parser.PELoader.loadPE(new java.io.File(args(1))) else null
    val start = System.nanoTime()
    val n = args(0) match {
      case "legacy" => loadLegacy()
      case "new" => loadNew()
      case "new-all" => loadAll()
      // all signatures PEData returned in PortEx 5, with the databases as PortEx 5 loaded them
      case "legacy-e2e" => new LegacyScans(asShipped = true).allPEMatches(pe).size
      case "new-e2e" => portex5Scanner._scan(pe, e2eKinds).size
      // what PEData returns now, including the Detect It Easy signatures
      case "new-all-e2e" => pe.getSignatureMatches(e2eKinds.toSeq: _*).size
    }
    val elapsed = System.nanoTime() - start
    println(s"$elapsed $n")
  }
}
