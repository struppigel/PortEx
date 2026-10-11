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
import io.github.struppigel.tools.sigscanner.engine._
import io.github.struppigel.tools.sigscanner.pattern.{ArrayByteSource, ByteSource}

import java.io.File
import scala.annotation.varargs
import scala.collection.JavaConverters._

/**
 * Scans files for the signatures of a database. See docs/SIGNATURES.md.
 * <p>
 * The database is compiled once when the scanner is created. Scanners are
 * immutable and thread-safe, so one instance can be shared.
 *
 * @param database the signatures to scan for
 * @param options scan options
 */
final class SignatureScanner(val database: SignatureDatabase, val options: ScanOptions) {

  def this(database: SignatureDatabase) = this(database, ScanOptions.Default)

  private[sigscanner] val plan = new ScanPlan(database)

  def getDatabase: SignatureDatabase = database

  /** warnings about signatures that are slow to scan */
  def getWarnings: java.util.List[String] = plan.warnings.asJava

  /**
   * Scans all location kinds of a PE file.
   */
  def scan(pe: PEData): java.util.List[SignatureMatch] =
    _scan(pe, LocationKind.values().toSet).asJava

  /**
   * Scans the given location kinds of a PE file.
   */
  @varargs def scan(pe: PEData, kinds: LocationKind*): java.util.List[SignatureMatch] =
    _scan(pe, kinds.toSet).asJava

  /**
   * Scans the given location kinds of a PE file.
   */
  def scan(pe: PEData, kinds: java.util.Set[LocationKind]): java.util.List[SignatureMatch] =
    _scan(pe, kinds.asScala.toSet).asJava

  /**
   * Scans the given location kinds of a PE file.
   */
  def _scan(pe: PEData, kinds: Set[LocationKind]): IndexedSeq[SignatureMatch] =
    scanDetailed(pe, kinds)._1

  /** scans and returns the resolver for tests */
  private[sigscanner] def scanDetailed(pe: PEData, kinds: Set[LocationKind]): (IndexedSeq[SignatureMatch], RegionResolver) = {
    val reader = new FileWindowReader(pe.getFile)
    try {
      val resolver = new RegionResolver(reader.size, pe.getFile.getName, pe)
      (run(reader, resolver, pe, kinds), resolver)
    } finally reader.close()
  }

  /**
   * Scans a file without parsing it as PE file, so only the locations file
   * and eof are scanned. Use this for files that are no PE files.
   */
  def scanFile(file: File): java.util.List[SignatureMatch] = _scanFile(file).asJava

  def _scanFile(file: File): IndexedSeq[SignatureMatch] = {
    val reader = new FileWindowReader(file)
    try run(reader, new RegionResolver(reader.size, file.getName, null), null, Set(LocationKind.FILE, LocationKind.EOF))
    finally reader.close()
  }

  /**
   * Scans bytes, only the locations file and eof are scanned.
   */
  def scanBytes(bytes: Array[Byte]): java.util.List[SignatureMatch] = _scanBytes(bytes).asJava

  def _scanBytes(bytes: Array[Byte]): IndexedSeq[SignatureMatch] =
    run(new ArrayByteSource(bytes), new RegionResolver(bytes.length, "bytes", null), null,
      Set(LocationKind.FILE, LocationKind.EOF))

  private def run(source: ByteSource, resolver: RegionResolver, pe: PEData, kinds: Set[LocationKind]): IndexedSeq[SignatureMatch] = {
    val facts = new PEFacts(pe, resolver, source)
    new ScanRun(plan, options, source, resolver, facts).run(kinds)
  }
}

object SignatureScanner {

  def apply(database: SignatureDatabase): SignatureScanner = new SignatureScanner(database)

  def apply(database: SignatureDatabase, options: ScanOptions): SignatureScanner = new SignatureScanner(database, options)
}
