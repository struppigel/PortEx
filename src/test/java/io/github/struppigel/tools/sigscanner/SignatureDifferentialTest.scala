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

import io.github.struppigel.parser.PELoader
import io.github.struppigel.tools.sigscanner.legacy.LegacyGoldenGenerator
import org.testng.Assert.assertTrue
import org.testng.SkipException
import org.testng.annotations.Test

import java.io.File
import scala.collection.mutable.ListBuffer
import scala.io.Source

/**
 * Compares the results of the signature scanner with the results of the
 * PortEx 5 scanner on the test corpus, which were saved by the
 * LegacyGoldenGenerator. Every difference must be listed with a reason in
 * golden-v1-allowed-changes.tsv.
 */
class SignatureDifferentialTest {

  private val corpus = new File("portextestfiles")

  /** the databases converted from PortEx 5, without the Detect It Easy signatures */
  private lazy val legacyScanner = new SignatureScanner(SignatureDatabase.merge(
    DefaultSignatures.packers, DefaultSignatures.installers, DefaultSignatures.fileTypes))

  private case class GoldenRow(path: String, sha: String, group: String, name: String, address: Long)

  /** a match in the terms of the golden file */
  private case class Found(group: String, name: String, address: Long, regionStart: Long)

  private case class Allowed(change: String, path: String, group: String, name: String, address: String) {
    def covers(c: String, p: String, g: String, n: String, a: Long): Boolean =
      change == c && (path == "*" || path == p) && group == g && name == n &&
        (address == "*" || java.lang.Long.decode(address) == a)
  }

  private def lines(resource: String): List[String] = {
    val in = getClass.getResourceAsStream(resource)
    if (in == null) throw new IllegalStateException("missing " + resource)
    try Source.fromInputStream(in, "UTF-8").getLines().filterNot(l => l.startsWith("#") || l.trim.isEmpty).toList
    finally in.close()
  }

  private def golden: List[GoldenRow] = lines("/sigscanner/golden-v1.tsv").map { line =>
    val f = line.split("\t", -1)
    GoldenRow(f(0), f(1), f(2), LegacyGoldenGenerator.unescape(f(3)), java.lang.Long.decode(f(4)))
  }

  private def allowed: List[Allowed] = lines("/sigscanner/golden-v1-allowed-changes.tsv").map { line =>
    val f = line.split("\t", -1)
    Allowed(f(0), f(1), f(2), f(3), f(4))
  }

  /** names of INI style databases had brackets, non-UTF-8 characters were replaced */
  private def normalize(name: String): String = {
    val trimmed = name.trim
    val unbracketed = if (trimmed.startsWith("[") && trimmed.endsWith("]")) trimmed.substring(1, trimmed.length - 1).trim else trimmed
    unbracketed.filter(c => c < 128)
  }

  private def groupOf(kind: LocationKind): String = kind match {
    case LocationKind.ENTRY_POINT | LocationKind.SECTION => "peid"
    case LocationKind.OVERLAY => "overlay"
    case LocationKind.RESOURCE => "resource"
    case LocationKind.MSDOS_HEADER => "msdos"
    case other => other.keyword
  }

  private def scan(file: File, groups: Set[String]): Set[Found] = {
    val found = ListBuffer[Found]()
    def add(group: String, matches: Seq[SignatureMatch]): Unit =
      found ++= matches.map(m => Found(group, normalize(m.getName), m.getOffset, m.getRegionStart))
    if (groups.exists(Set("peid", "overlay", "resource", "msdos"))) {
      val pe = PELoader.loadPE(file)
      val kinds = Set(LocationKind.ENTRY_POINT, LocationKind.SECTION, LocationKind.OVERLAY,
        LocationKind.RESOURCE, LocationKind.MSDOS_HEADER)
      for (m <- legacyScanner._scan(pe, kinds)) {
        // InnoSetup and the PyInstaller string were hard coded in PortEx 5
        val group = groupOf(m.getLocationKind)
        if (groups.contains(group)) found += Found(group, normalize(m.getName), m.getOffset, m.getRegionStart)
      }
    }
    if (groups.contains("jar2exe")) add("jar2exe", DefaultSignatures.javaWrapperScanner._scanFile(file))
    if (groups.contains("filetype0")) add("filetype0", DefaultSignatures.fileTypeScanner._scanFile(file))
    found.toSet
  }

  @Test
  def newScannerReproducesLegacyResults(): Unit = {
    if (!corpus.isDirectory) throw new SkipException("test corpus portextestfiles not available")
    val allowedChanges = allowed
    val missing = ListBuffer[String]()
    val added = ListBuffer[String]()
    var compared = 0
    for ((path, rows) <- golden.groupBy(_.path).toList.sortBy(_._1)) {
      val file = new File(corpus, path)
      if (file.isFile && LegacyGoldenGenerator.sha256(file) == rows.head.sha) {
        compared += 1
        val groups = rows.find(_.group == "_scanned").map(_.name.split(",").filter(_.nonEmpty).toSet).getOrElse(Set())
        val legacy = rows.filterNot(_.group.startsWith("_")).map(r => Found(r.group, normalize(r.name), r.address, -1)).distinct
        val current = scan(file, groups)
        def same(l: Found, c: Found): Boolean = l.group == c.group && l.name == c.name &&
          // leading wildcards of overlay signatures became anchor offsets
          (l.address == c.address || (l.group == "overlay" && l.address == c.regionStart))
        for (l <- legacy if !current.exists(same(l, _)) &&
          !allowedChanges.exists(_.covers("missing", path, l.group, l.name, l.address)))
          missing += s"missing\t$path\t${l.group}\t${l.name}\t0x${l.address.toHexString}"
        for (c <- current if !legacy.exists(same(_, c)) &&
          !allowedChanges.exists(_.covers("added", path, c.group, c.name, c.address)))
          added += s"added\t$path\t${c.group}\t${c.name}\t0x${c.address.toHexString}"
      }
    }
    if (compared == 0) throw new SkipException("no file of the golden results found in the corpus")
    val diffs = missing ++ added
    assertTrue(diffs.isEmpty, s"${diffs.size} unexpected differences to PortEx 5 in $compared files:\n" + diffs.mkString("\n"))
  }
}
