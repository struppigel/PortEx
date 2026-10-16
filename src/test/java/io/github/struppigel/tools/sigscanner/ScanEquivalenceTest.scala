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
import io.github.struppigel.tools.sigscanner.engine.{PEFacts, RegionResolver, ScanRun}
import io.github.struppigel.tools.sigscanner.pattern.{ArrayByteSource, Pattern}
import org.testng.Assert._
import org.testng.SkipException
import org.testng.annotations.Test

import java.io.File
import java.nio.charset.StandardCharsets
import scala.collection.mutable.ArrayBuffer
import scala.util.Random

/**
 * Compares the scanner with a naive scan that tries every signature at every
 * position, for databases like those converted from YARA: many signatures
 * with several patterns that search the whole file.
 */
class ScanEquivalenceTest {

  private val words = Vector("Invoke", "password", "kernel32", "Setup", "MZheader", "cmd.exe", "SELECT", "token",
    "Mutex", "wallet", "AB", "xyz", "Loader", "decrypt")

  /** random text with planted words in various encodings and cases */
  private def data(rnd: Random, size: Int): Array[Byte] = {
    val out = new java.io.ByteArrayOutputStream()
    while (out.size() < size) {
      if (rnd.nextInt(4) == 0) {
        val w = words(rnd.nextInt(words.size))
        val text = rnd.nextInt(3) match {
          case 0 => w
          case 1 => w.toUpperCase
          case _ => w.toLowerCase
        }
        out.write(text.getBytes(if (rnd.nextBoolean()) StandardCharsets.US_ASCII else StandardCharsets.UTF_16LE))
      } else out.write("abcdefgh .\u0000".charAt(rnd.nextInt(11)))
    }
    out.toByteArray
  }

  private def randomPattern(rnd: Random): String = {
    def w = "'" + words(rnd.nextInt(words.size)) + "'"
    rnd.nextInt(9) match {
      case 0 => w
      case 1 => "i" + w
      case 2 => "w" + w
      case 3 => "aw" + w
      case 4 => "awi" + w
      case 5 => s"$w [0-${rnd.nextInt(600)}] $w"
      case 6 => s"?? [0-${rnd.nextInt(600)}] $w"
      case 7 => s"($w | $w)"
      case _ => s"'${"abcdefgh".charAt(rnd.nextInt(8))}' ?? '${"abcdefgh".charAt(rnd.nextInt(8))}'" // no atom
    }
  }

  private def location(rnd: Random, size: Int): String = rnd.nextInt(5) match {
    case 0 | 1 => "in = file"
    case 2 => s"in = file[${rnd.nextInt(size / 2)}-]"
    case 3 => val a = rnd.nextInt(size); s"in = file[$a-${a + 1 + rnd.nextInt(size)}]"
    case _ => s"at = file + ${rnd.nextInt(size)}"
  }

  /** a database of signatures with 1 to 4 patterns */
  private def database(rnd: Random, count: Int, size: Int): String = (0 until count).map { i =>
    val clauses = (1 to 1 + rnd.nextInt(4)).map { n =>
      val suffix = if (n == 1) "" else "." + n
      s"pattern$suffix = ${randomPattern(rnd)}\n${location(rnd, size).replaceFirst(" =", suffix + " =")}"
    }
    s"[s$i]\n${clauses.mkString("\n")}\n"
  }.mkString("\n")

  /** start offsets of a pattern at a location of the data, all or only the lowest */
  private def starts(p: Pattern, spec: LocationSpec, bytes: Array[Byte]): Seq[Long] = {
    val size = bytes.length.toLong
    val candidates: Seq[Long] = spec.mode match {
      case Anchored(offset) => if (offset < size) Seq(offset) else Nil
      case Search(from, until) => from until (if (until < 0) size else math.min(size, until))
      case _ => fail("unexpected location " + spec.source); Nil
    }
    candidates.filter(s => s + p.compiled.minLength <= size && p.matchAt(bytes, s.toInt) >= 0)
  }

  /** the matches of the naive scan: name and the offsets of all clause matches */
  private def naive(db: SignatureDatabase, bytes: Array[Byte]): Set[(String, Seq[Long])] = {
    val result = ArrayBuffer[(String, Seq[Long])]()
    for (sig <- db.signatures) {
      val first = sig.clauses.head
      val firstStarts = first.locations.flatMap(spec => starts(first.pattern, spec, bytes)).distinct
      // a further clause: the lowest match of its first location that has one
      val further = sig.clauses.drop(1).map { c =>
        c.locations.view.map(spec => starts(c.pattern, spec, bytes)).find(_.nonEmpty).map(_.min)
      }
      if (further.forall(_.isDefined)) for (s <- firstStarts) result += ((sig.name, s +: further.flatten))
    }
    result.toSet
  }

  private def scanned(scanner: SignatureScanner, bytes: Array[Byte]): Set[(String, Seq[Long])] =
    scanner._scanBytes(bytes).map(m => (m.getName, m.getClauseMatches.toArray(Array.empty[ClauseMatch]).toSeq.map(_.getOffset))).toSet

  @Test
  def manyPatternsAgreeWithNaiveScan(): Unit = {
    val rnd = new Random(2026)
    for (round <- 0 until 12) {
      val bytes = data(rnd, 3000 + rnd.nextInt(5000))
      val db = SignatureDatabase.parse(database(rnd, 40, bytes.length), "generated.sig")
      val expected = naive(db, bytes)
      for (chunk <- Seq(97, 4096, 1 << 20)) {
        val actual = scanned(new SignatureScanner(db, ScanOptions(chunkSize = chunk)), bytes)
        assertEquals(actual, expected, s"round $round, chunk size $chunk")
      }
    }
  }

  private def run(scanner: SignatureScanner, bytes: Array[Byte]): ScanRun = {
    val source = new ArrayByteSource(bytes)
    val resolver = new RegionResolver(bytes.length, "bytes", null)
    new ScanRun(scanner.plan, scanner.options, source, resolver, new PEFacts(null, resolver, source))
  }

  @Test
  def furtherPatternsAreSearchedInThePassOfTheFirstOnes(): Unit = {
    val text = (0 until 50).map(i => s"[s$i]\npattern = 'Setup'\nin = file\npattern.2 = 'wallet'\nin.2 = file\n" +
      s"pattern.3 = 'missing$i'\nin.3 = file\n").mkString("\n")
    val scanner = new SignatureScanner(SignatureDatabase.parse(text, "multi.sig"))
    val bytes = "....Setup....wallet....".getBytes(StandardCharsets.US_ASCII)
    val r = run(scanner, bytes)
    assertTrue(r.run(Set(LocationKind.FILE, LocationKind.EOF)).isEmpty)
    assertEquals(r.searchPasses, 1)
  }

  @Test
  def furtherPatternTakesTheLowestOffset(): Unit = {
    // the first branch is searched by its second literal, so the second branch at 9 is found before it at 7
    val db = SignatureDatabase.parse("[x]\npattern = 'first'\nin = file\npattern.2 = ('AB' [4] 'CDEFGHIJ' | 'KLMN')\nin.2 = file", "x.sig")
    val bytes = "first..ABKLMNCDEFGHIJ".getBytes(StandardCharsets.US_ASCII)
    val m = new SignatureScanner(db)._scanBytes(bytes)
    assertEquals(m.size, 1)
    assertEquals(m.head.getClauseMatches.get(1).getOffset, 7L)
  }

  @Test
  def furtherPatternOfAnotherLocationIsSearchedLaterIfNeeded(): Unit = {
    val file = new File("portextestfiles/testfiles/embedded_exe_overlay")
    if (!file.isFile) throw new SkipException("sample not available")
    val pe = PELoader.loadPE(file)
    val db = SignatureDatabase.parse(
      """[overlay pe]
        |pattern = 'MZ'
        |in = overlay[0-1]
        |pattern.2 = 'This program'
        |in.2 = overlay
        |pattern.3 = 'PE' 00 00
        |in.3 = file
        |
        |[file pass]
        |pattern = 'kernel32'
        |in = file
        |""".stripMargin, "pe.sig")
    val scanner = new SignatureScanner(db)
    val all = scanner._scan(pe, LocationKind.values().toSet).filter(_.getName == "overlay pe")
    // pattern.3 is searched in the pass of [file pass] or alone if only the overlay is scanned
    val overlayOnly = scanner._scan(pe, Set(LocationKind.OVERLAY))
    assertEquals(all.size, 1)
    assertEquals(overlayOnly.map(_.getClauseMatches.toString), all.map(_.getClauseMatches.toString))
    val bytes = java.nio.file.Files.readAllBytes(file.toPath)
    val firstPE = new String(bytes, StandardCharsets.ISO_8859_1).indexOf("PE\u0000\u0000")
    assertEquals(all.head.getClauseMatches.get(2).getOffset, firstPE.toLong)
  }
}
