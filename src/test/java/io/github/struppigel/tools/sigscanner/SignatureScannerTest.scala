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

import io.github.struppigel.tools.sigscanner.engine.AhoCorasick
import io.github.struppigel.tools.sigscanner.pattern.Pattern
import org.testng.Assert._
import org.testng.annotations.Test

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
 * Tests of the scan engine on data without PE structure, so only the locations
 * file and eof are involved.
 */
class SignatureScannerTest {

  private def db(text: String): SignatureDatabase = SignatureDatabase.parse(text, "test")

  private def scan(text: String, bytes: Array[Byte], options: ScanOptions = ScanOptions.Default): IndexedSeq[SignatureMatch] =
    new SignatureScanner(db(text), options)._scanBytes(bytes)

  private def offsets(matches: Seq[SignatureMatch], name: String): List[Long] =
    matches.filter(_.getName == name).map(_.getOffset).toList

  private def ascii(s: String): Array[Byte] = s.getBytes(StandardCharsets.ISO_8859_1)

  @Test
  def anchoredAtFileStart(): Unit = {
    val m = scan("[MZ]\npattern = 'MZ' 90\nat = file\n\n[PE]\npattern = 'PE'\nat = file", ascii("MZ\u0090 PE"))
    assertEquals(m.map(_.getName), Seq("MZ"))
    assertEquals(m.head.getOffset, 0L)
    assertEquals(m.head.getLength, 3)
    assertEquals(m.head.getLocationKind, LocationKind.FILE)
  }

  @Test
  def anchoredWithOffset(): Unit = {
    val m = scan("[x]\npattern = 'PE'\nat = file + 4", ascii("MZ  PE"))
    assertEquals(offsets(m, "x"), List(4L))
    assertTrue(scan("[x]\npattern = 'PE'\nat = file + 3", ascii("MZ  PE")).isEmpty)
  }

  @Test
  def searchFindsEveryOccurrence(): Unit = {
    val m = scan("[pk]\npattern = 'PK' 03 04\nin = file", ascii("PK\u0003\u0004..PK\u0003\u0004PK\u0003"))
    assertEquals(offsets(m, "pk"), List(0L, 6L))
    assertEquals(m.head.getLocationLabel, "file")
  }

  @Test
  def searchWindowLimitsTheStart(): Unit = {
    val data = ascii("abcXYZdefXYZ")
    assertEquals(offsets(scan("[x]\npattern = 'XYZ'\nin = file[0-4]", data), "x"), List(3L))
    // the window end is exclusive
    assertEquals(offsets(scan("[x]\npattern = 'XYZ'\nin = file[0-3]", data), "x"), Nil)
    // the match may end after the window
    assertEquals(offsets(scan("[x]\npattern = 'XYZ'\nin = file[9-10]", data), "x"), List(9L))
    assertEquals(offsets(scan("[x]\npattern = 'XYZ'\nin = file[4-]", data), "x"), List(9L))
    assertEquals(offsets(scan("[x]\npattern = 'XYZ'\nin = file[4]", data), "x"), List(3L))
  }

  @Test
  def matchesDoNotCrossTheEndOfData(): Unit = {
    assertTrue(scan("[x]\npattern = 'XYZ'\nin = file", ascii("abcXY")).isEmpty)
    assertTrue(scan("[x]\npattern = 'XY' [1-]\nin = file", ascii("abcXY")).isEmpty)
    assertEquals(offsets(scan("[x]\npattern = 'XY' [0-]\nin = file", ascii("abcXY")), "x"), List(3L))
  }

  @Test
  def bruteForceSearchWithoutAtom(): Unit = {
    // no literal of two bytes: checked at every position
    val m = scan("[x]\npattern = 4D ?? 5A\nin = file", ascii("4M5Z MaZ M"))
    assertEquals(offsets(m, "x"), List(1L, 5L))
  }

  @Test
  def duplicateLocationsReportOneMatch(): Unit = {
    val m = scan("[x]\npattern = 'XYZ'\nin = file, file[0-10]", ascii("..XYZ"))
    assertEquals(offsets(m, "x"), List(2L))
  }

  @Test
  def maxMatchesPerSignature(): Unit = {
    val m = scan("[x]\npattern = 'AB'\nin = file", ascii("ABABABABAB"), ScanOptions(maxMatchesPerSignature = 3))
    assertEquals(m.size, 3)
  }

  @Test
  def atEndOfFileMinusN(): Unit = {
    val data = ascii("....MEI\u000C\u000B\u000A\u000B\u000E" + "x" * 16)
    val m = scan("[cookie]\npattern = 'MEI' 0C 0B 0A 0B 0E\nat = eof - 0x18", data)
    assertEquals(offsets(m, "cookie"), List(4L))
    assertEquals(m.head.getLocationKind, LocationKind.EOF)
    assertEquals(m.head.getRelativeOffset, 0L)
    // more than the file size
    assertTrue(scan("[x]\npattern = 'MEI'\nat = eof - 0x100", data).isEmpty)
  }

  @Test
  def atEndOfFileRequiresMatchToEndThere(): Unit = {
    assertEquals(offsets(scan("[t]\npattern = 'END'\nat = eof", ascii("xxEND")), "t"), List(2L))
    // the same bytes one byte before the end do not match
    assertTrue(scan("[t]\npattern = 'END'\nat = eof", ascii("xxEND.")).isEmpty)
    // variable length pattern that ends at the end of the file
    assertEquals(offsets(scan("[t]\npattern = 'E' [1-3] 'D'\nat = eof", ascii("xxEabcD")), "t"), List(2L))
    assertTrue(scan("[t]\npattern = 'E' [1-3] 'D'\nat = eof", ascii("xxEabcDx")).isEmpty)
    // file shorter than the pattern
    assertTrue(scan("[t]\npattern = 'LONGER'\nat = eof", ascii("END")).isEmpty)
  }

  @Test
  def inEndOfFileWindow(): Unit = {
    val data = ascii("PK\u0005\u0006" + "." * 40 + "PK\u0005\u0006" + "." * 18)
    val m = scan("[eocd]\npattern = 50 4B 05 06\nin = eof[0x20]", data)
    assertEquals(offsets(m, "eocd"), List(44L))
    assertEquals(m.head.getRegionStart, data.length - 0x20L)
    // the window is clipped to the start of small files
    assertEquals(offsets(scan("[eocd]\npattern = 50 4B 05 06\nin = eof", data), "eocd"), List(0L, 44L))
  }

  @Test
  def furtherClausesMustMatch(): Unit = {
    val sigs = "[both]\npattern = 'MZ'\nat = file\npattern.2 = 'TAIL'\nat.2 = eof"
    val m = scan(sigs, ascii("MZ......TAIL"))
    assertEquals(m.size, 1)
    assertEquals(m.head.getClauseMatches.size, 2)
    assertEquals(m.head.getClauseMatches.get(1).getOffset, 8L)
    assertTrue(scan(sigs, ascii("MZ......TAIX")).isEmpty)
    assertTrue(scan(sigs, ascii("XZ......TAIL")).isEmpty)
  }

  @Test
  def furtherClauseSearch(): Unit = {
    val sigs = "[s]\npattern = 'MZ'\nat = file\npattern.2 = w'Setup'\nin.2 = file[2-]"
    assertEquals(scan(sigs, "MZ..".getBytes(StandardCharsets.ISO_8859_1) ++ "Setup".getBytes(StandardCharsets.UTF_16LE)).size, 1)
    assertEquals(scan(sigs, ascii("MZ..Setup")).size, 0)
  }

  @Test
  def conditionsAreFalseWithoutPEStructure(): Unit = {
    assertTrue(scan("[x]\npattern = 'MZ'\nat = file\nrequires = dotnet", ascii("MZ")).isEmpty)
    assertEquals(scan("[x]\npattern = 'MZ'\nat = file\nrequires = !dotnet", ascii("MZ")).size, 1)
  }

  @Test
  def followTokensWithoutPEStructureUseFileOffsets(): Unit = {
    val data = Array[Byte](0xE8.toByte, 3, 0, 0, 0, 0, 0, 0, 0x55, 0x8B.toByte, 0xEC.toByte)
    val m = scan("[call]\npattern = E8 $$$$$$$$ 55 8B EC\nat = file", data)
    assertEquals(m.size, 1)
    assertEquals(m.head.getLength, 5)
  }

  @Test
  def scanFileEqualsScanBytes(): Unit = {
    val rnd = new Random(7)
    val data = Array.fill(100000)((rnd.nextInt(4) + 0x41).toByte)
    val file = File.createTempFile("portex-scanner-test", ".bin")
    file.deleteOnExit()
    Files.write(file.toPath, data)
    val scanner = new SignatureScanner(db("[a]\npattern = 'ABCD'\nin = file\n\n[b]\npattern = 'DCBA' [0-4] 'AB'\nin = eof[0x5000]"),
      ScanOptions(chunkSize = 4096))
    val fromFile = scanner._scanFile(file).map(m => (m.getName, m.getOffset))
    val fromBytes = scanner._scanBytes(data).map(m => (m.getName, m.getOffset))
    assertTrue(fromFile.nonEmpty)
    assertEquals(fromFile, fromBytes)
  }

  /** all matches by trying every signature at every position */
  private def naive(sigs: Seq[(String, Pattern, Long, Long)], data: Array[Byte]): Set[(String, Long)] =
    (for {
      (name, pattern, from, until) <- sigs
      start <- from until math.min(until, data.length.toLong)
      if pattern.matchAt(data, start.toInt) >= 0
    } yield (name, start)).toSet

  @Test
  def searchAgreesWithNaiveScanOnRandomData(): Unit = {
    val rnd = new Random(1234)
    val alphabet = Array[Byte](0x41, 0x42, 0x43, 0x44)
    for (round <- 0 until 40) {
      val data = Array.fill(2000 + rnd.nextInt(3000))(alphabet(rnd.nextInt(4)))
      val sigs = ListBuffer[(String, Pattern, Long, Long)]()
      val text = new StringBuilder
      for (i <- 0 until 1 + rnd.nextInt(8)) {
        def lit(n: Int) = (0 until n).map(_ => "%02X".format(alphabet(rnd.nextInt(4)))).mkString(" ")
        val source = rnd.nextInt(5) match {
          case 0 => lit(3 + rnd.nextInt(3))
          case 1 => lit(2) + " [0-3] " + lit(2)
          case 2 => "?? " + lit(4)
          case 3 => "(" + lit(3) + " | " + lit(4) + ")"
          case _ => lit(1) + " ?? " + lit(1) // no atom, brute force
        }
        val (window, from, until) = rnd.nextInt(3) match {
          case 0 => ("", 0L, Long.MaxValue)
          case 1 =>
            val a = rnd.nextInt(1000)
            val b = a + 1 + rnd.nextInt(2000)
            (s"[$a-$b]", a.toLong, b.toLong)
          case _ =>
            val a = rnd.nextInt(1000)
            (s"[$a-]", a.toLong, Long.MaxValue)
        }
        text ++= s"[s$i]\npattern = $source\nin = file$window\n\n"
        sigs += ((s"s$i", Pattern.parse(source), from, until))
      }
      val expected = naive(sigs, data)
      for (chunk <- Seq(64, 1000, 1 << 20)) {
        val actual = new SignatureScanner(db(text.toString), ScanOptions(chunkSize = chunk))._scanBytes(data)
          .map(m => (m.getName, m.getOffset)).toSet
        assertEquals(actual, expected, s"round $round, chunk size $chunk:\n$text")
      }
    }
  }

  @Test
  def ahoCorasickDenseEqualsSparse(): Unit = {
    val rnd = new Random(99)
    val keys = (0 until 200).map(_ => Array.fill(2 + rnd.nextInt(5))((rnd.nextInt(3) + 1).toByte))
    val input = Array.fill(5000)((rnd.nextInt(3) + 1).toByte)
    def hits(ac: AhoCorasick): List[(Int, Int)] = {
      val found = ListBuffer[(Int, Int)]()
      // feed in two parts to test the carried state
      val s = ac.feed(0, input, 0, 2500)((k, i) => found += ((k, i)))
      ac.feed(s, input, 2500, input.length)((k, i) => found += ((k, i)))
      found.toList.sorted
    }
    val dense = new AhoCorasick(keys)
    val sparse = new AhoCorasick(keys, denseLimit = 0)
    assertTrue(dense.isDense)
    assertFalse(sparse.isDense)
    val expected = (for {
      (k, ki) <- keys.zipWithIndex
      end <- k.length - 1 until input.length
      if java.util.Arrays.equals(java.util.Arrays.copyOfRange(input, end - k.length + 1, end + 1), k)
    } yield (ki, end)).toList.sorted
    assertEquals(hits(dense), expected)
    assertEquals(hits(sparse), expected)
  }

  @Test
  def ahoCorasickOverlappingAndSuffixKeys(): Unit = {
    val ac = new AhoCorasick(IndexedSeq("he", "she", "his", "hers").map(_.getBytes(StandardCharsets.US_ASCII)))
    val found = ListBuffer[(Int, Int)]()
    ac.feed(0, "ushers".getBytes(StandardCharsets.US_ASCII), 0, 6)((k, i) => found += ((k, i)))
    assertEquals(found.toSet, Set((1, 3), (0, 3), (3, 5)))
  }
}
