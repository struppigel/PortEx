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

import io.github.struppigel.TestreportsReader
import io.github.struppigel.parser.PELoader
import io.github.struppigel.tools.sigscanner.pattern.Pattern
import org.testng.Assert._
import org.testng.annotations.Test

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import scala.collection.mutable.ListBuffer

/**
 * Checks that the examples of docs/SIGNATURES.md are valid: blocks tagged
 * portex-sig must parse, portex-sig-invalid must not parse, and every line of
 * a portex-pattern block must be a valid pattern. Some examples are matched.
 */
class DocsExamplesTest {

  private lazy val doc: String =
    new String(Files.readAllBytes(new File("docs/SIGNATURES.md").toPath), StandardCharsets.UTF_8)

  private def blocks(tag: String): List[String] = {
    val result = ListBuffer[String]()
    val lines = doc.split("\r?\n")
    var i = 0
    while (i < lines.length) {
      if (lines(i).trim == "```" + tag) {
        val block = new StringBuilder
        i += 1
        while (i < lines.length && lines(i).trim != "```") {
          block ++= lines(i) + "\n"
          i += 1
        }
        result += block.toString
      }
      i += 1
    }
    result.toList
  }

  private lazy val examples: Map[String, Signature] =
    blocks("portex-sig").flatMap(b => SignatureDatabase.parse(b, "SIGNATURES.md").signatures).map(s => s.name -> s).toMap

  @Test
  def signatureExamplesParse(): Unit = {
    val sigBlocks = blocks("portex-sig")
    assertTrue(sigBlocks.size >= 10, s"only ${sigBlocks.size} examples found")
    for (b <- sigBlocks) {
      val db = SignatureDatabase.parse(b, "SIGNATURES.md")
      assertTrue(db.size > 0 && db.warnings.isEmpty, b)
    }
  }

  @Test
  def invalidExamplesFail(): Unit = {
    val invalid = blocks("portex-sig-invalid")
    assertTrue(invalid.nonEmpty)
    for (b <- invalid) {
      try {
        SignatureDatabase.parse(b, "SIGNATURES.md")
        fail("expected an error for\n" + b)
      } catch {
        case _: SignatureDatabaseException =>
      }
    }
  }

  @Test
  def patternExamplesParse(): Unit = {
    val lines = blocks("portex-pattern").flatMap(_.split("\n")).map(_.trim).filter(_.nonEmpty)
    assertTrue(lines.size >= 10)
    lines.foreach(Pattern.parse)
  }

  private def scanBytes(name: String, bytes: Array[Byte]): IndexedSeq[SignatureMatch] =
    new SignatureScanner(SignatureDatabase.of(Seq(examples(name))))._scanBytes(bytes)

  @Test
  def endOfFileExamplesMatch(): Unit = {
    val zip = Array.fill[Byte](100)(0x2E) ++ Array[Byte](0x50, 0x4B, 5, 6) ++ Array.fill[Byte](18)(0)
    assertEquals(scanBytes("ZIP end of central directory", zip).map(_.getOffset), IndexedSeq(100L))
    val cookie = "MEI\u000C\u000B\u000A\u000B\u000E".getBytes(StandardCharsets.ISO_8859_1)
    val pyinstaller = Array.fill[Byte](64)(0x2E) ++ cookie ++ Array.fill[Byte](0x18 - cookie.length)(0)
    assertEquals(scanBytes("PyInstaller cookie", pyinstaller).map(_.getOffset), IndexedSeq(64L))
    val zipFile = Array[Byte](0x50, 0x4B, 3, 4) ++ Array.fill[Byte](20)(0)
    assertEquals(scanBytes("ZIP archive", zipFile).map(_.getLocationKind), IndexedSeq(LocationKind.FILE))
  }

  private def scanSample(name: String, sample: String): IndexedSeq[SignatureMatch] = {
    val pe = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/testfiles/" + sample))
    new SignatureScanner(SignatureDatabase.of(Seq(examples(name))))._scan(pe, LocationKind.values().toSet)
  }

  @Test
  def peExamplesMatch(): Unit = {
    assertEquals(scanSample("UPX 64 bit", "upx.exe").size, 1)
    assertEquals(scanSample("PyInstaller archive string", "pyinstaller").size, 1)
    assertTrue(scanSample("Inno Setup Installer with Stub", "inno_with_stub").nonEmpty)
    assertTrue(scanSample("UPX 64 bit", "HelloWorld.exe").isEmpty)
  }
}
