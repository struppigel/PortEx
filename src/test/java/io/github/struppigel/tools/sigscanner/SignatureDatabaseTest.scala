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

import org.testng.Assert._
import org.testng.annotations.Test

import java.io.StringWriter
import scala.collection.JavaConverters._

class SignatureDatabaseTest {

  private def parse(text: String): SignatureDatabase = SignatureDatabase.parse(text, "test.sig")

  private def assertError(text: String, line: Int, column: Int, reasonPart: String): Unit = {
    try {
      parse(text)
      fail("expected an error for:\n" + text)
    } catch {
      case e: SignatureDatabaseException =>
        assertEquals((e.line, e.column), (line, column), e.getMessage)
        assertTrue(e.reason.contains(reasonPart), e.getMessage)
        assertTrue(e.getMessage.startsWith(s"test.sig:$line"), e.getMessage)
    }
  }

  @Test
  def parsesEntries(): Unit = {
    val db = parse(
      """; comment
        |# another comment
        |
        |[UPX 0.89.6 - 1.02]
        |pattern = 60 BE ?? ?? ?? ?? 8D BE
        |at = entrypoint
        |type = packer, compressor
        |version = 0.89
        |description = Ultimate Packer for eXecutables
        |x-source = PEiD
        |
        |[[MSLRH] v0.32a -> emadicius]
        |pattern = 'Inno'
        |at = overlay + 0x34, file
        |in = section(.rdata)[0-0x1500]
        |""".stripMargin)
    assertEquals(db.size, 2)
    val upx = db.signatures(0)
    assertEquals(upx.name, "UPX 0.89.6 - 1.02")
    assertEquals(upx.getTypes.asScala, Seq("packer", "compressor"))
    assertEquals(upx.getVersion.get, "0.89")
    assertEquals(upx.getDescription.get, "Ultimate Packer for eXecutables")
    assertEquals(upx.metadata("x-source"), "PEiD")
    assertEquals(upx.source, "test.sig:4")
    val nested = db.signatures(1)
    assertEquals(nested.name, "[MSLRH] v0.32a -> emadicius")
    assertEquals(nested.clauses.head.locations.map(_.source), Seq("overlay + 0x34", "file", "section(.rdata)[0-0x1500]"))
    assertEquals(nested.clauses.head.locations.head.mode, Anchored(0x34))
    assertEquals(nested.clauses.head.locations(2).mode, Search(0, 0x1500))
  }

  @Test
  def crlfAndByteOrderMark(): Unit = {
    val db = parse("﻿[a]\r\npattern = 01 02\r\nat = file\r\n")
    assertEquals(db.signatures.head.name, "a")
  }

  @Test
  def clausesAndConditions(): Unit = {
    val sig = parse(
      """[WinRAR like]
        |pattern = e8 $$$$$$$$ 55 8B EC
        |at = entrypoint
        |pattern.2 = w'***messages***'
        |at.2 = overlay
        |requires = !dotnet, pe32
        |import = kernel32.dll!VirtualAlloc
        |version_info.ProductName = /WinRAR/i
        |dotnet_us = "a, b"
        |""".stripMargin).signatures.head
    assertEquals(sig.clauses.map(_.number), Seq(1, 2))
    assertEquals(sig.conditions.map(_.fullKey), Seq("requires", "import", "version_info.ProductName", "dotnet_us"))
    assertEquals(sig.conditions.head.values.map(v => (v.negated, v.text)), Seq((true, "dotnet"), (false, "pe32")))
    assertTrue(sig.conditions(2).values.head.isRegex)
    assertEquals(sig.conditions(3).values.map(_.text), Seq("a, b"))
  }

  @Test
  def conditionOnlySignature(): Unit = {
    val sig = parse("[lib]\ndotnet_string = Newtonsoft.Json").signatures.head
    assertFalse(sig.hasPattern)
  }

  @Test
  def errorsHaveLineAndColumn(): Unit = {
    assertError("[a]\npattern = 01 0G\nat = file", 2, 14, "incomplete byte")
    assertError("[a]\npattern = 01\nat = fil", 3, 6, "unknown location 'fil'")
    assertError("[a]\npattern = 01\nat = overlay + 0x10, eof + 4", 3, 26, "offsets after eof")
    assertError("[a]\npattern = 01\nat = overlay - 4", 3, 14, "negative offsets")
    assertError("[a]\npattern = 01\nat = overlay[0-4]", 3, 13, "only allowed with 'in'")
    assertError("[a]\npattern = 01\nin = overlay + 4", 3, 14, "only allowed with 'at'")
    assertError("[a]\npattern = 01\nin = eof[0-4]", 3, 11, "only takes a window size")
    assertError("[a]\npattern = 01\nin = datadir", 3, 6, "needs a data directory")
    assertError("[a]\npattern = 01\nin = datadir(NOPE)", 3, 14, "unknown data directory")
    assertError("[a]\npattern = 01\nin = file(x)", 3, 10, "takes no argument")
    assertError("[a]\npattern = 01\nat = file\nfoo = bar", 4, 1, "unknown key 'foo'")
    assertError("[a]\npattern = 01\nat = file\nlinker_version = 14", 4, 1, "not supported")
    assertError("[a]\npattern = 01", 2, 1, "has no location")
    assertError("[a]\nat = file", 1, 0, "without 'pattern'")
    assertError("[a]\npattern = 01\nat = file\npattern.3 = 02", 4, 1, "has no location")
    assertError("[a]\npattern = 01\nat = file\npattern.1 = 02\nat.1 = file", 4, 1, "clause numbers start at 2")
    assertError("[a]\npattern = 01\nat = file\nversion_info = x", 4, 1, "needs a key")
    assertError("[a]\npattern = E8 $$$$$$$$\nat = eof", 2, 11, "follow tokens")
    assertError("[a]\nrequires = dotnet, foo", 2, 20, "unknown requirement 'foo'")
    assertError("[a]\nrequires = /dotnet/", 2, 12, "regular expressions")
    assertError("[a]\nimport = kernel32.dll!", 2, 10, "dll!function")
    assertError("[a]\nsection = /UPX(/", 2, 11, "invalid regular expression")
    assertError("[a]\nsection = /UPX/x", 2, 16, "unknown regular expression flag")
    assertError("[a]\nsection = \"UPX", 2, 11, "unterminated quote")
    assertError("[a]\ntype = packer", 1, 0, "needs a pattern or a condition")
    assertError("pattern = 01", 1, 1, "expected a signature name")
    assertError("[]\npattern = 01\nat = file", 1, 0, "empty signature name")
    assertError("[a]\npattern = 01\nat = file\ntype = x\ntype = y", 5, 1, "duplicate 'type'")
  }

  @Test
  def lenientModeSkipsBrokenEntries(): Unit = {
    val db = SignatureDatabase.parse("[ok]\npattern = 01\nat = file\n\n[broken]\npattern = 0G\nat = file\n\n[ok2]\npattern = 02\nat = file",
      "test.sig", lenient = true)
    assertEquals(db.signatures.map(_.name), Seq("ok", "ok2"))
    assertEquals(db.warnings.size, 1)
    assertTrue(db.warnings.head.contains("test.sig:6"), db.warnings.head)
  }

  @Test
  def exactDuplicatesAreDropped(): Unit = {
    val db = parse("[a]\npattern = 01\nat = file\n\n[a]\npattern = 01\nat = file\n\n[a]\npattern = 02\nat = file")
    assertEquals(db.size, 2)
    assertEquals(db.warnings.size, 1)
  }

  private def roundTrip(db: SignatureDatabase): Unit = {
    val out = new StringWriter()
    SignatureDatabaseWriter.write(db, out, Seq("header"))
    val parsed = SignatureDatabase.parse(out.toString, "roundtrip")
    assertEquals(parsed.size, db.size)
    for ((a, b) <- db.signatures.zip(parsed.signatures)) assertTrue(a.sameAs(b), s"$a differs after writing")
  }

  @Test
  def writerRoundTripOfBundledDatabases(): Unit = {
    roundTrip(DefaultSignatures.packers)
    roundTrip(DefaultSignatures.installers)
    roundTrip(DefaultSignatures.fileTypes)
    roundTrip(DefaultSignatures.javaWrappers)
  }

  @Test
  def writerRoundTripOfAllFeatures(): Unit = {
    roundTrip(parse(
      """[all]
        |pattern = E8 $$$$$$$$ (55 | 56 57) [2-] aw'x' i'MZ' %& ** 4?
        |at = entrypoint, eof - 0x18
        |in = section(executable), resource(RT_RCDATA/*), eof[0x100]
        |pattern.2 = 01 02
        |at.2 = eof
        |requires = !dotnet
        |section = /^UPX/
        |version_info.ProductName = "a, b"
        |type = packer
        |x-note = test
        |""".stripMargin))
  }

  @Test
  def mergeKeepsOrder(): Unit = {
    val merged = SignatureDatabase.merge(parse("[a]\npattern = 01\nat = file"), parse("[b]\npattern = 02\nat = file"))
    assertEquals(merged.signatures.map(_.name), Seq("a", "b"))
  }
}
