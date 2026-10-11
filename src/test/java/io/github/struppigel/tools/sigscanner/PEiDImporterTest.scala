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

import java.nio.charset.Charset

class PEiDImporterTest {

  private def importText(text: String, options: PEiDImportOptions = PEiDImportOptions.Default): SignatureDatabase =
    PEiDImporter.parse(text, "userdb.txt", options)

  private def single(text: String, options: PEiDImportOptions = PEiDImportOptions.Default): Signature = {
    val db = importText(text, options)
    assertEquals(db.size, 1, db.warnings.mkString("\n"))
    db.signatures.head
  }

  private def locations(sig: Signature): Seq[String] = sig.clauses.head.locations.map(_.source)

  @Test
  def entryPointSignatures(): Unit = {
    val sig = single("[UPX -&gt; www.upx.sourceforge.net]\nsignature = 60 be ?? ?? ?? ?? 8d be\nep_only = true")
    assertEquals(sig.name, "UPX -> www.upx.sourceforge.net")
    assertEquals(sig.clauses.head.pattern.source, "60 BE ?? ?? ?? ?? 8D BE")
    assertEquals(locations(sig), Seq("entrypoint"))
    assertEquals(sig.source, "userdb.txt:1")
  }

  @Test
  def otherSignaturesUseTheBaseLocation(): Unit = {
    assertEquals(locations(single("[a]\nsignature = 01 02\nep_only = false")), Seq("file"))
    assertEquals(locations(single("[a]\nsignature = 01 02")), Seq("file"))
    assertEquals(locations(single("[a]\nsignature = 01 02", PEiDImportOptions(base = "overlay"))), Seq("overlay"))
    assertTrue(single("[a]\nsignature = 01 02", PEiDImportOptions(base = "overlay")).clauses.head.locations.head.mode.isInstanceOf[Search])
    assertEquals(single("[a]\nsignature = 01 02", PEiDImportOptions(base = "overlay", anchoredBase = true)).clauses.head.locations.head.mode, Anchored(0))
  }

  @Test
  def offsets(): Unit = {
    assertEquals(locations(single("[a]\nsignature = 01 02\nat_offset = 19A0", PEiDImportOptions(base = "overlay"))), Seq("overlay + 0x19A0"))
    assertEquals(locations(single("[a]\nsignature = 01 02\nuntil_offset = 100", PEiDImportOptions(base = "overlay"))), Seq("overlay[0x0-0x100]"))
    assertEquals(locations(single("[a]\nsignature = 01 02\nep_only = true\nat_offset = 4")), Seq("entrypoint + 0x4"))
    assertEquals(locations(single("[a]\nsignature = 01 02\nsection_start_only = true")), Seq("section"))
    assertEquals(locations(single("[a]\nsignature = 01 02\nep_only = false\nin_section = 1")), Seq("section(entrypoint)"))
  }

  @Test
  def leadingWildcardsAsOffset(): Unit = {
    val options = PEiDImportOptions(base = "overlay", anchoredBase = true, leadingWildcardsAsOffset = true)
    val sig = single("[Inno]\nsignature = ?? ?? ?? ?? 'Inno'", options)
    assertEquals(sig.clauses.head.pattern.source, "'Inno'")
    assertEquals(locations(sig), Seq("overlay + 0x4"))
    // the default keeps the pattern as it is
    assertEquals(single("[Inno]\nsignature = ?? ?? 'Inno'\nep_only = true").clauses.head.pattern.source, "?? ?? 'Inno'")
  }

  @Test
  def dotNetFlag(): Unit = {
    val sig = single("[NET Reactor]\nsignature = e8 ?? ?? ?? ?? e9\nep_only = true\nis_dot_net = true")
    assertEquals(sig.conditions.map(_.toString), Seq("requires = dotnet"))
    assertEquals(single("[x]\nsignature = 01 02\nis_dot_net = false").conditions.map(_.toString), Seq("requires = !dotnet"))
  }

  @Test
  def quotedStrings(): Unit = {
    assertEquals(single("[a]\nsignature = EF BE AD DE 'Null' ?? 'oftInst'").clauses.head.pattern.source,
      "EF BE AD DE 'Null' ?? 'oftInst'")
    // characters that need escaping in the new format become hex bytes
    assertEquals(single("[a]\nsignature = 'C:\\x'").clauses.head.pattern.source, "43 3A 5C 78")
    // only hex digits and ? are significant outside of quotes
    assertEquals(single("[a]\nsignature = 4d5a-90").clauses.head.pattern.source, "4D 5A 90")
  }

  @Test
  def malformedEntriesAreSkipped(): Unit = {
    val db = importText("[odd]\nsignature = 4D 5\n\n[ok]\nsignature = 4D 5A\n\n[empty]\nep_only = true")
    assertEquals(db.signatures.map(_.name), Seq("ok"))
    assertEquals(db.warnings.size, 2, db.warnings.mkString("\n"))
  }

  @Test
  def decodesLinesAsUtf8OrWindows1252(): Unit = {
    val bytes = "[UPX-SCRAMBLER 3.06 -> ".getBytes("UTF-8") ++
      "\u00A9OnT\u00AEoL]".getBytes(Charset.forName("windows-1252")) ++
      "\n[\u00E9t\u00E9]\n".getBytes("UTF-8")
    val text = PEiDImporter.decode(bytes)
    assertTrue(text.contains("\u00A9OnT\u00AEoL"))
    assertTrue(text.contains("[\u00E9t\u00E9]"))
  }
}
