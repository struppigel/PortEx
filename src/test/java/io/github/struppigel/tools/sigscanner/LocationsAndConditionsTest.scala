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
import io.github.struppigel.parser.optheader.StandardFieldEntryKey
import io.github.struppigel.parser.{PEData, PELoader}
import io.github.struppigel.tools.sigscanner.engine.RegionResolver
import io.github.struppigel.tools.sigscanner.legacy.LegacySignatureScanner
import org.testng.Assert._
import org.testng.annotations.Test

import java.io.File

/**
 * Tests the scan locations and conditions on files of the test corpus.
 */
class LocationsAndConditionsTest {

  private def pe(name: String): PEData = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/testfiles/" + name))

  private def regions(name: String, location: String): List[(String, Long, Long)] = {
    val data = pe(name)
    val resolver = new RegionResolver(data.getFile.length, name, data)
    resolver.resolve(LocationSpec.parseList(location, search = true).head).map(r => (r.label, r.start, r.end)).toList
  }

  @Test
  def headerLocations(): Unit = {
    assertEquals(regions("HelloWorld.exe", "msdos_header"), List(("msdos_header", 0L, 0x40L)))
    assertEquals(regions("HelloWorld.exe", "msdos_stub"), List(("msdos_stub", 0x40L, 0x80L)))
    assertEquals(regions("HelloWorld.exe", "headers"), List(("headers", 0L, 0x200L)))
    assertEquals(regions("Lab11-02dll", "rich_header"), List(("rich_header", 0x80L, 0xbcL)))
    assertEquals(regions("HelloWorld.exe", "rich_header"), Nil)
  }

  @Test
  def entryPointEndsWithItsSection(): Unit = {
    assertEquals(regions("HelloWorld.exe", "entrypoint"), List(("entrypoint", 0x88eL, 0xa00L)))
  }

  @Test
  def entryPointEqualsLegacyEntryPoint(): Unit = {
    for (name <- List("HelloWorld.exe", "Lab11-02dll", "upx.exe", "WinRar.exe", "nsis", "inno_with_stub", "pyinstaller", "batch2exe")) {
      val data = pe(name)
      val legacy = new LegacySignatureScanner(Nil).maybeGetEntryPoint(data.getFile)
      val resolver = new RegionResolver(data.getFile.length, name, data)
      assertEquals(resolver.entryPoint.map(_._1), legacy, name)
    }
  }

  @Test
  def overlayAndImage(): Unit = {
    assertEquals(regions("WinRar.exe", "overlay"), List(("overlay", 0x18600L, 0x12516aL)))
    assertEquals(regions("WinRar.exe", "image"), List(("image", 0L, 0x18600L)))
    assertEquals(regions("HelloWorld.exe", "overlay"), Nil)
    assertEquals(regions("HelloWorld.exe", "image"), List(("image", 0L, 0x1200L)))
  }

  @Test
  def sections(): Unit = {
    assertEquals(regions("HelloWorld.exe", "section").map(_._1), List("section(.text)", "section(.rsrc)", "section(.reloc)"))
    assertEquals(regions("HelloWorld.exe", "section(.rsrc)"), List(("section(.rsrc)", 0xa00L, 0x1000L)))
    assertEquals(regions("HelloWorld.exe", "section(#0)").map(_._1), List("section(.text)"))
    assertEquals(regions("HelloWorld.exe", "section(#-1)").map(_._1), List("section(.reloc)"))
    assertEquals(regions("HelloWorld.exe", "section(entrypoint)").map(_._1), List("section(.text)"))
    assertEquals(regions("HelloWorld.exe", "section(executable)").map(_._1), List("section(.text)"))
    assertEquals(regions("HelloWorld.exe", "section(code)").map(_._1), List("section(.text)"))
    assertEquals(regions("upx.exe", "section(UPX*)").map(_._1), List("section(UPX0)", "section(UPX1)").filter(l =>
      regions("upx.exe", "section").map(_._1).contains(l)))
    assertEquals(regions("HelloWorld.exe", "section(.nothere)"), Nil)
  }

  @Test
  def resources(): Unit = {
    assertEquals(regions("HelloWorld.exe", "resource").size, 2)
    assertEquals(regions("HelloWorld.exe", "resource(RT_MANIFEST)"), List(("resource(RT_MANIFEST/1/0)", 0xd74L, 0xf5eL)))
    assertEquals(regions("HelloWorld.exe", "manifest"), regions("HelloWorld.exe", "resource(RT_MANIFEST)"))
    assertEquals(regions("HelloWorld.exe", "resource(rt_version/1)").map(_._2), List(0xa90L))
    assertEquals(regions("HelloWorld.exe", "resource(16)").map(_._2), List(0xa90L))
    assertEquals(regions("HelloWorld.exe", "resource(*/1/0)").size, 2)
    assertEquals(regions("HelloWorld.exe", "resource(RT_VERSION/2)"), Nil)
  }

  @Test
  def exportsAndDataDirectories(): Unit = {
    assertEquals(regions("Lab11-02dll", "export"), List(("export(installer)", 0x158bL, 0x2000L)))
    assertEquals(regions("Lab11-02dll", "export(inst*)").size, 1)
    assertEquals(regions("Lab11-02dll", "export(other)"), Nil)
    assertEquals(regions("HelloWorld.exe", "datadir(IMPORT_TABLE)"), List(("datadir(IMPORT_TABLE)", 0x83aL, 0x889L)))
    assertEquals(regions("nsis", "certificate"), List(("certificate", 0x71ee8L, 0x72980L)))
    assertEquals(regions("nsis", "datadir(CERTIFICATE_TABLE)").map(_._2), List(0x71ee8L))
  }

  @Test
  def dotnetLocations(): Unit = {
    assertEquals(regions("HelloWorld.exe", "dotnet"), List(("dotnet", 0x264L, 0x744L)))
    assertEquals(regions("HelloWorld.exe", "dotnet_stream(#US)"), List(("dotnet_stream(#US)", 0x640L, 0x65cL)))
    assertEquals(regions("HelloWorld.exe", "dotnet_stream(#Strings)").map(_._2), List(0x454L))
    assertEquals(regions("Lab11-02dll", "dotnet"), Nil)
  }

  @Test
  def userStringSignature(): Unit = {
    val db = SignatureDatabase.parse("[hello]\npattern = w'Hello World!'\nin = dotnet_stream(#US)", "test")
    val m = new SignatureScanner(db)._scan(pe("HelloWorld.exe"), LocationKind.values().toSet)
    assertEquals(m.map(_.getName), Seq("hello"))
    assertEquals(m.head.getLocationLabel, "dotnet_stream(#US)")
  }

  @Test
  def onlyRequestedLocationsAreResolved(): Unit = {
    val (_, resolver) = DefaultSignatures.peScanner.scanDetailed(pe("HelloWorld.exe"), Set(LocationKind.ENTRY_POINT))
    assertEquals(resolver.resolvedKinds.toSet, Set(LocationKind.ENTRY_POINT))
  }

  private def conditionMatches(name: String, conditions: String*): Boolean = {
    val db = SignatureDatabase.parse(("[c]" +: conditions).mkString("\n"), "test")
    new SignatureScanner(db)._scan(pe(name), Set(LocationKind.METADATA)).nonEmpty
  }

  @Test
  def requiresFlags(): Unit = {
    assertTrue(conditionMatches("HelloWorld.exe", "requires = dotnet, pe32, console, x86"))
    assertFalse(conditionMatches("HelloWorld.exe", "requires = native"))
    assertTrue(conditionMatches("Lab11-02dll", "requires = native, dll, rich, !overlay, !signed"))
    assertTrue(conditionMatches("nsis", "requires = overlay, signed, !dll"))
    assertFalse(conditionMatches("nsis", "requires = pe32+"))
    assertFalse(conditionMatches("Lab11-02dll", "requires = dotnet"))
  }

  @Test
  def sectionAndImportConditions(): Unit = {
    assertTrue(conditionMatches("upx.exe", "section = UPX0"))
    assertTrue(conditionMatches("upx.exe", "section = /^UPX\\d$/"))
    assertFalse(conditionMatches("upx.exe", "section = upx0"))
    assertTrue(conditionMatches("upx.exe", "section = !.text"))
    assertTrue(conditionMatches("Lab11-02dll", "import = kernel32.dll"))
    assertTrue(conditionMatches("Lab11-02dll", "import = KERNEL32.DLL!VirtualProtect, advapi32.dll!RegSetValueExA"))
    assertFalse(conditionMatches("Lab11-02dll", "import = kernel32.dll!virtualprotect"))
    assertTrue(conditionMatches("Lab11-02dll", "import = /^msvcrt\\.dll!str/"))
    assertTrue(conditionMatches("HelloWorld.exe", "import = mscoree.dll!_CorExeMain"))
    assertFalse(conditionMatches("HelloWorld.exe", "import = !mscoree.dll"))
  }

  @Test
  def exportResourceAndVersionConditions(): Unit = {
    assertTrue(conditionMatches("Lab11-02dll", "export = installer"))
    assertFalse(conditionMatches("Lab11-02dll", "export = Installer"))
    assertTrue(conditionMatches("HelloWorld.exe", "resource = RT_MANIFEST"))
    assertTrue(conditionMatches("HelloWorld.exe", "resource = RT_VERSION/1/0"))
    assertFalse(conditionMatches("HelloWorld.exe", "resource = RT_ICON"))
    assertTrue(conditionMatches("upx.exe", "version_info.InternalName = upx.exe"))
    assertTrue(conditionMatches("upx.exe", "version_info.companyname = /UPX Team/"))
    assertFalse(conditionMatches("upx.exe", "version_info.InternalName = upx"))
    assertFalse(conditionMatches("Lab11-02dll", "version_info.InternalName = /./"))
  }

  @Test
  def dotnetConditions(): Unit = {
    assertTrue(conditionMatches("HelloWorld.exe", "dotnet_us = Hello World!"))
    assertTrue(conditionMatches("HelloWorld.exe", "dotnet_us = \"Hello World!\""))
    assertFalse(conditionMatches("HelloWorld.exe", "dotnet_us = Hello World"))
    assertTrue(conditionMatches("HelloWorld.exe", "dotnet_string = mscorlib"))
    assertTrue(conditionMatches("HelloWorld.exe", "dotnet_string = /^Hello/"))
    assertTrue(conditionMatches("HelloWorld.exe", "dotnet_type = /\\.Program$/"))
    assertFalse(conditionMatches("Lab11-02dll", "dotnet_string = mscorlib"))
  }

  @Test
  def conditionsAndPatternsCombined(): Unit = {
    val db = SignatureDatabase.parse(
      """[UPX like]
        |pattern = 53 56 57 55 48 8D 35
        |at = entrypoint
        |section = UPX1
        |
        |[UPX wrong section]
        |pattern = 53 56 57 55 48 8D 35
        |at = entrypoint
        |section = .text
        |""".stripMargin, "test")
    val names = new SignatureScanner(db)._scan(pe("upx.exe"), LocationKind.values().toSet).map(_.getName)
    assertEquals(names, Seq("UPX like"))
  }
}
