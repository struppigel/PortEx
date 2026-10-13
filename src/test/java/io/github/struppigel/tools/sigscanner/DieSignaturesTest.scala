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
import io.github.struppigel.tools.sigscanner.perf.SyntheticFiles
import org.testng.Assert._
import org.testng.annotations.{AfterClass, Test}

import java.io.File
import scala.collection.JavaConverters._
import scala.io.Source

/**
 * Tests the signatures converted from Detect It Easy, see die.sig.
 */
class DieSignaturesTest {

  private val source = "https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/"

  private lazy val scanner = new SignatureScanner(DefaultSignatures.die)

  private lazy val files = new SyntheticFiles

  @AfterClass(alwaysRun = true)
  def deleteFiles(): Unit = files.delete()

  private def bytes(values: Int*): Array[Byte] = values.map(_.toByte).toArray

  private def names(file: File): IndexedSeq[String] =
    scanner._scan(PELoader.loadPE(file), LocationKind.peDefaults().asScala.toSet).map(_.getName).distinct

  @Test
  def containsTheLicense(): Unit = {
    val in = getClass.getResourceAsStream("/data/signatures/die.sig")
    val text = try Source.fromInputStream(in, "UTF-8").mkString finally in.close()
    assertTrue(text.contains("MIT License"))
    assertTrue(text.contains("Copyright (c) 2012-2026 hors<horsicq@gmail.com>"))
    assertTrue(text.contains("The above copyright notice and this permission notice shall be included in all"))
  }

  @Test
  def everyEntryNamesItsSourceAndType(): Unit = {
    val types = Set("packer", "protector", "cryptor", "joiner", "installer", "sfx")
    for (sig <- DefaultSignatures.die.signatures) {
      val url = sig.metadata.getOrElse("url", "")
      assertTrue(url.startsWith(source) && url.endsWith(".sg"), sig.toString)
      assertTrue(sig.getTypes.asScala.nonEmpty && sig.getTypes.asScala.forall(types), sig.toString)
    }
  }

  @Test
  def followsCallsAtTheEntryPoint(): Unit = {
    // call to 0x10 bytes after the call, the pattern continues at the target
    val code = bytes(0xE8, 0x10, 0, 0, 0) ++ Array.fill[Byte](0x10)(0xCC.toByte) ++
      bytes(0x5D, 0x81, 0xED, 0x11, 0x22, 0x33, 0x44, 0x60, 0xE8, 0, 0, 0, 0, 0x58, 0x83, 0xC0, 0x05, 0xFF, 0xE0)
    assertTrue(names(files.pe("tpp", code, 0x200, Array())).contains("TPP Pack"))
    // without the call target the bytes are just in a row and do not match
    val inARow = bytes(0xE8, 0, 0, 0, 0x10) ++ code.drop(5 + 0x10)
    assertFalse(names(files.pe("tpp-no-call", inARow, 0x200, Array())).contains("TPP Pack"))
  }

  @Test
  def versionBytesAfterTheEntryPoint(): Unit = {
    val code = bytes(0x9C, 0x60, 0xE8, 0x02, 0, 0, 0, 0x33, 0xC0, 0x8B, 0xC4, 0x83, 0xC0, 0x04, 0x93, 0x8B, 0xE3,
      0x8B, 0x5B, 0xFC, 0x81, 0xEB, 0, 0, 0, 0, 0x87, 0xDD, 0x83, 0xBD)
    val found = names(files.pe("pebundle", code, 0x200, Array())).filter(_.startsWith("PEBundle"))
    // the section of the synthetic file is .text, not pebundle
    assertTrue(found.contains("PEBundle 2.44 [modified]"), found.toString)
    assertFalse(found.exists(n => n.contains("0.2-2.0X") || n.contains("3.XX") || !n.endsWith("[modified]")), found.toString)
  }

  @Test
  def samples(): Unit = {
    def sample(name: String): IndexedSeq[String] = names(new File(TestreportsReader.RESOURCE_DIR + "/testfiles/" + name))
    assertTrue(sample("upx.exe").contains("UPX"))
    assertTrue(sample("Lab18-04").contains("ASPack 2.12-2.42"))
    assertTrue(sample("nsis").contains("Nullsoft Scriptable Install System"))
    assertTrue(sample("7zipsfx").contains("7-Zip"))
    assertTrue(sample("WinRar.exe").contains("WinRAR"))
    assertTrue(sample("pyinstaller").contains("PyInstaller"))
    assertTrue(sample("inno_with_stub").contains("Inno Setup Module [with stub]"))
    assertTrue(sample("upx_vmp").contains("VMProtect 2.XX-3.XX"))
    assertEquals(sample("HelloWorld.exe"), IndexedSeq())
  }

  @Test
  def entryPointAndOverlay(): Unit = {
    val code = bytes(0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0x64, 0xA1, 0, 0, 0, 0, 0x50,
      0x64, 0x89, 0x25, 0, 0, 0, 0, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x57, 0x89, 0x65, 0xE8, 0xFF, 0x15)
    val overlay = "wwgT)".getBytes("US-ASCII") ++ Array.fill[Byte](0x20)(0)
    assertTrue(names(files.pe("clickteam", code, 0x200, overlay)).contains("ClickTeam"))
    assertFalse(names(files.pe("clickteam-no-overlay", code, 0x200, Array())).contains("ClickTeam"))
  }
}
