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

import io.github.struppigel.parser.sections.clr.UserStringsHeap
import org.testng.Assert._
import org.testng.annotations.Test

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import scala.collection.JavaConverters._
import scala.io.Source

class DefaultSignaturesTest {

  @Test
  def bundledDatabasesLoadWithoutWarnings(): Unit = {
    assertEquals(DefaultSignatures.packers.size, 1517)
    assertEquals(DefaultSignatures.installers.size, 88)
    assertEquals(DefaultSignatures.fileTypes.size, 391)
    assertEquals(DefaultSignatures.javaWrappers.size, 11)
    assertEquals(DefaultSignatures.die.size, 1705)
    assertEquals(DefaultSignatures.pe.size, 1517 + 88 + 391 + 1705)
    for (db <- List(DefaultSignatures.packers, DefaultSignatures.installers, DefaultSignatures.fileTypes,
      DefaultSignatures.javaWrappers, DefaultSignatures.die))
      assertTrue(db.warnings.isEmpty, db.warnings.mkString("\n"))
  }

  @Test
  def bundledSignaturesAreNotSlow(): Unit = {
    for (scanner <- List(DefaultSignatures.fileTypeScanner, DefaultSignatures.javaWrapperScanner))
      assertTrue(scanner.plan.warnings.isEmpty, scanner.plan.warnings.mkString("\n"))
    // the IL patterns of these Detect It Easy rules search short literals in the first section of .NET files
    val weak = DefaultSignatures.peScanner.plan.warnings
    assertTrue(weak.forall(_.contains("by the short literal")), weak.mkString("\n"))
    assertEquals(weak.map(w => w.substring(w.indexOf('[') + 1, w.lastIndexOf("] pattern"))).toSet,
      Set("ArmDot", "EazFuscator", ".NET Reactor 6.X [Control Flow]", "Robust Obfuscator"), weak.mkString("\n"))
  }

  @Test
  def databaseFilesReferToTheHelpFile(): Unit = {
    for (name <- List("packers.sig", "installers.sig", "filetypes.sig", "javawrappers.sig", "die.sig")) {
      val in = getClass.getResourceAsStream("/data/signatures/" + name)
      val head = try Source.fromInputStream(in, "UTF-8").getLines().take(5).mkString("\n") finally in.close()
      assertTrue(head.contains("docs/SIGNATURES.md"), name)
    }
  }

  @Test
  def userStringsHeap(): Unit = {
    def entry(s: String): Array[Byte] = {
      val utf16 = s.getBytes(StandardCharsets.UTF_16LE)
      val length = utf16.length + 1
      val header = if (length < 0x80) Array(length.toByte) else Array((0x80 | (length >> 8)).toByte, length.toByte)
      header ++ utf16 :+ 0.toByte
    }
    val long = "x" * 100
    val bytes = Array[Byte](0) ++ entry("Hello World!") ++ entry(long) ++ entry("é")
    assertEquals(UserStringsHeap(bytes).strings, IndexedSeq("Hello World!", long, "é"))
    // a truncated entry ends the parsing
    assertEquals(UserStringsHeap(bytes.dropRight(2)).strings, IndexedSeq("Hello World!", long))
  }

  @Test
  def scanFileFindsTheFileTypeOfNonPEFiles(): Unit = {
    val file = File.createTempFile("portex-defaultsignatures-zip", ".zip")
    try {
      Files.write(file.toPath, Array[Byte](0x50, 0x4B, 0x03, 0x04) ++ new Array[Byte](0x40))
      val matches = DefaultSignatures.scanFile(file).asScala
      assertTrue(matches.exists(_.getName == "PKZIP archive_1"), matches.mkString("\n"))
      for (m <- matches)
        assertTrue(m.getLocationKind == LocationKind.FILE || m.getLocationKind == LocationKind.EOF, m.toString)
      val fileTypes = FileTypeScanner.scan(file).asScala.map(_.getName).toSet
      assertTrue(fileTypes.subsetOf(matches.map(_.getName).toSet))
    } finally file.delete()
  }

  @Test
  def scanFileOfAnEmptyFileFindsNothing(): Unit = {
    val file = File.createTempFile("portex-defaultsignatures-empty", ".bin")
    try assertTrue(DefaultSignatures.scanFile(file).isEmpty)
    finally file.delete()
  }
}
