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

import java.nio.charset.StandardCharsets
import scala.io.Source

class DefaultSignaturesTest {

  @Test
  def bundledDatabasesLoadWithoutWarnings(): Unit = {
    assertEquals(DefaultSignatures.packers.size, 1517)
    assertEquals(DefaultSignatures.installers.size, 88)
    assertEquals(DefaultSignatures.fileTypes.size, 407)
    assertEquals(DefaultSignatures.javaWrappers.size, 11)
    assertEquals(DefaultSignatures.pe.size, 1517 + 88 + 407)
    for (db <- List(DefaultSignatures.packers, DefaultSignatures.installers, DefaultSignatures.fileTypes, DefaultSignatures.javaWrappers))
      assertTrue(db.warnings.isEmpty, db.warnings.mkString("\n"))
  }

  @Test
  def bundledSignaturesAreNotSlow(): Unit = {
    for (scanner <- List(DefaultSignatures.peScanner, DefaultSignatures.fileTypeScanner, DefaultSignatures.javaWrapperScanner))
      assertTrue(scanner.plan.warnings.isEmpty, scanner.plan.warnings.mkString("\n"))
  }

  @Test
  def databaseFilesReferToTheHelpFile(): Unit = {
    for (name <- List("packers.sig", "installers.sig", "filetypes.sig", "javawrappers.sig")) {
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
}
