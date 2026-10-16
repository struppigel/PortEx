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

import io.github.struppigel.parser.AnalysisInterruptedException
import org.testng.Assert._
import org.testng.annotations.Test

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, NoSuchFileException, NotDirectoryException, Path}
import java.util.Comparator
import scala.collection.JavaConverters._
import scala.collection.immutable.ListMap

class SignatureFolderTest {

  private def withFolder(test: Path => Unit): Unit = {
    val folder = Files.createTempDirectory("portex-sig-folder")
    try test(folder)
    finally {
      val paths = Files.walk(folder)
      try paths.sorted(Comparator.reverseOrder[Path]()).iterator().asScala.foreach(p => Files.deleteIfExists(p))
      finally paths.close()
    }
  }

  private def write(folder: Path, name: String, text: String): Unit = {
    val file = folder.resolve(name)
    Files.createDirectories(file.getParent)
    Files.write(file, text.getBytes(StandardCharsets.UTF_8))
  }

  private def entry(name: String, pattern: String = "01 02"): String =
    s"[$name]\npattern = $pattern\nat = file\n"

  @Test
  def loadsTheSigFilesSortedByName(): Unit = withFolder { folder =>
    write(folder, "b.sig", entry("B"))
    write(folder, "A.SIG", entry("A"))
    write(folder, "c.txt", entry("C"))
    write(folder, ".hidden.sig", entry("Hidden"))
    write(folder, "sub/d.sig", entry("D"))
    val db = SignatureDatabase.loadFolder(folder.toFile)
    assertEquals(db.signatures.map(_.name), Vector("A", "B"))
    assertEquals(db.signatures.map(_.source), Vector("A.SIG:1", "b.sig:1"))
    assertEquals(db.signatures.map(_.getDatabaseName), Vector("A.SIG", "b.sig"))
    assertTrue(db.warnings.isEmpty, db.warnings.toString)
    assertEquals(SignatureDatabase.listFolder(folder.toFile).asScala.map(_.getName), Seq("A.SIG", "b.sig"))
  }

  @Test
  def emptyFolderHasNoSignatures(): Unit = withFolder { folder =>
    val db = SignatureDatabase.loadFolder(folder.toFile, true)
    assertEquals(db.size, 0)
    assertTrue(db.warnings.isEmpty)
  }

  @Test
  def missingFolderThrows(): Unit = withFolder { folder =>
    val missing = folder.resolve("missing").toFile
    expectThrows(classOf[NoSuchFileException], () => SignatureDatabase.loadFolder(missing))
    expectThrows(classOf[NoSuchFileException], () => SignatureDatabase.loadFolder(missing, true))
  }

  @Test
  def fileInsteadOfFolderThrows(): Unit = withFolder { folder =>
    write(folder, "a.sig", entry("A"))
    val file = folder.resolve("a.sig").toFile
    expectThrows(classOf[NotDirectoryException], () => SignatureDatabase.loadFolder(file))
    expectThrows(classOf[NotDirectoryException], () => SignatureDatabase.loadFolder(file, true))
  }

  @Test
  def malformedEntriesAreSkippedWhenLenient(): Unit = withFolder { folder =>
    write(folder, "a.sig", entry("A"))
    write(folder, "broken.sig", "[Broken]\npattern = 0G\nat = file\n\n" + entry("Fine"))
    val db = SignatureDatabase.loadFolder(folder.toFile, true)
    assertEquals(db.signatures.map(_.name), Vector("A", "Fine"))
    assertEquals(db.warnings.size, 1, db.warnings.toString)
    assertTrue(db.warnings.head.startsWith("broken.sig:2:"), db.warnings.head)
    assertTrue(db.warnings.head.endsWith("signature skipped"), db.warnings.head)
  }

  @Test
  def malformedEntriesThrowWhenStrict(): Unit = withFolder { folder =>
    write(folder, "a.sig", entry("A"))
    write(folder, "broken.sig", "[Broken]\npattern = 0G\nat = file\n")
    val e = expectThrows(classOf[SignatureDatabaseException], () => SignatureDatabase.loadFolder(folder.toFile))
    assertEquals((e.source, e.line), ("broken.sig", 2))
  }

  @Test
  def duplicatesInDifferentFilesAreSkipped(): Unit = withFolder { folder =>
    write(folder, "a.sig", entry("Same") + "\n" + entry("Other name"))
    write(folder, "b.sig", "; the same signature again\n" + entry("Same") + "\n" + entry("Same", "01 03"))
    val db = SignatureDatabase.loadFolder(folder.toFile, true)
    assertEquals(db.signatures.map(_.source), Vector("a.sig:1", "a.sig:5", "b.sig:6"))
    assertEquals(db.warnings, Vector("b.sig:2: duplicate of the signature [Same] in a.sig:1, skipped"))
  }

  @Test
  def interruptionStopsLoading(): Unit = withFolder { folder =>
    write(folder, "a.sig", entry("A"))
    Thread.currentThread().interrupt()
    try expectThrows(classOf[AnalysisInterruptedException], () => SignatureDatabase.loadFolder(folder.toFile, true))
    finally Thread.interrupted()
  }

  @Test
  def loadedSignaturesMatch(): Unit = withFolder { folder =>
    write(folder, "mine.sig", "[My magic]\npattern = 'MAGIC'\nin = file\n")
    val scanner = new SignatureScanner(SignatureDatabase.loadFolder(folder.toFile))
    val matches = scanner._scanBytes("xxMAGICxx".getBytes(StandardCharsets.US_ASCII))
    assertEquals(matches.map(m => (m.getName, m.getOffset, m.getSignature.getDatabaseName)),
      Vector(("My magic", 2L, "mine.sig")))
  }

  @Test
  def databaseNameKeepsPathsWithColons(): Unit = {
    def databaseName(source: String): String =
      new Signature("A", Vector.empty, Vector.empty, ListMap.empty, source).getDatabaseName
    assertEquals(databaseName("C:\\sigs\\a.sig:12"), "C:\\sigs\\a.sig")
    assertEquals(databaseName("C:\\sigs\\a.sig"), "C:\\sigs\\a.sig")
    assertEquals(databaseName("a.sig:"), "a.sig:")
    assertEquals(SignatureDatabase.parse(entry("A"), "C:\\sigs\\a.sig").signatures.head.getDatabaseName, "C:\\sigs\\a.sig")
  }
}
