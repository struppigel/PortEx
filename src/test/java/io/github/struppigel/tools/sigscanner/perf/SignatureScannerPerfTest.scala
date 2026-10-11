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
package io.github.struppigel.tools.sigscanner.perf

import io.github.struppigel.parser.{PEData, PELoader, PESignature}
import io.github.struppigel.tools.sigscanner._
import io.github.struppigel.tools.sigscanner.legacy.{LegacyScans, LegacySignatureScanner}
import io.github.struppigel.tools.sigscanner.perf.PerfHarness._
import org.testng.Assert.assertTrue
import org.testng.SkipException
import org.testng.annotations.{AfterClass, BeforeClass, Test}

import java.io.File
import java.nio.charset.StandardCharsets
import scala.collection.JavaConverters._
import scala.collection.mutable.ArrayBuffer

/**
 * Compares the speed of the signature scanner with the PortEx 5 scanner.
 * The new scanner must not be slower in any scenario.
 * <p>
 * Excluded from the default test run, run with: test.ps1 -Perf
 */
class SignatureScannerPerfTest {

  private var files: SyntheticFiles = _
  private val corpus = new File("portextestfiles/testfiles")

  private def assertNotSlower(r: Result, maxRatio: Double = MaxRatio): Unit =
    assertTrue(r.ratio <= maxRatio, f"${r.name}: new scanner is slower, ratio ${r.ratio}%.3f > $maxRatio")

  private def ascii(s: String): Array[Byte] = s.getBytes(StandardCharsets.ISO_8859_1)

  /** UPX 2.90 entry point as in packers.sig */
  private val upxEntryPoint: Array[Byte] = ("60 BE 00 10 40 00 8D BE 00 F0 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 " +
    "01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB")
    .split(" ").map(Integer.parseInt(_, 16).toByte)

  private lazy val corpusPEs: List[File] = {
    if (!corpus.isDirectory) throw new SkipException("test corpus not available")
    corpus.listFiles().filter(f => f.isFile && new PESignature(f).exists()).sortBy(_.getName).toList
  }

  @BeforeClass(groups = Array("performance"))
  def createFiles(): Unit = files = new SyntheticFiles

  @AfterClass(groups = Array("performance"), alwaysRun = true)
  def deleteFiles(): Unit = {
    if (files != null) files.delete()
    println()
    println("Signature scanner performance, PortEx 5 (legacy) vs. PortEx 6 (new):")
    summary.foreach(println)
  }

  /** runs the ColdLoadProbe in a fresh JVM and returns the measured nanoseconds */
  private def probe(args: String*): Double = {
    val java = new File(System.getProperty("java.home"), "bin" + File.separator +
      (if (System.getProperty("os.name").toLowerCase.contains("win")) "java.exe" else "java")).getAbsolutePath
    val command = Seq(java, "-cp", System.getProperty("java.class.path"),
      "io.github.struppigel.tools.sigscanner.perf.ColdLoadProbe") ++ args
    val process = new ProcessBuilder(command: _*).redirectErrorStream(true).start()
    val output = new String(readAll(process.getInputStream), StandardCharsets.UTF_8)
    process.waitFor()
    output.trim.linesIterator.toList.last.split(" ")(0).toDouble
  }

  /** compares legacy and new in fresh JVMs, alternating, 7 runs each */
  private def coldCompare(name: String, legacyArgs: Seq[String], newArgs: Seq[String]): Result = {
    // the first runs warm up the file system cache
    probe(legacyArgs: _*)
    probe(newArgs: _*)
    val legacy = ArrayBuffer[Double]()
    val current = ArrayBuffer[Double]()
    for (i <- 0 until 7) {
      if (i % 2 == 0) { legacy += probe(legacyArgs: _*); current += probe(newArgs: _*) }
      else { current += probe(newArgs: _*); legacy += probe(legacyArgs: _*) }
    }
    report(Result(name, median(legacy), median(current)))
  }

  @Test(groups = Array("performance"))
  def coldDatabaseLoad(): Unit =
    assertNotSlower(coldCompare("1a load and compile all databases, fresh JVM", Seq("legacy"), Seq("new")), MaxFreshJvmRatio)

  @Test(groups = Array("performance"))
  def coldSingleFile(): Unit = {
    // a single file analysis in a fresh JVM, as with one PortexAnalyzer call per file
    val file = corpusPEs.find(_.getName == "WinRar.exe").getOrElse(corpusPEs.head)
    val path = file.getAbsolutePath
    assertNotSlower(coldCompare(s"1d all PEData signatures of ${file.getName}, fresh JVM",
      Seq("legacy-e2e", path), Seq("new-e2e", path)), MaxFreshJvmRatio)
  }

  private def readAll(in: java.io.InputStream): Array[Byte] =
    Stream.continually(in.read()).takeWhile(_ != -1).map(_.toByte).toArray

  @Test(groups = Array("performance"))
  def warmDatabaseLoad(): Unit = {
    val r = compareSimple("1b load and compile all databases, warm JVM", warmups = 3, runs = 9) {
      ColdLoadProbe.loadLegacy()
    } {
      val packers = SignatureDatabase.loadResource("/data/signatures/packers.sig")
      val installers = SignatureDatabase.loadResource("/data/signatures/installers.sig")
      val fileTypes = SignatureDatabase.loadResource("/data/signatures/filetypes.sig")
      val javaWrappers = SignatureDatabase.loadResource("/data/signatures/javawrappers.sig")
      ColdLoadProbe.compile(List(new SignatureScanner(SignatureDatabase.merge(packers, installers, fileTypes)),
        new SignatureScanner(fileTypes), new SignatureScanner(javaWrappers)))
    }
    assertNotSlower(r)
  }

  @Test(groups = Array("performance"))
  def databasesAsUsedPerFile(): Unit = {
    // PortEx 5 loaded the PEiD, overlay and file type databases for every PEData
    val r = compareSimple("1c databases per scanned file (PortEx 5 reloaded them)", warmups = 3, runs = 9) {
      (LegacySignatureScanner(), new LegacySignatureScanner(LegacySignatureScanner.loadOverlaySigs()),
        new LegacySignatureScanner(LegacySignatureScanner.loadFileTypeSigs()))
    } {
      DefaultSignatures.peScanner
    }
    assertNotSlower(r)
  }

  @Test(groups = Array("performance"))
  def entryPointScanSynthetic(): Unit = {
    val file = files.pe("upx_like.exe", upxEntryPoint, 0x10000, Array.emptyByteArray)
    val legacy = LegacySignatureScanner().prebuild()
    val m = DefaultSignatures.peScanner._scan(PELoader.loadPE(file), Set(LocationKind.ENTRY_POINT))
    assertTrue(m.exists(_.getName.startsWith("UPX")), m.mkString(", "))
    assertNotSlower(compareSimple("2  entry point scan, synthetic PE incl. PE parsing") {
      legacy._findAllEPMatches(file)
    } {
      DefaultSignatures.peScanner._scan(PELoader.loadPE(file), Set(LocationKind.ENTRY_POINT))
    })
  }

  @Test(groups = Array("performance"))
  def entryPointScanCorpus(): Unit = {
    val pes = corpusPEs
    val legacy = LegacySignatureScanner().prebuild()
    assertNotSlower(compareSimple(s"2  entry point scan, ${pes.size} corpus files incl. PE parsing", warmups = 2, runs = 7) {
      pes.map(legacy._findAllEPMatches(_).size).sum
    } {
      pes.map(f => DefaultSignatures.peScanner._scan(PELoader.loadPE(f), Set(LocationKind.ENTRY_POINT)).size).sum
    })
  }

  @Test(groups = Array("performance"))
  def overlayScan(): Unit = {
    val overlay = new Array[Byte](8 << 20)
    new scala.util.Random(3).nextBytes(overlay)
    System.arraycopy(ascii("Inno"), 0, overlay, 0x34, 4)
    val file = files.pe("installer.exe", upxEntryPoint, 0x10000, overlay)
    val legacy = new LegacyScans(asShipped = false)
    val m = DefaultSignatures.peScanner._scan(PELoader.loadPE(file), Set(LocationKind.OVERLAY))
    assertTrue(m.exists(_.getName == "Inno Setup Installer with Stub"), m.mkString(", "))
    assertNotSlower(compare("3  overlay scan, 8 MB overlay")(
      () => PELoader.loadPE(file), (pe: PEData) => legacy.overlayMatches(pe))(
      () => PELoader.loadPE(file), (pe: PEData) => DefaultSignatures.peScanner._scan(pe, Set(LocationKind.OVERLAY))))
  }

  @Test(groups = Array("performance"))
  def resourceScan(): Unit = {
    val (file, count) = corpusPEs.map(f => (f, scala.util.Try(PELoader.loadPE(f).loadResources().size).getOrElse(0))).maxBy(_._2)
    val asShipped = new LegacyScans(asShipped = true)
    val prebuilt = new LegacyScans(asShipped = false)
    assertNotSlower(compare(s"4a resource scan, ${file.getName} ($count resources), legacy as shipped", warmups = 2, runs = 7)(
      () => PELoader.loadPE(file), (pe: PEData) => asShipped.resourceMatches(pe))(
      () => PELoader.loadPE(file), (pe: PEData) => DefaultSignatures.peScanner._scan(pe, Set(LocationKind.RESOURCE))))
    assertNotSlower(compare(s"4b resource scan, ${file.getName} ($count resources), legacy prebuilt")(
      () => PELoader.loadPE(file), (pe: PEData) => prebuilt.resourceMatches(pe))(
      () => PELoader.loadPE(file), (pe: PEData) => DefaultSignatures.peScanner._scan(pe, Set(LocationKind.RESOURCE))))
  }

  @Test(groups = Array("performance"))
  def wholeFileScan(): Unit = {
    val size = 1L << 20
    val planted = Seq(1000L -> Array[Byte](0x50, 0x4B, 3, 4), 50000L -> Array[Byte](0xCA.toByte, 0xFE.toByte, 0xBA.toByte, 0xBE.toByte),
      500000L -> ascii("Launch4j"))
    val file = files.random("wrapped.bin", size, 5, planted)
    val legacy = new LegacySignatureScanner(LegacySignatureScanner.loadJavaWrapperSigs()).prebuild()
    val found = DefaultSignatures.javaWrapperScanner._scanFile(file).map(_.getName).toSet
    assertTrue(Set("PKZIP Archive File", "CAFEBABE", "Launch4j").subsetOf(found), found.toString)
    assertNotSlower(compareSimple("5  whole file search, Java wrappers, 1 MB", warmups = 1, runs = 5) {
      legacy._findAllEPFalseMatches(file)
    } {
      DefaultSignatures.javaWrapperScanner._scanFile(file)
    })
    val big = files.random("big.bin", 256L << 20, 6, planted)
    val nanos = sample(() => (), (_: Unit) => DefaultSignatures.javaWrapperScanner._scanFile(big), 0)
    reportOnly(f"5  whole file search, Java wrappers, 256 MB, new only: ${nanos / 1e6}%.1f ms, ${256 * 1e9 / nanos}%.0f MB/s")
  }

  @Test(groups = Array("performance"))
  def fileTypeScan(): Unit = {
    val zip = files.random("archive.zip", 65536, 7, Seq(0L -> Array[Byte](0x50, 0x4B, 3, 4)))
    val png = files.random("image.png", 65536, 8, Seq(0L -> Array[Byte](0x89.toByte, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)))
    val other = files.random("unknown.bin", 65536, 9)
    val inputs = List(zip, png, other)
    assertTrue(FileTypeScanner._scan(zip).nonEmpty && FileTypeScanner._scan(png).nonEmpty)
    assertNotSlower(compareSimple("6a file type at offset 0, legacy as shipped") {
      inputs.map(f => new LegacySignatureScanner(LegacySignatureScanner.loadFileTypeSigs())._scanAt(f, 0))
    } {
      inputs.map(FileTypeScanner._scan)
    })
    val prebuilt = new LegacySignatureScanner(LegacySignatureScanner.loadFileTypeSigs()).prebuild()
    assertNotSlower(compareSimple("6b file type at offset 0, legacy prebuilt") {
      inputs.map(prebuilt._scanAt(_, 0))
    } {
      inputs.map(FileTypeScanner._scan)
    })
  }

  @Test(groups = Array("performance"))
  def endToEnd(): Unit = {
    val pes = corpusPEs
    val kinds = Array(LocationKind.ENTRY_POINT, LocationKind.OVERLAY, LocationKind.RESOURCE, LocationKind.MSDOS_HEADER)
    val asShipped = new LegacyScans(asShipped = true)
    val prebuilt = new LegacyScans(asShipped = false)
    def load(): List[PEData] = pes.map(PELoader.loadPE)
    assertNotSlower(compare(s"7a all PEData signatures, ${pes.size} corpus files, legacy as shipped", warmups = 1, runs = 5)(
      () => load(), (data: List[PEData]) => data.map(asShipped.allPEMatches(_).size).sum)(
      () => load(), (data: List[PEData]) => data.map(_.getSignatureMatches(kinds: _*).size).sum))
    assertNotSlower(compare(s"7c all PEData signatures, ${pes.size} corpus files, legacy prebuilt", warmups = 1, runs = 5)(
      () => load(), (data: List[PEData]) => data.map(prebuilt.allPEMatches(_).size).sum)(
      () => load(), (data: List[PEData]) => data.map(_.getSignatureMatches(kinds: _*).size).sum))
    // the default locations include more than PortEx 5 scanned
    report(compare(s"7b all default locations (more than PortEx 5), ${pes.size} corpus files", warmups = 1, runs = 5)(
      () => load(), (data: List[PEData]) => data.map(asShipped.allPEMatches(_).size).sum)(
      () => load(), (data: List[PEData]) => data.map(_.getSignatureMatches().size).sum))
  }

  @Test(groups = Array("performance"))
  def endOfFileDoesNotDependOnFileSize(): Unit = {
    val db = SignatureDatabase.parse(
      "[eocd]\npattern = 50 4B 05 06\nin = eof[0x10000]\n\n[cookie]\npattern = 'MEI' 0C 0B 0A 0B 0E\nat = eof - 0x18", "perf")
    val scanner = new SignatureScanner(db)
    val small = files.random("small_eof.bin", 1L << 20, 10)
    val big = new File(files.folder, "big.bin")
    val bigFile = if (big.exists()) big else files.random("big.bin", 256L << 20, 6)
    val smallNanos = median((0 until 15).map(_ => sample(() => (), (_: Unit) => scanner._scanFile(small), 20000000L)))
    val bigNanos = median((0 until 15).map(_ => sample(() => (), (_: Unit) => scanner._scanFile(bigFile), 20000000L)))
    reportOnly(f"8  end of file signatures, new only: 1 MB ${smallNanos / 1e6}%.3f ms, 256 MB ${bigNanos / 1e6}%.3f ms")
    assertTrue(bigNanos < smallNanos * 3 + 1e6, s"eof scan depends on the file size: $smallNanos ns vs $bigNanos ns")
  }

  @Test(groups = Array("performance"))
  def conditionOverhead(): Unit = {
    val pes = corpusPEs.take(20)
    val text = (0 until 1000).map { i =>
      i % 4 match {
        case 0 => s"[lib$i]\nimport = library$i.dll\n"
        case 1 => s"[net$i]\ndotnet_string = Some.Type$i\n"
        case 2 => s"[sec$i]\nsection = .sec$i\n"
        case _ => s"[ver$i]\nversion_info.ProductName = Product $i\n"
      }
    }.mkString("\n")
    val scanner = new SignatureScanner(SignatureDatabase.parse(text, "conditions"))
    val data = pes.map(PELoader.loadPE)
    data.foreach(pe => scanner._scan(pe, Set(LocationKind.METADATA)))
    val nanos = median((0 until 7).map(_ =>
      sample(() => pes.map(PELoader.loadPE), (d: List[PEData]) => d.map(pe => scanner._scan(pe, Set(LocationKind.METADATA)).size).sum, 50000000L)))
    reportOnly(f"9  1000 condition-only signatures, new only: ${nanos / 1e6 / pes.size}%.3f ms per file incl. parsing of imports, .NET and version info")
  }
}
