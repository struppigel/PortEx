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
package io.github.struppigel.tools.sigscanner.legacy

import io.github.struppigel.tools.sigscanner._

import java.io.{File, OutputStreamWriter}
import java.nio.charset.{Charset, StandardCharsets}
import java.nio.file.Files
import scala.collection.immutable.ListMap

/**
 * Converts the signature databases of PortEx 5 to the signature database
 * format of PortEx 6. The output is deterministic.
 * <p>
 * Usage: SignatureDbConverter &lt;output folder&gt;
 * <p>
 * The old databases are read from the test resources folder /legacy/.
 */
object SignatureDbConverter {

  private def resource(name: String): Array[Byte] = {
    val in = getClass.getResourceAsStream("/legacy/" + name)
    if (in == null) throw new IllegalStateException("missing /legacy/" + name)
    try Stream.continually(in.read()).takeWhile(_ != -1).map(_.toByte).toArray finally in.close()
  }

  /** lines of userdb.txt that are neither UTF-8 nor windows-1252 */
  private val userdbLineCharsets: Map[Int, Charset] = Map(
    2312 -> Charset.forName("GBK"),
    2316 -> Charset.forName("GBK"),
    3387 -> Charset.forName("GBK"),
    3843 -> Charset.forName("GBK"),
    5307 -> Charset.forName("windows-1252"))

  /** decodes lines as UTF-8, with charset overrides for single lines */
  private def decode(bytes: Array[Byte], overrides: Map[Int, Charset]): String = {
    val text = PEiDImporter.decode(bytes)
    if (overrides.isEmpty) return text
    val rawLines = splitLines(bytes)
    text.split("\n", -1).zipWithIndex.map { case (line, idx) =>
      overrides.get(idx + 1).map(cs => new String(rawLines(idx), cs)).getOrElse(line)
    }.mkString("\n")
  }

  private def splitLines(bytes: Array[Byte]): IndexedSeq[Array[Byte]] = {
    val lines = scala.collection.mutable.ArrayBuffer[Array[Byte]]()
    var start = 0
    for (i <- 0 to bytes.length) {
      if (i == bytes.length || bytes(i) == '\n') {
        lines += java.util.Arrays.copyOfRange(bytes, start, i)
        start = i + 1
      }
    }
    lines.toIndexedSeq
  }

  private def reparse(sig: Signature, lines: Seq[String]): Signature = {
    val db = SignatureDatabase.parse((("[" + sig.name + "]") +: lines).mkString("\n"), "converter")
    val s = db.signatures.head
    new Signature(s.name, s.clauses, s.conditions, s.metadata, sig.source)
  }

  private def withMetadata(sig: Signature, metadata: (String, String)*): Signature =
    new Signature(sig.name, sig.clauses, sig.conditions, sig.metadata ++ metadata, sig.source)

  /** packer, protector and compiler signatures of userdb.txt */
  def convertUserDb(): SignatureDatabase = {
    val text = decode(resource("userdb.txt"), userdbLineCharsets)
    val db = PEiDImporter.parse(text, "userdb.txt", PEiDImportOptions.Default)
    val converted = db.signatures.map { sig =>
      sig.name match {
        // ep_only = false and in_section = 0: native code of the .NET protector stub
        case "NET Reactor 3.X" =>
          reparse(sig, Seq("pattern = " + sig.clauses.head.pattern.source, "in = section(executable)", "requires = dotnet"))
        case _ => sig
      }
    }
    new SignatureDatabase(converted, db.warnings)
  }

  /** installer and archive signatures for the overlay */
  def convertOverlayDb(): SignatureDatabase = {
    val text = decode(resource("overlaysignatures"), Map.empty)
    val options = PEiDImportOptions(base = "overlay", anchoredBase = true, leadingWildcardsAsOffset = true)
    val db = PEiDImporter.parse(text, "overlaysignatures", options)
    val converted = db.signatures.map { sig =>
      sig.name match {
        // the question marks were meant as wildcards
        case "NOS Installer" if sig.clauses.head.pattern.source == "'PK??NOS_PO'" =>
          reparse(sig, Seq("pattern = 'PK' ?? ?? 'NOS_PO'", "at = overlay"))
        case _ => sig
      }
    }
    // signatures that were hard coded in PortEx 5
    val moved = SignatureDatabase.parse(
      """[InnoSetup]
        |pattern = 'InUn'
        |at = msdos_header + 0x30
        |type = installer
        |
        |[PyInstaller archive string]
        |pattern = 'PyInstaller archive'
        |in = section(.rdata)[0-0x1500]
        |type = installer
        |""".stripMargin, "converter")
    new SignatureDatabase(converted ++ moved.signatures, db.warnings)
  }

  /** file type magic numbers of customsigs_GCK.txt */
  def convertFileTypes(): SignatureDatabase = {
    val text = new String(resource("customsigs_GCK.txt"), StandardCharsets.US_ASCII)
    val warnings = scala.collection.mutable.ArrayBuffer[String]()
    val signatures = text.split("\r\n|\n", -1).zipWithIndex.filter(_._1.trim.nonEmpty).flatMap { case (line, idx) =>
      val fields = line.split(",")
      val name = fields(0).trim
      val tokens = PEiDImporter.convertPattern(fields(1).trim)
      val byteCount = tokens.count(_ != "??")
      // PortEx 5 dropped short magic numbers because they cause too many false positives
      if (byteCount < 3 && name != "MS-DOS or Portable Executable") {
        warnings += s"customsigs_GCK.txt:${idx + 1}: [$name] has less than 3 bytes, dropped as in PortEx 5"
        None
      } else {
        val extensions = fields.lift(2).map(_.trim).filter(e => e.nonEmpty && e != "(none)")
          .map(_.split("\\|").map(_.trim).filter(_.nonEmpty).mkString(", "))
        val lines = Seq(s"[$name]", s"pattern = ${tokens.mkString(" ")}", "at = overlay, resource, file") ++
          extensions.map(e => s"extensions = $e")
        val sig = SignatureDatabase.parse(lines.mkString("\n"), "customsigs_GCK.txt").signatures.head
        Some(new Signature(sig.name, sig.clauses, sig.conditions, sig.metadata, s"customsigs_GCK.txt:${idx + 1}"))
      }
    }
    val unique = scala.collection.mutable.LinkedHashMap[String, Signature]()
    for (s <- signatures) {
      val key = SignatureDatabaseWriter.canonical(s)
      if (unique.contains(key)) warnings += s"${s.source}: duplicate of [${s.name}], dropped"
      else unique(key) = s
    }
    new SignatureDatabase(unique.values.toIndexedSeq, warnings.toIndexedSeq)
  }

  /** descriptions of the Jar2ExeScanner of PortEx 5 */
  private val javaWrapperDescriptions = Map(
    "Jar Manifest" -> "Jar manifest (strong indication for embedded jar)",
    "PKZIP Archive File" -> "PZIP Magic Number (weak indication for embedded zip)",
    "java.exe" -> "Call to java.exe (strong indication for java wrapper)",
    "javaw.exe" -> "Call to javaw.exe (strong indication for java wrapper)",
    "Jar2Exe Products" -> "Jar2Exe.com signature",
    "JSmooth" -> "JSmooth signature",
    "Launch4j" -> "Launch4j signature",
    "Exe4j" -> "Exe4j signature, search in your temp folder for e4jxxxx.tmp file while application is running",
    "CAFEBABE" -> ".class file signature(s) found")

  /** signatures of Java wrappers, searched in the whole file */
  def convertJavaWrappers(): SignatureDatabase = {
    val db = PEiDImporter.parse(decode(resource("javawrapperdb"), Map.empty), "javawrapperdb", PEiDImportOptions.Default)
    new SignatureDatabase(db.signatures.map { sig =>
      javaWrapperDescriptions.get(sig.name).map(d => withMetadata(sig, "description" -> d)).getOrElse(sig)
    }, db.warnings)
  }

  private def header(purpose: String, origin: String): Seq[String] = Seq(
    s"PortEx signature database: $purpose",
    "Format: see docs/SIGNATURES.md",
    s"Converted from $origin of PortEx 5 by SignatureDbConverter")

  def main(args: Array[String]): Unit = {
    if (args.length != 1) {
      println("Usage: SignatureDbConverter <output folder>")
      sys.exit(1)
    }
    val out = new File(args(0))
    out.mkdirs()
    val outputs = ListMap(
      "packers.sig" -> (convertUserDb(), header("packers, protectors and compilers, mostly at the entry point", "userdb.txt")),
      "installers.sig" -> (convertOverlayDb(), header("installers and archives in the overlay", "overlaysignatures")),
      "filetypes.sig" -> (convertFileTypes(), header("file type magic numbers in the overlay, resources and at the file start", "customsigs_GCK.txt")),
      "javawrappers.sig" -> (convertJavaWrappers(), header("Java wrappers, searched in the whole file", "javawrapperdb")))
    for ((name, (db, head)) <- outputs) {
      val file = new File(out, name)
      val writer = new OutputStreamWriter(Files.newOutputStream(file.toPath), StandardCharsets.UTF_8)
      try SignatureDatabaseWriter.write(db, writer, head) finally writer.close()
      // the written file must load without problems
      val check = SignatureDatabase.load(file)
      require(check.size == db.size, s"$name: wrote ${db.size} signatures, but read ${check.size}")
      println(s"$name: ${db.size} signatures")
      db.warnings.foreach(w => println("  " + w))
    }
  }
}
