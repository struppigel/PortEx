/**
 * *****************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
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

import io.github.struppigel.parser.{PELoader, PESignature}

import java.io.{File, FileInputStream, PrintWriter}
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import scala.collection.mutable.ListBuffer

/**
 * Scans the test corpus with the frozen v1 scanner and writes the results as
 * golden file for the SignatureDifferentialTest.
 * <p>
 * Usage: LegacyGoldenGenerator &lt;corpus root&gt; &lt;output tsv&gt;
 * <p>
 * Output rows: path, sha256, group, name, address (hex). For every scanned file
 * there is one row with group "_scanned" whose name lists the groups that were
 * computed, so that files without matches are distinguishable from files that
 * were not scanned. Failed groups are listed as "_error" rows.
 */
object LegacyGoldenGenerator {

  /** v1 needs microseconds per byte for whole file scans */
  val Jar2ExeMaxSize: Long = 4L * 1024 * 1024

  /** folders of the corpus root that contain reports instead of samples */
  private val excludedFolders = Set("reports", "exportreports", "importreports")

  def main(args: Array[String]): Unit = {
    if (args.length != 2) {
      println("Usage: LegacyGoldenGenerator <corpus root> <output tsv>")
      sys.exit(1)
    }
    val root = new File(args(0))
    val files = listFiles(root).sortBy(relativePath(root, _))
    val scans = new LegacyScans(asShipped = false)
    val rows = ListBuffer[String]()
    var count = 0
    for (file <- files) {
      count += 1
      val path = relativePath(root, file)
      println(s"[$count/${files.size}] $path")
      val sha = sha256(file)
      val groups = ListBuffer[String]()
      val matches = ListBuffer[LegacyMatch]()

      def run(group: String)(scan: => List[LegacyMatch]): Unit = {
        try {
          matches ++= scan
          groups += group
        } catch {
          case e: Exception =>
            rows += row(path, sha, "_error", group + ": " + e.getClass.getSimpleName, 0)
        }
      }

      if (new PESignature(file).exists()) {
        try {
          val pedata = PELoader.loadPE(file)
          run("peid")(scans.peidMatches(file))
          run("overlay")(scans.overlayMatches(pedata))
          run("resource")(scans.resourceMatches(pedata))
          run("msdos")(scans.msdosMatches(pedata))
        } catch {
          case e: Exception =>
            rows += row(path, sha, "_error", "load: " + e.getClass.getSimpleName, 0)
        }
      } else {
        run("filetype0")(scans.fileType0Matches(file))
      }
      if (file.length() <= Jar2ExeMaxSize) run("jar2exe")(scans.jar2exeMatches(file))

      rows += row(path, sha, "_scanned", groups.mkString(","), 0)
      matches.distinct.foreach(m => rows += row(path, sha, m.group, m.name, m.address))
    }
    val out = new PrintWriter(new File(args(1)), "UTF-8")
    try {
      out.println("# golden results of the PortEx 5.x (v1) signature scanner, created by LegacyGoldenGenerator")
      out.println(s"# jar2exe whole file scans only for files <= $Jar2ExeMaxSize bytes")
      out.println("# path\tsha256\tgroup\tname\taddress")
      rows.foreach(out.println)
    } finally {
      out.close()
    }
    println(s"wrote ${rows.size} rows for ${files.size} files")
  }

  private def row(path: String, sha: String, group: String, name: String, address: Long): String =
    List(path, sha, group, escape(name), "0x" + java.lang.Long.toHexString(address)).mkString("\t")

  /** names never contain tabs or line breaks, but make sure the TSV stays intact */
  def escape(s: String): String = s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")

  def unescape(s: String): String = {
    val sb = new StringBuilder
    var i = 0
    while (i < s.length) {
      val c = s.charAt(i)
      if (c == '\\' && i + 1 < s.length) {
        s.charAt(i + 1) match {
          case 't' => sb += '\t'
          case 'n' => sb += '\n'
          case 'r' => sb += '\r'
          case other => sb += other
        }
        i += 2
      } else {
        sb += c
        i += 1
      }
    }
    sb.toString
  }

  def relativePath(root: File, file: File): String =
    root.toPath.relativize(file.toPath).toString.replace('\\', '/')

  def listFiles(root: File): List[File] = {
    val result = ListBuffer[File]()
    def walk(dir: File, isRoot: Boolean): Unit = {
      val children = Option(dir.listFiles()).map(_.toList).getOrElse(Nil)
      for (child <- children) {
        if (child.isDirectory) {
          if (!(isRoot && excludedFolders.contains(child.getName))) walk(child, isRoot = false)
        } else if (child.isFile) result += child
      }
    }
    walk(root, isRoot = true)
    result.toList
  }

  def sha256(file: File): String = {
    val digest = MessageDigest.getInstance("SHA-256")
    val in = new FileInputStream(file)
    try {
      val buffer = new Array[Byte](1 << 16)
      var read = in.read(buffer)
      while (read > 0) {
        digest.update(buffer, 0, read)
        read = in.read(buffer)
      }
    } finally {
      in.close()
    }
    digest.digest().map("%02x".format(_)).mkString
  }

  /** for consistent reading of the golden file */
  val charset = StandardCharsets.UTF_8
}
