/**
 * *****************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
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

import io.github.struppigel.parser.ScalaIOUtil.using
import io.github.struppigel.parser.optheader.StandardFieldEntryKey._
import io.github.struppigel.parser.sections.SectionLoader
import io.github.struppigel.parser.{Interruption, PELoader}
import LegacySignatureScanner._

import java.io.{File, InputStreamReader, RandomAccessFile}
import java.nio.charset.CodingErrorAction
import scala.collection.mutable.ListBuffer
import scala.io.Codec
import scala.util.control.Breaks._
import org.apache.logging.log4j.LogManager

/**
 * Frozen copy of the PortEx 5.x (v1) signature scanner.
 * <p>
 * Only used as a baseline for the differential and performance tests of the
 * signature scanner. Do not change the behaviour of this class. The old
 * signature databases are read from the test resources folder /legacy/.
 */
class LegacySignatureScanner(signatures: List[LegacySignature]) {

  val logger = LogManager.getLogger(LegacySignatureScanner.getClass.getName)

  private val longestSigSequence: Int = signatures.foldLeft(0)(
    (i, s) => if (s.pattern.length > i) s.pattern.length else i)

  private lazy val epOnlyFalseSigs: LegacySignatureTree =
    createSignatureTree(signatures.filter(_.epOnly == false))

  private lazy val epOnlySigs: LegacySignatureTree =
    createSignatureTree(signatures.filter(_.epOnly == true))

  private def createSignatureTree(list: List[LegacySignature]): LegacySignatureTree = {
    var tree = LegacySignatureTree()
    list.foreach(s => tree += s)
    tree
  }

  /** Forces the creation of both prefix trees. */
  def prebuild(): LegacySignatureScanner = {
    epOnlyFalseSigs
    epOnlySigs
    this
  }

  def _scanAt(file: File, offset: Long): List[ScanResult] = {
    if (offset < 0) {
      return Nil
    }
    if (offset >= file.length()) {
      return Nil
    }
    using(new RandomAccessFile(file, "r")) { raf =>
      val results = ListBuffer[ScanResult]()
      val bytes = Array.fill(longestSigSequence + 1)(0.toByte)
      raf.seek(offset)
      val bytesRead = raf.read(bytes)
      val slicedarr = bytes.slice(0, bytesRead)
      val matches = epOnlyFalseSigs.findMatches(slicedarr.toList)
      results ++= matches.map((_, offset))
      return results.toList
    }
  }

  def _scanAll(file: File, epOnly: Boolean = true): List[ScanResult] = {
    var matches = _findAllEPMatches(file)
    if (!epOnly) matches = matches ::: _findAllEPFalseMatches(file)
    matches
  }

  def _findAllEPFalseMatches(file: File): List[ScanResult] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val results = ListBuffer[ScanResult]()
      for (addr <- 0L to file.length()) {
        Interruption.checkInterrupt()
        val bytes = Array.fill(longestSigSequence + 1)(0.toByte)
        raf.seek(addr)
        val bytesRead = raf.read(bytes)
        val slicedarr = bytes.slice(0, bytesRead)
        val matches = epOnlyFalseSigs.findMatches(slicedarr.toList)
        results ++= matches.map((_, addr))
      }
      results.toList
    }
  }

  def _findAllEPMatches(file: File): List[ScanResult] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val maybeEntryPoint = maybeGetEntryPoint(file)
      maybeEntryPoint match {
        case Some(entryPoint) =>
          raf.seek(entryPoint.toLong)
          var bytes = Array.fill(longestSigSequence + 1)(0.toByte)
          val bytesRead = raf.read(bytes)
          val matches = epOnlySigs.findMatches(bytes.slice(0, bytesRead).toList)
          matches.map((_, entryPoint.toLong))
        case None =>
          List()
      }
    }
  }

  def maybeGetEntryPoint(file: File): Option[Long] = {
    val data = PELoader.loadPE(file)
    val rva = data.getOptionalHeader().getStandardFieldEntry(ADDR_OF_ENTRY_POINT).getValue
    val loader = new SectionLoader(data)
    val offset = loader.getFileOffset(rva)
    if (offset <= file.length()) Some(offset)
    else None
  }
}

object LegacySignatureScanner {

  private val logger = LogManager.getLogger(LegacySignatureScanner.getClass.getName)

  type Address = Long

  type ScanResult = (LegacySignature, Address)

  val userdb = "/legacy/userdb.txt"
  val overlaydb = "/legacy/overlaysignatures"
  val javawrapperdb = "/legacy/javawrapperdb"
  val filetypedb = "/legacy/customsigs_GCK.txt"

  def apply(): LegacySignatureScanner = new LegacySignatureScanner(loadDefaultSigs())

  def loadDefaultSigs(): List[LegacySignature] = _loadSignatures(userdb)

  def loadOverlaySigs(): List[LegacySignature] = _loadSignatures(overlaydb)

  def loadJavaWrapperSigs(): List[LegacySignature] = _loadSignatures(javawrapperdb)

  /**
   * Loads the signatures of an INI style database from the test resources.
   */
  def _loadSignatures(resource: String): List[LegacySignature] = {
    implicit val codec = Codec("UTF-8")
    // replace malformed input
    codec.onMalformedInput(CodingErrorAction.REPLACE)
    codec.onUnmappableCharacter(CodingErrorAction.REPLACE)

    val sigs = ListBuffer[LegacySignature]()
    val is = this.getClass().getResourceAsStream(resource)
    if (is == null) throw new IllegalStateException("could not read file " + resource)
    val it = scala.io.Source.fromInputStream(is)(codec).getLines
    while (it.hasNext) {
      var nameLine = it.next()
      while (nameLine.startsWith("[")) {
        val (maybeSig, nextNameLine) = readSignatureEntry(nameLine, it)
        if (maybeSig.isDefined) {
          sigs += maybeSig.get
        }
        nameLine = nextNameLine
      }
    }
    sigs.toList
  }

  private def readSignatureEntry(nameLine: String, it: Iterator[String]): (Option[LegacySignature], String) = {
    var nextNameLine = ""
    var ep = false
    var sig: Option[String] = None
    var addOffset = 0L
    var untilOffset = 0L
    var isDotNet: Option[Boolean] = None
    breakable {
      while (it.hasNext) {
        val line = it.next()
        if (line.startsWith("[")) {
          nextNameLine = line
          break
        } else if (line.startsWith("ep_only") && line.split("=").length > 1) {
          ep = line.split("=")(1).trim == "true"
        } else if (line.startsWith("signature")) {
          sig = Some(line.split("=")(1).trim)
        } else if (line.startsWith("at_offset") && line.split("=").length > 1) {
          addOffset = java.lang.Long.decode("0x" + line.split("=")(1).replace(" ","").trim())
        } else if (line.startsWith("until_offset") && line.split("=").length > 1) {
          untilOffset = java.lang.Long.decode("0x" + line.split("=")(1).replace(" ","").trim())
        } else if (line.startsWith("is_dot_net") && line.split("=").length > 1) {
          isDotNet = Some(line.split("=")(1).trim == "true")
        }
      }
    }
    if (sig.isDefined) {
      (Some(LegacySignature(nameLine, ep, sig.get, addOffset.toInt, untilOffset, isDotNet)), nextNameLine)
    } else (None, nextNameLine)
  }

  /**
   * Loads the CSV file type signatures, as done by the v1 FileTypeScanner.apply,
   * including its filter.
   */
  def loadFileTypeSigs(): List[LegacySignature] = {
    val is = this.getClass().getResourceAsStream(filetypedb)
    if (is == null) throw new IllegalStateException("could not read file " + filetypedb)
    val sigs = ListBuffer[LegacySignature]()
    // v1 used IOUtil.readArray, which reads with the platform charset
    using(new java.io.BufferedReader(new InputStreamReader(is))) { reader =>
      var line = reader.readLine()
      while (line != null) {
        val values = line.split(",")
        sigs += LegacySignature(values(0), false, values(1))
        line = reader.readLine()
      }
    }
    sigs.toList.filter { s => s.bytesMatched() >= 3 || s.name == "MS-DOS or Portable Executable" }
  }
}
