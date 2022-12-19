/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn.tools.sigscanner

import com.github.katjahahn.parser.IOUtil
import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.CodingErrorAction
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import scala.collection.mutable.Map
import scala.io.Codec
import scala.util.control.Breaks._
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.parser.FileFormatException
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.ScalaIOUtil.{ bytes2hex, using }
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey._
import com.github.katjahahn.parser.sections.SectionLoader
import Signature._
import SignatureScanner._
import com.github.katjahahn.tools.ReportCreator
import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.PESignature
import com.github.katjahahn.tools.Overlay
import com.github.katjahahn.parser.ScalaIOUtil

/**
 * Scans PE files for compiler and packer signatures.
 *
 * @author Katja Hahn
 *
 * Creates a SignatureScanner that uses the signatures applied
 * @param signatures to use for scanning
 */
class SignatureScanner(signatures: List[Signature]) {

  val logger = LogManager.getLogger(SignatureScanner.getClass.getName)
  /**
   * Creates a SignatureScanner that uses the signatures applied
   * @param signatures to use for scanning
   */
  def this(signatures: java.util.List[Signature]) = this(signatures.asScala.toList)

  private val longestSigSequence: Int = signatures.foldLeft(0)(
    (i, s) => if (s.signature.length > i) s.signature.length else i)

  private lazy val epOnlyFalseSigs: SignatureTree =
    createSignatureTree(signatures.filter(_.epOnly == false))

  private lazy val epOnlySigs: SignatureTree =
    createSignatureTree(signatures.filter(_.epOnly == true))

  private def createSignatureTree(list: List[Signature]): SignatureTree = {
    var tree = SignatureTree()
    list.foreach(s => tree += s)
    tree
  }

  /**
   * @param file the file to be scanned
   * @param offset the file offset to be matched
   *
   * @return list of scanresults with all matches found at the specified position
   */
  def _scanAt(file: File, offset: Long): List[ScanResult] = { //use from scala
    if (offset < 0) {
      logger.warn("offset must not be negative")
      return Nil
    }
    if (offset >= file.length()) {
      logger.warn("offset is larger than file")
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

  /**
   * @param file the file to be scanned
   * @param offset the file offset to be matched
   *
   * @return list of strings with all matches found
   */
  def scanAt(file: File, offset: Long): java.util.List[String] = {
    val matches = _scanAt(file, offset)
    (for ((m, addr) <- matches)
      yield (m.name + " bytes matched: " + m.bytesMatched + " at address: " + ScalaIOUtil.hex(addr) + 
        IOUtil.NL + "pattern: " + m.signatureString)).asJava
  }

  /**
   * @param file the file to be scanned
   * @return list of scanresults with all matches found
   */
  def _scanAll(file: File, epOnly: Boolean = true): List[ScanResult] = { //use from scala
    var matches = _findAllEPMatches(file)
    if (!epOnly) matches = matches ::: _findAllEPFalseMatches(file)
    matches
  }

  /**
   * @param file the file to be scanned
   * @return list of strings with all matches found
   */
  def scanAll(file: File, epOnly: Boolean = true): java.util.List[String] = { //use from Java
    val matches = _scanAll(file, epOnly)
    (for ((m, addr) <- matches)
      yield (m.name + " bytes matched: " + m.bytesMatched + " at address: " + ScalaIOUtil.hex(addr) + 
        IOUtil.NL + "pattern: " + m.signatureString)).asJava
  }

  /**
   * Searches for matches in the whole file uscom.github.katjahahn.tools.sigscanner.se signatures.
   *
   * @param file to search for signatures
   */
  def findAllEPFalseMatches(file: File): java.util.List[MatchedSignature] =
    _findAllEPFalseMatches(file).map(toMatchedSignature).asJava

  def _findAllEPFalseMatches(file: File): List[ScanResult] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val results = ListBuffer[ScanResult]()
      for (addr <- 0L to file.length()) {
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

  /**
   * Searches for matches only at the entry point and only using signatures that
   * are specifiecom.github.katjahahn.tools.sigscanner. for at ep_only.
   *
   * @param file to search for signatures
   */

  def findAllEPMatches(file: File): java.util.List[MatchedSignature] =
    _findAllEPMatches(file).map(toMatchedSignature).asJava

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
          logger.warn("no entry point found")
          List()
      }
    }
  }

  /**
   * Calculates the entry point with the given PE data
   *
   * @param data the pedata result created by a PELoader
   */
  def maybeGetEntryPoint(file: File): Option[Long] = {
    val data = PELoader.loadPE(file)
    val rva = data.getOptionalHeader().getStandardFieldEntry(ADDR_OF_ENTRY_POINT).getValue
    val loader = new SectionLoader(data)
    val offset = loader.getFileOffset(rva)
    if (offset <= file.length()) Some(offset)
    else None
  }
}

object SignatureScanner {

  private val logger = LogManager.getLogger(SignatureScanner.getClass.getName)

  /**
   * A file offset/address
   */
  type Address = Long

  /**
   * a scan result is a signature and the address where it was found
   */
  type ScanResult = (Signature, Address)

  private val defaultSigs = IOUtil.SPEC_DIR + "userdb.txt"
  private val overlaySigs = IOUtil.SPEC_DIR + "overlaysignatures"

  private val version = """version: 0.1
    |author: Katja Hahn
    |last update: 5.Feb 2014""".stripMargin

  private val title = "peiscan v0.1"

  private val usage = """Usage: java -jar peiscan.jar [-s <signaturefile>] [-ep true|false] <PEfile>
    """.stripMargin

  private type OptionMap = Map[Symbol, String]

  /**
   * Loads default signatures (provided by PEiD) and creates a
   * SignatureScanner that uses these.
   *
   * @return SignatureScanner with default signatures
   */
  def newInstance(): SignatureScanner = apply()

  /**
   * Loads default signatures (provided by PEiD) and creates a
   * SignatureScanner that uses these.
   *
   * @return SignatureScanner with default signatures
   */
  def apply(): SignatureScanner =
    new SignatureScanner(loadDefaultSigs())

  /**
   * Loads the signatures from the given file.
   *
   * @return a list containing the signatures of the file
   */
  private def loadDefaultSigs(): List[Signature] = {
    _loadSignatures(defaultSigs, true)
  }

  def _loadOverlaySigs(): List[Signature] = {
    _loadSignatures(overlaySigs, true)
  }

  def loadOverlaySigs(): java.util.List[Signature] = {
    _loadOverlaySigs().asJava
  }

  /**
   * Loads the signatures from the given file.
   *
   * @param sigFile the file containing the signatures
   * @return a list containing the signatures of the file
   */
  def _loadSignatures(sigFile: String, fromResource: Boolean = false): List[Signature] = {
    implicit val codec = Codec("UTF-8")
    // replace malformed input
    codec.onMalformedInput(CodingErrorAction.REPLACE)
    codec.onUnmappableCharacter(CodingErrorAction.REPLACE)

    val sigs = ListBuffer[Signature]()
    val it = {
      if (fromResource) {
        val is = this.getClass().getResourceAsStream(sigFile)
        if(is == null) logger.fatal("could not read file " + sigFile)
        scala.io.Source.fromInputStream(is)(codec).getLines
      } else
        scala.io.Source.fromFile(new File(sigFile))(codec).getLines
    }
    while (it.hasNext) {
      var nameLine = it.next()
      while (nameLine.startsWith("[")) {
        val (maybeSig, nextNameLine) = readSignatureEntry(nameLine, it)
        if (maybeSig.isDefined) {
          sigs += maybeSig.get
        } else {
          logger.error("could not read signature in file " + sigFile)
        }
        nameLine = nextNameLine
      }
    }
    sigs.toList
  }

  private def readSignatureEntry(nameLine: String, it: Iterator[String]): (Option[Signature], String) = {
    var nextNameLine = ""
    var ep = false
    var sig: Option[String] = None
    var addOffset = 0L
    var untilOffset = 0L
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
          addOffset = java.lang.Long.decode("0x" + line.split("=")(1).replace(" ","").trim()) //TODO test
        } else if (line.startsWith("until_offset") && line.split("=").length > 1) {
          untilOffset = java.lang.Long.decode("0x" + line.split("=")(1).replace(" ","").trim()) //TODO test
        }
      }
    }
    if (sig.isDefined) {
      (Some(Signature(nameLine, ep, sig.get, addOffset.toInt, untilOffset)), nextNameLine)
    } else (None, nextNameLine)
  }

  /**
   * Loads a list of signatures from the specified signature file
   *
   * @param sigFile file that contains the signatures
   * @return list containing the loaded signatures
   */
  def loadSignatures(sigFile: File): java.util.List[Signature] =
    _loadSignatures(sigFile.getAbsolutePath).asJava

  def toMatchedSignature(result: ScanResult): MatchedSignature = {
    val (sig, addr) = result
    val signature = bytes2hex(sig.signature, " ")
    new MatchedSignature(addr, signature, sig.name, sig.epOnly)
  }

  def main(args: Array[String]): Unit = {
    val folder = new File("/home/katja/samples")
    for (file <- folder.listFiles()) {
      if (!file.isDirectory() && new PESignature(file).exists()) {
        val data = PELoader.loadPE(file)
        val reporter = new ReportCreator(data)
        if (new Overlay(data).exists) {
          println(file.getName)
          println("******************************")
          println(reporter.overlayReport())
          //println(reporter.jar2ExeReport())
          println(reporter.peidReport())
        }
      }
    }
  }

  private def invokeCLI(args: Array[String]): Unit = {
    val options = nextOption(Map(), args.toList)
    println(title)
    if (args.length == 0 || !options.contains('inputfile)) {
      println(usage)
    } else {
      var eponly = true
      var signatures: Option[File] = None
      var file = new File(options('inputfile))

      if (options.contains('version)) {
        println(version)
      }
      if (options.contains('signatures)) {
        signatures = Some(new File(options('signatures)))
      }
      if (options.contains('eponly)) {
        eponly = options('eponly) == "true"
      }
      doScan(eponly, signatures, file)
    }
  }

  private def doScan(eponly: Boolean, signatures: Option[File], pefile: File): Unit = {

    if (signatures.isDefined && !signatures.get.exists()) {
      println(signatures.get)
      System.err.println("signature file doesn't exist")
      return
    }
    if (!pefile.exists()) {
      System.err.println("pe file doesn't exist")
      return
    }
    println("scanning file ...")
    if (!eponly) println("(this might take a while)")
    try {
      val scanner = {
        if (signatures.isDefined)
          new SignatureScanner(_loadSignatures(signatures.get.getAbsolutePath))
        else SignatureScanner()
      }
      val list = scanner.scanAll(pefile, eponly).asScala
      if (list.length == 0) println("no signature found")
      else list.foreach(println)
    } catch {
      case e: FileFormatException => System.err.println(e.getMessage())
    }
  }

  private def nextOption(map: OptionMap, list: List[String]): OptionMap = {
    list match {
      case Nil => map
      case "-s" :: value :: tail =>
        nextOption(map += ('signatures -> value), tail)
      case "-ep" :: value :: tail =>
        nextOption(map += ('eponly -> value), tail)
      case "-v" :: tail =>
        nextOption(map += ('version -> ""), tail)
      case value :: Nil => nextOption(map += ('inputfile -> value), list.tail)
      case option :: tail =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }

}
