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

import com.github.katjahahn.parser.IOUtil;
import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.CodingErrorAction

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import scala.collection.mutable.Map
import scala.io.Codec

import org.apache.logging.log4j.LogManager

import com.github.katjahahn.parser.FileFormatException
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.ScalaIOUtil.{bytes2hex, using}
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey._
import com.github.katjahahn.parser.sections.SectionLoader

import Signature._
import SignatureScanner._

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
    if(offset < 0){
      logger.warn("offset must not be negative")
      return Nil
    } 
    if(offset >= file.length()){
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
   * @return list of scanresults with all matches found at the specified position
   */
  def scanAt(file: File, offset: Long): java.util.List[String] = {
    val matches = _scanAt(file, offset)
    (for ((m, addr) <- matches)
      yield m.name + " bytes matched: " + m.bytesMatched + " at address: " + addr).asJava
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
      yield m.name + " bytes matched: " + m.bytesMatched + " at address: " + addr).asJava
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

  /**
   * A file offset/address
   */
  type Address = Long

  /**
   * a scan result is a signature and the address where it was found
   */
  type ScanResult = (Signature, Address)

  private val defaultSigs = IOUtil.SPEC_DIR + "userdb.txt"

  private val version = """version: 0.1
    |author: Katja Hahn
    |last update: 5.Feb 2014""".stripMargin

  private val title = "peiscan v0.1 -- by deque"

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
    implicit val codec = Codec("UTF-8")
    //replace malformed input
    codec.onMalformedInput(CodingErrorAction.REPLACE)
    codec.onUnmappableCharacter(CodingErrorAction.REPLACE)

    val sigs = ListBuffer[Signature]()
    val is = this.getClass().getResourceAsStream(defaultSigs)
    val it = scala.io.Source.fromInputStream(is)(codec).getLines
    while (it.hasNext) {
      val line = it.next
      if (line.startsWith("[") && it.hasNext) {
        val line2 = it.next
        if (it.hasNext) {
          sigs += Signature(line, it.next, line2)
        }
      }
    }
    sigs.toList
  }
  /**
   * Loads the signatures from the given file.
   *
   * @param sigFile the file containing the signatures
   * @return a list containing the signatures of the file
   */
  def _loadSignatures(sigFile: File): List[Signature] = {
    implicit val codec = Codec("UTF-8")
    //replace malformed input
    codec.onMalformedInput(CodingErrorAction.REPLACE)
    codec.onUnmappableCharacter(CodingErrorAction.REPLACE)

    val sigs = ListBuffer[Signature]()
    val it = scala.io.Source.fromFile(sigFile)(codec).getLines
    while (it.hasNext) {
      val line = it.next
      if (line.startsWith("[") && it.hasNext) {
        val line2 = it.next
        if (it.hasNext) {
          sigs += Signature(line, it.next, line2)
        }
      }
    }
    sigs.toList
  }

  /**
   * Loads a list of signatures from the specified signature file
   *
   * @param sigFile file that contains the signatures
   * @return list containing the loaded signatures
   */
  def loadSignatures(sigFile: File): java.util.List[Signature] =
    _loadSignatures(sigFile).asJava

  def toMatchedSignature(result: ScanResult): MatchedSignature = {
    val (sig, addr) = result
    val signature = bytes2hex(sig.signature, " ")
    new MatchedSignature(addr, signature, sig.name, sig.epOnly)
  }

  def main(args: Array[String]): Unit = {
    //    val file = new File("/home/deque/portextestfiles/Holiday_Island.exe")
    //    val scanner = SignatureScanner()
    //    scanner.scanAll(file).asScala.foreach(println)
    invokeCLI(args)
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
          new SignatureScanner(_loadSignatures(signatures.get))
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
