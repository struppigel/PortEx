package com.github.katjahahn.tools

import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.CodingErrorAction
import scala.PartialFunction._
import scala.collection.JavaConverters._
import scala.collection.mutable.{ Map, ListBuffer }
import scala.io.Codec
import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader
import com.github.katjahahn.optheader.StandardFieldEntryKey._
import com.github.katjahahn.sections.SectionLoader
import com.github.katjahahn.sections.SectionTable
import com.github.katjahahn.sections.SectionTableEntryKey
import Signature._
import SignatureScanner._
import com.github.katjahahn.FileFormatException

/**
 * Scans PE files for compiler and packer signatures.
 *
 * @author Katja Hahn
 *
 * @constructor Creates a SignatureScanner that uses the signatures applied
 * @param signatures to use for scanning
 */
class SignatureScanner(signatures: List[Signature]) {

  /**
   * @constructor Creates a SignatureScanner that uses the signatures applied
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
    def bytesMatched(sig: Signature): Int =
      sig.signature.filter(cond(_) { case Some(s) => true }).length
    val matches = _scanAll(file, epOnly)
    (for ((m, addr) <- matches)
      yield m.name + " bytes matched: " + bytesMatched(m) + " at address: " + addr).asJava
  }
  
  private def toMatchedSignature(result: ScanResult): MatchedSignature = {
    val (sig, addr) = result
    val signature = Signature.bytes2hex(sig.signature, " ")
    new MatchedSignature(addr, signature, sig.name, sig.epOnly)
  }
  
  /**
   * Searches for matches in the whole file using ep_only false signatures.
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
   * are specified to be checked for at ep_only.
   *
   * @param file to search for signatures
   */
  
  def findAllEPMatches(file: File): java.util.List[MatchedSignature] = 
    _findAllEPMatches(file).map(toMatchedSignature).asJava
    
  def _findAllEPMatches(file: File): List[ScanResult] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val entryPoint = getEntryPoint(file)
      raf.seek(entryPoint.toLong)
      var bytes = Array.fill(longestSigSequence + 1)(0.toByte)
      val bytesRead = raf.read(bytes)
      val matches = epOnlySigs.findMatches(bytes.slice(0, bytesRead).toList)
      matches.map((_, entryPoint.toLong))
    }
  }

  private def using[A <: { def close(): Unit }, B](param: A)(f: A => B): B =
    try { f(param) } finally { param.close() }

  /**
   * Calculates the entry point with the given PE data
   *
   * @param data the pedata result created by a PELoader
   */
  def getEntryPoint(file: File): Int = {
    val data = PELoader.loadPE(file)
    val rva = data.getOptionalHeader().getStandardFieldEntry(ADDR_OF_ENTRY_POINT).value
    val section = SectionLoader.getSectionByRVA(data.getSectionTable(), rva)
    val phystovirt = section.get(SectionTableEntryKey.VIRTUAL_ADDRESS) - section.get(SectionTableEntryKey.POINTER_TO_RAW_DATA)
    rva - phystovirt
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

  private val defaultSigs = new File("userdb.txt")

  private val version = """version: 0.1
    |author: Katja Hahn
    |last update: 5.Feb 2014""".stripMargin

  private val title = "peiscan v0.1 -- by deque"

  private val usage = """Usage: java -jar peiscan.jar [-s <signaturefile>] [-ep true|false] <PEfile>
    """.stripMargin

  private type OptionMap = Map[Symbol, String]

  // This name makes more sense to call from Java
  /**
   * Loads default signatures (provided by PEiD) and creates a
   * SignatureScanner that uses these.
   *
   * @return SignatureScanner with default signatures
   */
  def getInstance(): SignatureScanner = apply()

  /**
   * Loads default signatures (provided by PEiD) and creates a
   * SignatureScanner that uses these.
   *
   * @return SignatureScanner with default signatures
   */
  def apply(): SignatureScanner =
    new SignatureScanner(_loadSignatures(defaultSigs))

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

    var sigs = ListBuffer[Signature]()
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

  def main(args: Array[String]): Unit = {
    invokeCLI(args)
  }

  private def invokeCLI(args: Array[String]): Unit = {
    val options = nextOption(Map(), args.toList)
    println(title)
    if (args.length == 0 || !options.contains('inputfile)) {
      println(usage)
    } else {
      var eponly = true
      var signatures = defaultSigs
      var file = new File(options('inputfile))

      if (options.contains('version)) {
        println(version)
      }
      if (options.contains('signatures)) {
        signatures = new File(options('signatures))
      }
      if (options.contains('eponly)) {
        eponly = options('eponly) == "true"
      }
      doScan(eponly, signatures, file)
    }
  }

  private def doScan(eponly: Boolean, sigFile: File, pefile: File): Unit = {
    if (!sigFile.exists()) {
      println(sigFile)
      System.err.println("signature file doesn't exist")
      return
    }
    if (!pefile.exists()) {
      System.err.println("pe file doesn't exist")
      return
    }
    println("scanning file ...")
    if(!eponly) println("(this might take a while)")
    try {
      val scanner = new SignatureScanner(_loadSignatures(sigFile))
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