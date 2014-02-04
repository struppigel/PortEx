package com.github.katjahahn.tools

import java.io.File
import com.sun.org.apache.xalan.internal.xsltc.compiler.StartsWithCall
import scala.collection.mutable.ListBuffer
import java.nio.charset.MalformedInputException
import scala.io.Codec
import java.nio.charset.CodingErrorAction
import SignatureScanner._
import com.github.katjahahn.PELoader
import com.github.katjahahn.PEData
import com.github.katjahahn.optheader.StandardFieldEntryKey._
import java.io.RandomAccessFile
import com.github.katjahahn.sections.SectionTable
import com.github.katjahahn.sections.SectionLoader
import Signature._
import com.github.katjahahn.sections.SectionTableEntryKey
import PartialFunction._
import scala.collection.JavaConverters._

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
   * Scans a file for signatures and returns the best match
   *
   * @param file the PE file to be scanned
   * @return the best match found, null if no match was found
   */
  def scan(file: File, epOnly: Boolean = false): String = {
    val list = scanAll(file, epOnly)
    if (list != Nil) list.last
    else null //for Java
  }

  /**
   * @param file the file to be scanned
   * @return list of scanresults with all matches found
   */
  def _scanAll(file: File, epOnly: Boolean = true): List[ScanResult] = { //use from scala
    var matches = findAllEPMatches(file)
    if (!epOnly) matches = matches ::: findAllEPFalseMatches(file)
    matches
  }

  /**
   * @param file the file to be scanned
   * @return list of strings with all matches found
   */
  def scanAll(file: File, epOnly: Boolean = true): List[String] = { //use from Java
    def bytesMatched(sig: Signature): Int =
      sig.signature.filter(cond(_) { case Some(s) => true }).length
    val matches = _scanAll(file, epOnly)
    for ((m, addr) <- matches)
      yield m.name + " bytes matched: " + bytesMatched(m) + " at address: " + addr
  }

  /**
   * Searches for matches in the whole file using ep_only false signatures.
   *
   * @param file to search for signatures
   */
  def findAllEPFalseMatches(file: File): List[ScanResult] = {
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
  def findAllEPMatches(file: File): List[ScanResult] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val data = PELoader.loadPE(file)
      val entryPoint = getEntryPoint(data)
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
  private def getEntryPoint(data: PEData): Int = {
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

  private val defaultSigs = new File("userdb2.txt")

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

  //TODO performance measurement for different chunk sizes
  def main(args: Array[String]): Unit = {
    val s = SignatureScanner()
    val file = new File("WinRar.exe")
    s.scanAll(file, false).foreach(println)
    println("length of file: " + file.length())
  }

}