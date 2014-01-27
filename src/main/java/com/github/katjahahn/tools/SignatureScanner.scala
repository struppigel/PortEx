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

/**
 * Scans PE files for compiler and packer signatures.
 * 
 * @author Katja Hahn
 * 
 * @constructor Creates a SignatureScanner that uses the signatures applied
 * @param signatures to use for scanning
 */
class SignatureScanner(signatures: List[Signature]) {

  private var _chunkSize = 134217728 //default value of 128 MB

  /*
   * Getter and setter for Java ;)
   */
  /**
   * @return the current chunkSize in bytes
   */
  def getChunkSize = _chunkSize
  /**
   * @param value the chunkSize in bytes
   */
  def setChunkSize(value: Int): Unit = { _chunkSize = value }

  private val longestSigSequence: Int = signatures.foldLeft(0)(
    (i, s) => if (s.signature.length > i) s.signature.length else i)

  private lazy val epOnlyFalseSigs: SignatureTree =
    createSignatureTree(signatures.filter(_.epOnly == false))

  private val epOnlySigs: SignatureTree =
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
   * @return the best match found
   */
  def scan(file: File, epOnly: Boolean = false): String = {
    scanAll(file, epOnly).last
  }

  /**
   * @param file the file to be scanned
   * @param chunkSize default value is 128 MB
   * @return list with all matches found
   */
  def scanAll(file: File, epOnly: Boolean = true): List[String] = {
    def bytesMatched(sig: Signature): Int =
      sig.signature.filter(cond(_) { case Some(s) => true }).length
    var matches = findAllEPMatches(file)
    if (!epOnly) matches ::: findAllEPFalseMatches(file, _chunkSize)
    for (m <- matches) yield m.name + " bytes matched: " + bytesMatched(m)
  }

  private def findAllEPFalseMatches(file: File, chunkSize: Int): List[Signature] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val matches = ListBuffer[Signature]()
      var i = 0
      for (chaddr <- 0L to file.length() by (chunkSize - longestSigSequence)) { //TODO test this!
        i = i + 1
        if (i % 10000 == 0) println("reading chunk " + i + " at address " + chaddr)
        val bytes = Array.fill(chunkSize)(0.toByte)
        raf.seek(chaddr)
        val bytesRead = raf.read(bytes)
        for (addr <- 0L to (bytesRead - longestSigSequence)) {
          val slicedarr = bytes.slice(addr.toInt, addr.toInt + longestSigSequence)
          matches ++= epOnlyFalseSigs.findMatches(slicedarr.toList)
        }
      }
      matches.toList
    }
  }

  private def findAllEPMatches(file: File): List[Signature] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val data = PELoader.loadPE(file)
      val entryPoint = getEntryPoint(data)
      raf.seek(entryPoint.toLong)
      var bytes = Array.fill(longestSigSequence + 1)(0.toByte)
      val bytesRead = raf.read(bytes)
      epOnlySigs.findMatches(bytes.slice(0, bytesRead).toList)
    }
  }

  private def using[A <: { def close(): Unit }, B](param: A)(f: A => B): B =
    try { f(param) } finally { param.close() }

  private def getEntryPoint(data: PEData): Int = {
    val rva = data.getOptionalHeader().getStandardFieldEntry(ADDR_OF_ENTRY_POINT).value
    val section = SectionLoader.getSectionByRVA(data.getSectionTable(), rva)
    val phystovirt = section.get(SectionTableEntryKey.VIRTUAL_ADDRESS) - section.get(SectionTableEntryKey.POINTER_TO_RAW_DATA)
    rva - phystovirt
  }
}

object SignatureScanner {

  private val defaultSigs = new File("userdb.txt")
  
  // This name makes more sense to call from Java
  /**
   * Loads default signatures (provided by PEiD) and creates a 
   * SignatureScanner that uses these.
   * 
   * @return SignatureScanner with default signatures
   */
  def getInstance(): SignatureScanner = apply()

  def apply(): SignatureScanner =
    new SignatureScanner(loadSignatures(defaultSigs))

  /**
   * Loads a list of signatures from the specified signature file
   *
   * @param sigFile file that contains the signatures
   * @return list containing the loaded signatures
   */
  def loadSignatures(sigFile: File): List[Signature] = {
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

  //TODO performance measurement for different chunk sizes
  def main(args: Array[String]): Unit = {
    val s = SignatureScanner()
    val file = new File("Holiday_Island.exe")
    s.scanAll(file, true).foreach(println)
    println("length of file: " + file.length())
  }

}