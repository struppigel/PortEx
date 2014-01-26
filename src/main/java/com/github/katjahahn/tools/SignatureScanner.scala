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

class SignatureScanner(signatures: List[Signature]) {

  private val defaultChunkSize = 134217728

  private val longestSigSequence: Int = signatures.foldLeft(0)(
    (i, s) => if (s.signature.length > i) s.signature.length
    else i)

  private lazy val epOnlyFalseSigs: SigTree =
    createSigTree(signatures.filter(_.epOnly == false))

  private val epOnlySigs: SigTree =
    createSigTree(signatures.filter(_.epOnly == true))

  private def createSigTree(list: List[Signature]): SigTree = {
    var tree = SigTree()
    list.foreach(s => tree += s)
    tree
  }

  /**
   * Scans a file for signatures and returns the best match
   *
   * @param file the PE file to be scanned
   * @return the best match found
   */
  def scan(file: File, epOnly: Boolean = false, chunkSize: Int = defaultChunkSize): String = {
    scanAll(file, epOnly, chunkSize).last
  }

  /**
   * @param file the file to be scanned
   * @param chunkSize default value is 128 MB
   * @return list with all matches found
   */
  def scanAll(file: File, epOnly: Boolean = true, chunkSize: Int = defaultChunkSize): List[String] = {
    def bytesMatched(sig: Signature): Int =
      sig.signature.filter(cond(_) { case Some(s) => true }).length
    var matches = findAllEPMatches(file)
    if (!epOnly) matches ::: findAllEPFalseMatches(file, chunkSize)
    for (m <- matches) yield m.name + " bytes matched: " + bytesMatched(m)
  }

  private def findAllEPFalseMatches(file: File, chunkSize: Int): List[Signature] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val matches = ListBuffer[Signature]()
      var i = 0
      println("longest sig " + longestSigSequence)
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

  private val defaultSigs = new File("testuserdb.txt")

  def apply(): SignatureScanner =
    new SignatureScanner(loadSignatures(defaultSigs))

  /**
   * Loads a list of signatures from the specified sigFile
   *
   * @param sigFile file that contains the signatures
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
          sigs += createSig(line, it.next, line2)
        }
      }
    }
    sigs.toList
  }

  private def createSig(name: String, ep: String, sig: String): Signature = {
    val ep_only = ep.split("=")(1).trim == "true"
    val sigbytes = hex2bytes(sig.split("=")(1).trim)
    new Signature(name, ep_only, sigbytes)
  }

  //TODO performance measurement for different chunk sizes
  def main(args: Array[String]): Unit = {
    val s = SignatureScanner()
    val file = new File("Minecraft.exe")
    s.scanAll(file, false).foreach(println)
    println("length of file: " + file.length())
  }

}