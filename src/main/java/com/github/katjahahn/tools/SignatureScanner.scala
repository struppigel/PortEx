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

class SignatureScanner(signatures: List[Signature]) {
  
  private val longestSigSequence: Int = signatures.foldLeft(0)(
    (i, s) => if (s.signature.length > i) s.signature.length
    		  else i)
    		  
  private lazy val epOnlyFalseSigs: SigTree = 
    createSigTree(signatures.filter(_.epOnly == false))

  private def createSigTree(list: List[Signature]): SigTree = {
    var tree = SigTree()
    list.foreach(s => tree += s)
    tree
  }
  
  /**
   * @param file the PE file to be scanned
   * @return the best match found
   */
  def scan(file: File): String = {
    scanAll(file).last
  }

  /**
   * @param file the file to be scanned
   * @param chunkSize default value is 128 MB
   * @return list with all matches found
   */
  def scanAll(file: File, chunkSize: Int = 134217728): List[String] = {
    def bytesMatched(sig: Signature): Int =
      sig.signature.filter(x => x match { case Some(s) => true; case None => false }).length
    var matches = findAllEPMatches(file) ::: findAllEPFalseMatches(file, chunkSize)
    for (m <- matches) yield m.name + " bytes matched: " + bytesMatched(m)
  }

  private def findAllEPFalseMatches(file: File, chunkSize: Int): List[Signature] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val matches = ListBuffer[Signature]()
      var i = 0
      println("longest sig " + longestSigSequence)
      for (chaddr <- 0L to file.length() by (chunkSize - longestSigSequence)) { //TODO test this!
        i = i + 1
        if (i % 100000 == 0) println("reading chunk " + i + " at address " + chaddr)
        val bytes = Array.fill(chunkSize)(0.toByte)
        raf.seek(chaddr)
        val bytesRead = raf.read(bytes)
        for (addr <- 0L to (bytesRead - longestSigSequence)) {
          val slicedarr = bytes.slice(addr.toInt, addr.toInt + longestSigSequence)
          matches ++= findAllSigTreeMatches(slicedarr, epOnlyFalseSigs)
        }
      }
      matches.toList
    }
  }
  
  
  private def findAllSigTreeMatches(bytes: Array[Byte], sigtree: SigTree): List[Signature] = 
    sigtree.findMatches(bytes.toList)

  private def findAllEPMatches(file: File): List[Signature] = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val data = PELoader.loadPE(file)
      val entryPoint = getEntryPoint(data)
      raf.seek(entryPoint.toLong)
      var bytes = Array.fill(longestSigSequence)(0.toByte)
      val bytesRead = raf.read(bytes)
      findAllMatches(bytes.slice(0, bytesRead), signatures)
    }
  }

  private def using[A <: { def close(): Unit }, B](param: A)(f: A => B): B =
    try { f(param) } finally { param.close() }

  //replace with findAllSigTreeMatches
  private def findAllMatches(bytes: Array[Byte], siglist: List[Signature]): List[Signature] = {
    def matches(sig: Array[Option[Byte]], bytes: Array[Byte]): Boolean = {
      sig.zip(bytes).forall(tuple =>
        tuple match {
          case (None, _) => true
          case (o, b) => o.get == b
        })
    }
    siglist.filter(s => matches(s.signature, bytes))
  }

  //TODO test for matches with peid
  private def getEntryPoint(data: PEData): Int = {
    val rva = data.getOptionalHeader().getStandardFieldEntry(ADDR_OF_ENTRY_POINT).value
    val section = SectionLoader.getSectionByRVA(data.getSectionTable(), rva)
    val phystovirt = section.get(SectionTableEntryKey.VIRTUAL_ADDRESS) - section.get(SectionTableEntryKey.POINTER_TO_RAW_DATA)
    rva - phystovirt
  }
}

object SignatureScanner {

  private val defaultSigs = new File("userdb.txt")

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
    s.scanAll(new File("Holiday_Island.exe")).foreach(println)
  }

}