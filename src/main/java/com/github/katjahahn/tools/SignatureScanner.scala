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
import com.github.katjahahn.sections.SectionTableEntryKey

class SignatureScanner(signatures: List[Signature]) {
  private val longestSigSequence: Int = signatures.foldLeft(0)(
        (i, s) => if (s.signature.length > i) s.signature.length 
        		  else i )

  def scan(file: File): String = {
    val data = PELoader.loadPE(file)
    val entryPoint = getEntryPoint(data)
    val raf = new RandomAccessFile(file, "r")
    raf.seek(entryPoint.toLong)
    val bytes = Array.fill(longestSigSequence)(0.toByte)
    raf.read(bytes)
    val signature: Option[Signature] = find(bytes)
    signature match {
      case None => "no signature found"
      case _ => signature.get.name
    }
  }

  private def find(bytes: Array[Byte]): Option[Signature] = {
    def matches(sig: Array[Option[Byte]], bytes: Array[Byte]): Boolean = {
      sig.zip(bytes).forall(tuple =>
        tuple match {
          case (None, _) => true
          case (o, b) => o.get == b
        })
    }
    signatures.find(s => matches(s.signature, bytes))
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

  private val defaultSigs = new File("UserDB.TXT")

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
    Signature(name, ep_only, sigbytes)
  }

  private def hex2bytes(hex: String): Array[Option[Byte]] = {
    val arr = hex.replaceAll("[^0-9A-Fa-f?]", "").sliding(2, 2).toArray
    arr.map(str => str match {
      case "??" => None
      case _ => Some(Integer.parseInt(str, 16).toByte)
    })
  }

  private def bytes2hex(bytes: Array[Option[Byte]], sep: String): String = {
    bytes.foldLeft("")((s, b) => b match {
      case None => s + sep + "??"
      case _ => s + sep + "%02x".format(b.get)
    })
  }

  case class Signature(name: String, ep: Boolean, signature: Array[Option[Byte]]) {
    override def toString(): String = s"""|name: $name
    									  |signature: ${bytes2hex(signature, " ")}
	                                      |ep_only: $ep """.stripMargin
  }

  def main(args: Array[String]): Unit = {
    val s = SignatureScanner()
    println(s.scan(new File("/home/deque/Downloads/peidt.exe")))
  }

}