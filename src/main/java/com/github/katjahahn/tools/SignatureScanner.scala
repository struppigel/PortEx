package com.github.katjahahn.tools

import java.io.File
import com.sun.org.apache.xalan.internal.xsltc.compiler.StartsWithCall
import scala.collection.mutable.ListBuffer
import java.nio.charset.MalformedInputException
import scala.io.Codec
import java.nio.charset.CodingErrorAction

object SignatureScanner {

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
    val arr = hex.replaceAll("[^0-9A-Fa-f??]", "").sliding(2, 2).toArray
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
    println("loading signatures")
    val list = loadSignatures(new File("UserDB.TXT"));
    println(list(0))
  }

}