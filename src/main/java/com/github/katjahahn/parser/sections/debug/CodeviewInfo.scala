package com.github.katjahahn.parser.sections.debug

import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.using
import java.io.RandomAccessFile
import java.io.File
import com.github.katjahahn.parser.ByteArrayUtil._
import CodeviewInfo._

class CodeviewInfo(private val age: Long,
                   private val guid: Array[Byte],
                   private val filePath: String) {

  def getInfo(): String = NL +
    "Codeview" + NL +
      "--------" + NL +
      s"Age:  $age" + NL +
      s"GUID: ${guidToString(guid)}" + NL +
      s"File: $filePath" + NL

}

object CodeviewInfo {

  /* offsets and sizes in bytes */
  private val guidOffset = 4
  private val ageOffset = 0x14
  private val filePathOffset = 0x18

  private val signatureSize = 4
  private val guidSize = 16
  private val ageSize = 4

  def guidToString(guid: Array[Byte]): String = {
    val part1 = guid.slice(0, 4).reverse
    val part2 = guid.slice(4, 6).reverse
    val part3 = guid.slice(6, 8).reverse
    val part4 = guid.slice(8, 10)
    val part5 = guid.slice(10, 16)
    byteToHex(part1, "") + "-" + byteToHex(part2, "") + "-" +
      byteToHex(part3, "") + "-" + byteToHex(part4, "") + "-" + byteToHex(part5, "")
  }

  def getInstance(ptrToRaw: Long, pefile: File): CodeviewInfo = {
    val maybe = apply(ptrToRaw, pefile)
    if (maybe.isDefined) maybe.get
    else throw new IllegalStateException("RSDS signature not found")
  }

  def apply(ptrToRaw: Long, pefile: File): Option[CodeviewInfo] = {
    using(new RandomAccessFile(pefile, "r")) { raf =>
      val age = 0
      val filePath = ""
      //check signature
      val signature = new String(loadBytes(ptrToRaw, signatureSize, raf))
      if (signature.equals("RSDS")) {
        val guid = loadBytes(ptrToRaw + guidOffset, guidSize, raf)
        val age = bytesToInt(loadBytes(ptrToRaw + ageOffset, ageSize, raf))
        val filePath = readNullTerminatedUTF8String(ptrToRaw + filePathOffset, raf)
        Some(new CodeviewInfo(age, guid, filePath))
      } else None
    }
  }
}