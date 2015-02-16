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

  def getInfo(): String =
    s"""|
        |Codeview
        |--------
        |
        |Age:  $age 
        |GUID: ${guidToString(guid)}
        |File: $filePath
        |""".stripMargin

}

object CodeviewInfo {

  def guidToString(guid: Array[Byte]): String = {
    val part1 = guid.slice(0, 4).reverse
    val part2 = guid.slice(4, 6).reverse
    val part3 = guid.slice(6, 8).reverse
    val part4 = guid.slice(8, 10)
    val part5 = guid.slice(10, 16)
    byteToHex(part1, "") + "-" + byteToHex(part2, "") + "-" +
      byteToHex(part3, "") + "-" + byteToHex(part4, "") + "-" + byteToHex(part5, "")
  }

  def apply(ptrToRaw: Long, pefile: File): CodeviewInfo = {
    using(new RandomAccessFile(pefile, "r")) { raf =>
      val age = 0
      val filePath = ""
      //check signature
      val signature = new String(loadBytes(ptrToRaw, 4, raf))
      if (signature.equals("RSDS")) {
        val guid = loadBytes(ptrToRaw + 4, 16, raf)
        val age = bytesToInt(loadBytes(ptrToRaw + 0x14, 4, raf))
        val filePath = readNullTerminatedUTF8String(ptrToRaw + 0x18, raf)
        new CodeviewInfo(age, guid, filePath)
      } else throw new IllegalStateException("RSDS signature not found")
    }
  }
}