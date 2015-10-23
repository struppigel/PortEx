package com.github.katjahahn.parser.sections.rsrc.version

import java.io.RandomAccessFile
import com.github.katjahahn.parser.ByteArrayUtil
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.hex
import com.github.katjahahn.parser.ScalaIOUtil.using
import scala.collection.mutable.ListBuffer

class StringTable(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val children: Array[VersionString]) {

  override def toString(): String =
    s"language ID: 0x${szKey.substring(0, 4)}" + NL +
      s"code page: 0x${szKey.substring(4)}" + NL +
      children.mkString(NL)
}

object StringTable {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  private val signatureDigits = 8

  def apply(offset: Long, raf: RandomAccessFile): StringTable = {
    // length in bytes of string table structure
    val wLength = ByteArrayUtil.bytesToInt(loadBytes(offset, wordSize, raf))
    // must be zero TODO add to anomalies
    val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize, wordSize, raf))
    val wType = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 2, wordSize, raf))
    // always 8 digits
    val szKey = new String(loadBytes(offset + wordSize * 3, signatureDigits * wordSize, raf), "UTF_16LE")
    val childrenOffset = offset + wordSize * 4 + signatureDigits * wordSize
    val maxOffset = Math.min(offset + wLength, raf.length)
    val children = readChildren(childrenOffset, maxOffset, raf)
    new StringTable(wLength, wValueLength, wType, szKey, children)
  }

  private def readChildren(offset: Long, maxOffset: Long, raf: RandomAccessFile): Array[VersionString] = {
    var currOffset = offset
    val listBuf = ListBuffer[VersionString]()
    while (currOffset < maxOffset) {
      val childOffset = currOffset + loadBytes(currOffset, 0x50, raf).indexWhere(0 !=)
      val elem = VersionString(childOffset, raf)
      listBuf += elem
      currOffset = childOffset + elem.wLength
    }
    listBuf.toArray
  }

}