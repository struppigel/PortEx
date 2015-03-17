package com.github.katjahahn.parser.sections.rsrc.version

import java.io.RandomAccessFile
import com.github.katjahahn.parser.ByteArrayUtil
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.hex
import com.github.katjahahn.parser.ScalaIOUtil.using
import scala.collection.mutable.ListBuffer

class StringFileInfo(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val padding: Int,
  val children: Array[StringTable]) extends FileInfo {

  override def toString(): String =
    s"""|wLength: $wLength
        |wValueLength: $wValueLength
        |wType: $wType
        |szKey: $szKey
        |padding: $padding
        |string table children: 
        |${children.mkString(NL)}
      """.stripMargin

}

object StringFileInfo {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  val signature = "StringFileInfo"

  def apply(offset: Long, raf: RandomAccessFile): StringFileInfo = {
    // length of string file info block in bytes
    val wLength = ByteArrayUtil.bytesToInt(loadBytes(offset, wordSize, raf))
    // always zero
    val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize, wordSize, raf))
    val wType = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 2, wordSize, raf))
    val szKey = new String(loadBytes(offset + wordSize * 3, signature.length * wordSize, raf), "UTF_16LE")
    val padding = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 3 + signature.length * wordSize, wordSize, raf))
    val childrenOffset = offset + wordSize * 4 + signature.length * wordSize + padding
    val children = readChildren(childrenOffset, offset + wLength, padding, raf)
    new StringFileInfo(wLength, wValueLength, wType, szKey, padding, children)
  }

  private def readChildren(offset: Long, maxOffset: Long, padding: Int, raf: RandomAccessFile): Array[StringTable] = {
    var currOffset = offset
    val listBuf = ListBuffer[StringTable]()
    while(currOffset < maxOffset) {
      val elem = StringTable(currOffset, raf)
      listBuf += elem 
      currOffset += elem.wLength
    }
    listBuf.toArray
  }
}