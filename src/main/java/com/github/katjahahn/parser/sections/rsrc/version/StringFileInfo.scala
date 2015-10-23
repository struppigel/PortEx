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
  val children: Array[StringTable]) extends FileInfo {

  override def toString(): String =
    szKey + NL + "---------------" + NL + children.mkString(NL + NL) 

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
    if(szKey == signature) {
      val childrenOffset = offset + wordSize * 3 + signature.length * wordSize
      val children = readChildren(childrenOffset, offset + wLength, raf)
      new StringFileInfo(wLength, wValueLength, wType, szKey, children)
    } else new StringFileInfo(wLength, wValueLength, wType, szKey, Array.empty)
  }

  private def readChildren(offset: Long, maxOffset: Long, raf: RandomAccessFile): Array[StringTable] = {
    var currOffset = offset
    val listBuf = ListBuffer[StringTable]()
    while (currOffset < maxOffset) {
      val childOffset = currOffset + loadBytes(currOffset, 0x50, raf).indexWhere(0 !=)
      val elem = StringTable(childOffset, raf)
      listBuf += elem
      currOffset = childOffset + elem.wLength
    }
    listBuf.toArray
  }
}