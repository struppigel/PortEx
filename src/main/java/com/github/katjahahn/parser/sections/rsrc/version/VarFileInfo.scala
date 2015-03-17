package com.github.katjahahn.parser.sections.rsrc.version

import java.io.RandomAccessFile
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.{ using, hex }
import com.github.katjahahn.parser.ByteArrayUtil

class VarFileInfo(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val padding: Int,
  val children: Array[Var]) extends FileInfo {

  override def toString(): String =
    s"""|wLength: $wLength
        |wValueLength: $wValueLength
        |wType: $wType
        |szKey: $szKey
        |padding: $padding
        |children: ${children.mkString(NL)}
      """.stripMargin

}

object VarFileInfo {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  val signature = "VarFileInfo"

  def apply(offset: Long, raf: RandomAccessFile): VarFileInfo = {
    val wLength = ByteArrayUtil.bytesToInt(loadBytes(offset, wordSize, raf))
    val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize, wordSize, raf))
    val wType = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 2, wordSize, raf))
    val szKey = new String(loadBytes(offset + wordSize * 3, signature.length * wordSize, raf), "UTF_16LE")
    val padding = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 3 + signature.length * wordSize, wordSize, raf))
    val childrenOffset = offset + wordSize * 4 + signature.length * wordSize + padding
    val children = readChildren(childrenOffset, raf)
    new VarFileInfo(wLength, wValueLength, wType, szKey, padding, children)
  }
  
  private def readChildren(offset: Long, raf: RandomAccessFile): Array[Var] = {
    Array.empty
  }
}