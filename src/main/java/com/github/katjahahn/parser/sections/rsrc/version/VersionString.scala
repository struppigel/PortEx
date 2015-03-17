package com.github.katjahahn.parser.sections.rsrc.version

import java.io.RandomAccessFile
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.{ using, hex }
import com.github.katjahahn.parser.ByteArrayUtil

class VersionString(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val padding: Int,
  val value: String) {

  override def toString(): String =
    s"${szKey}: $value wValueLength: $wValueLength padding: $padding"
}

object VersionString {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  private val szKeyMaxDigits = "LegalCopyright".length

  def apply(offset: Long, raf: RandomAccessFile): VersionString = {
    val wLength = ByteArrayUtil.bytesToInt(loadBytes(offset, wordSize, raf))
    val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize, wordSize, raf))
    val wType = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 2, wordSize, raf))
    val szBytes = loadBytes(offset + wordSize * 3, szKeyMaxDigits * wordSize, raf).toList
    var prev = 0
    val szSize = szBytes.indexWhere { x => val i = prev; prev = x; i == 0 && x == 0 }
    val szKey = new String(szBytes.take(szSize).toArray, "UTF_16LE")
    val padding = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 3 + szSize, wordSize, raf))
    val valueOffset = offset + wordSize * 4 + szSize + padding 
    val value = new String(loadBytes(valueOffset, wValueLength, raf), "UTF_16LE")
    new VersionString(wLength, wValueLength, wType, szKey, padding, value)
  }

}