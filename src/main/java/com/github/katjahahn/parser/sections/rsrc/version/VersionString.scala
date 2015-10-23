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
  val value: String) {

  override def toString(): String =
    szKey + ": " + { if (value.trim.isEmpty) "-" else value }
}

object VersionString {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  private val szKeyMaxDigits = "LegalTrademarks ".length

  def apply(offset: Long, raf: RandomAccessFile): VersionString = {
    val wLength = ByteArrayUtil.bytesToInt(loadBytes(offset, wordSize, raf))
    val maxOffset = offset + wLength
    val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize, wordSize, raf))
    val wType = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 2, wordSize, raf))
    val szBytes = loadBytes(offset + wordSize * 3, szKeyMaxDigits * dwordSize, raf).toList
    var prev = 0
    val szSize = szBytes.indexWhere { x => val i = prev; prev = x; i == 0 && x == 0 }
    val szKey = new String(szBytes.take(szSize).toArray, "UTF_16LE")
    val valueOffsetStart = offset + wordSize * 3 + szSize
    val bytesToRead = Math.min(maxOffset - valueOffsetStart, wValueLength * wordSize).toInt
    val valueOffset = valueOffsetStart + loadBytes(valueOffsetStart, bytesToRead, raf).indexWhere(0 !=)
    val value = new String(loadBytes(valueOffset, bytesToRead, raf), "UTF_16LE")
    new VersionString(wLength, wValueLength, wType, szKey, value)
  }

}