/**
 * *****************************************************************************
 * Copyright 2016 Katja Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */

package com.github.katjahahn.parser.sections.rsrc.version

import com.github.katjahahn.parser.{ByteArrayUtil, FileFormatException}
import com.github.katjahahn.parser.IOUtil._

import java.io.RandomAccessFile

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
    
    def isValidKey(key: String):Boolean = !(key.trim.isEmpty)
    
    val wLength = ByteArrayUtil.bytesToInt(loadBytes(offset, wordSize, raf))
    val maxOffset = offset + wLength
    val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize, wordSize, raf))
    val wType = ByteArrayUtil.bytesToInt(loadBytes(offset + wordSize * 2, wordSize, raf))
    val szBytes = loadBytes(offset + wordSize * 3, szKeyMaxDigits * dwordSize, raf).toList
    var prev = 0
    val szSize = szBytes.indexWhere { x => val i = prev; prev = x; i == 0 && x == 0 }
    val szKey = new String(szBytes.take(szSize).toArray, "UTF_16LE")
    if (isValidKey(szKey)) {
      val valueOffsetStart = offset + wordSize * 3 + szSize
      val valueOffset = valueOffsetStart + loadBytes(valueOffsetStart, wValueLength * wordSize, raf).indexWhere(0 !=)
      val bytesToRead = Math.min(maxOffset - valueOffset, wValueLength * wordSize).toInt
      val value = new String(loadBytes(valueOffset, bytesToRead, raf), "UTF_16LE")
      new VersionString(wLength, wValueLength, wType, szKey, value)
    } else {
      throw new FileFormatException("invalid version string szKey");
    }
  }

}