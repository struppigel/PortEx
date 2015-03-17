/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
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

import java.io.File
import java.io.RandomAccessFile

import com.github.katjahahn.parser.ByteArrayUtil
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.PhysicalLocation
import com.github.katjahahn.parser.ScalaIOUtil.hex
import com.github.katjahahn.parser.ScalaIOUtil.using
import com.github.katjahahn.parser.sections.rsrc.Resource

class VsVersionInfo(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val padding1: Int,
  val value: VsFixedFileInfo,
  val padding2: Int,
  val children: Array[FileInfo]) {

  override def toString(): String =
    s"""|wLength: $wLength
        |wValueLength: $wValueLength
        |wType: $wType
        |szKey: $szKey
        |padding1: $padding1
        |
        |VsFixedFileInfo:
        |$value
        |
        |padding2: $padding2
        |
        |Children:
        |${children.mkString(NL)}
      """.stripMargin
}

object VsVersionInfo {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  private val signature = "VS_VERSION_INFO"

  def apply(resource: Resource, file: File): VsVersionInfo = {
    require(resource.getType == "RT_VERSION", "No RT_VERSION resource!")
    val loc = resource.rawBytesLocation
    readVersionInfo(loc, file)
  }

  private def readVersionInfo(loc: PhysicalLocation, file: File): VsVersionInfo = {
    using(new RandomAccessFile(file, "r")) { raf =>
      val wLength = ByteArrayUtil.bytesToInt(loadBytes(loc.from, wordSize, raf))
      val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(loc.from + wordSize, wordSize, raf))
      val wType = ByteArrayUtil.bytesToInt(loadBytes(loc.from + wordSize * 2, wordSize, raf))
      val szKey = new String(loadBytes(loc.from + wordSize * 3, signature.length * wordSize, raf), "UTF_16LE")
      val padding1 = ByteArrayUtil.bytesToInt(loadBytes(loc.from + wordSize * 3 + signature.length * wordSize, wordSize, raf))
      val fixedInfoOffset = loc.from + wordSize * 4 + signature.length * wordSize + padding1
      val vsFixedFileInfo = VsFixedFileInfo(fixedInfoOffset, wValueLength, raf)
      val padding2 = ByteArrayUtil.bytesToInt(loadBytes(fixedInfoOffset + VsFixedFileInfo.size, wordSize, raf))
      val childrenOffset = fixedInfoOffset + VsFixedFileInfo.size + wordSize + padding2
      val children = readChildren(childrenOffset, raf)
      new VsVersionInfo(wLength, wValueLength, wType, szKey, padding1, vsFixedFileInfo, padding2, children)
    }
  }

  private def readChildren(offset: Long, raf: RandomAccessFile): Array[FileInfo] = {
    val varFileInfo = VarFileInfo(offset, raf)
    if(varFileInfo.szKey == VarFileInfo.signature) {
    val stringFileInfo = StringFileInfo(offset + varFileInfo.wLength, raf)
    Array[FileInfo](varFileInfo, stringFileInfo)
    } else {
      val stringFileInfo = StringFileInfo(offset, raf)
      Array(stringFileInfo)
    }
  }
}