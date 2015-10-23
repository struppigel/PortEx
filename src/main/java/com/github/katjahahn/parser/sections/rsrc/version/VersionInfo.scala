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
  val value: Option[VsFixedFileInfo],
  val children: Array[FileInfo]) extends VersionInfo {

  override def toString(): String = {
    {
      if (value.isDefined) {
        "VS_FIXEDFILEINFO" + NL +
          "----------------" + NL +
          value.get + NL + NL
      } else "No VS_FIXEDFILEINFO present!" + NL + NL
    } +
      { if (children.isEmpty) "Invalid version info children!" else children.mkString(NL) }
  }
}

class EmptyVersionInfo extends VersionInfo {
  override def toString(): String =
    "-empty-"
}

abstract class VersionInfo {}

object VersionInfo {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  private val signature = "VS_VERSION_INFO"

  def apply(resource: Resource, file: File): VersionInfo = {
    require(resource.getType == "RT_VERSION", "No RT_VERSION resource!")
    val loc = resource.rawBytesLocation
    if (isValid(loc, file)) {
      readVersionInfo(loc, file)
    } else new EmptyVersionInfo()
  }

  private def isValid(location: PhysicalLocation, file: File): Boolean = {
    location.from >= 0 && location.size + location.from < file.length
  }

  private def readVersionInfo(loc: PhysicalLocation, file: File): VsVersionInfo = {

    using(new RandomAccessFile(file, "r")) { raf =>
      val wLength = ByteArrayUtil.bytesToInt(loadBytes(loc.from, wordSize, raf))
      val wValueLength = ByteArrayUtil.bytesToInt(loadBytes(loc.from + wordSize, wordSize, raf))
      val wType = ByteArrayUtil.bytesToInt(loadBytes(loc.from + wordSize * 2, wordSize, raf))
      val szKey = new String(loadBytes(loc.from + wordSize * 3, signature.length * wordSize, raf), "UTF_16LE")
      val fixedOffsetStart = loc.from + wordSize * 3 + signature.length * wordSize
      var fixedInfoOffset = fixedOffsetStart + loadBytes(fixedOffsetStart, 0x50, raf).indexWhere(0 !=)
      val maybeVsFixedFileInfo = if (wValueLength > 0) {
        VsFixedFileInfo(fixedInfoOffset, wValueLength, raf)
      } else {
        fixedInfoOffset = fixedOffsetStart
        None
      }
      val childrenOffsetStart = fixedInfoOffset + VsFixedFileInfo.size
      val childrenOffset = childrenOffsetStart + loadBytes(childrenOffsetStart, 0x50, raf).indexWhere(0 !=)
      val children = readChildren(childrenOffset, raf)
      new VsVersionInfo(wLength, wValueLength, wType, szKey, maybeVsFixedFileInfo, children)
    }

  }

  private def readChildren(offset: Long, raf: RandomAccessFile): Array[FileInfo] = {
    if (VarFileInfo(offset, raf).szKey == VarFileInfo.signature) {
      val varFileInfo = VarFileInfo(offset, raf)
      val strFileOffsetStart = offset + varFileInfo.wLength
      val strFileOffset = strFileOffsetStart + loadBytes(strFileOffsetStart, 0x50, raf).indexWhere(0 !=)
      val stringFileInfo = StringFileInfo(strFileOffset, raf)
      if (stringFileInfo.szKey == StringFileInfo.signature) {
        Array(varFileInfo, stringFileInfo)
      } else Array(varFileInfo)
    } else if (StringFileInfo(offset, raf).szKey == StringFileInfo.signature) {
      val stringFileInfo = StringFileInfo(offset, raf)
      val varFileOffsetStart = offset + stringFileInfo.wLength
      val varFileOffset = varFileOffsetStart + loadBytes(varFileOffsetStart, 0x50, raf).indexWhere(0 !=)
      val varFileInfo = VarFileInfo(varFileOffset, raf)
      if (varFileInfo.szKey == StringFileInfo.signature) {
        Array(stringFileInfo, varFileInfo)
      } else Array(stringFileInfo)
    } else Array.empty
  }
}