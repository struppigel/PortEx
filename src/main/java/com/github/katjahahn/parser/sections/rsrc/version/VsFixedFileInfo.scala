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

import java.io.RandomAccessFile
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.{ using, hex }
import com.github.katjahahn.parser.ByteArrayUtil

class VsFixedFileInfo(
  val dwSignature: Long,
  val wMajorStrucVersion: Int,
  val wMinorStrucVersion: Int,
  val dwFileVersionMS: Long,
  val dwFileVersionLS: Long,
  val dwProductVersionMS: Long,
  val dwProductVersionLS: Long,
  val dwFileFlagsMask: Long,
  val dwFileFlags: Long,
  val fileOS: List[FileOS],
  val fileType: FileType,
  val fileSubtype: FileSubtype,
  val dwFileDateMS: Long,
  val dwFileDateLS: Long) {

  override def toString(): String =
    s"signature: ${hex(dwSignature)}" + NL +
      s"binary version:  ${wMajorStrucVersion}.${wMinorStrucVersion}" + NL +
      s"file version: ${dwFileVersionMS}.${dwFileVersionLS}" + NL +
      s"product version: ${dwProductVersionMS}.${dwProductVersionLS}" + NL +
      s"file flags mask: ${hex(dwFileFlagsMask)}" + NL +
      s"file flags: ${hex(dwFileFlags)}" + NL +
      s"file OS: ${fileOS.map(_.getDescription).mkString(", ")}" + NL +
      s"file type: ${fileType.getDescription}" + NL +
      s"file subtype: ${fileSubtype.getDescription}" + NL +
      s"file date: ${dwFileDateMS}.${dwFileDateLS}"

}

object VsFixedFileInfo {

  //TODO move to utility class
  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8

  val signature = 0xFEEF04BD

  val members = 13
  val size = members * dwordSize

  def apply(offset: Long, wValueLength: Int, raf: RandomAccessFile): Option[VsFixedFileInfo] = {
    val dwSignature = ByteArrayUtil.bytesToLong(loadBytes(offset, dwordSize, raf))
    if (dwSignature == signature) {
      val wMinorVersion = ByteArrayUtil.bytesToInt(loadBytes(offset + dwordSize, wordSize, raf))
      val wMajorVersion = ByteArrayUtil.bytesToInt(loadBytes(offset + dwordSize + wordSize, wordSize, raf))
      val dwFileVersionMS = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 2, dwordSize, raf))
      val dwFileVersionLS = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 3, dwordSize, raf))
      val dwProductVersionMS = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 4, dwordSize, raf))
      val dwProductVersionLS = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 5, dwordSize, raf))
      val dwFileFlagsMask = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 6, dwordSize, raf))
      val dwFileFlags = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 7, dwordSize, raf))
      val dwFileOS = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 8, dwordSize, raf))
      //TODO use mask to collect all that fit
      val fileOS = FileOS.values.toBuffer.filter { os => (os.getValue & dwFileOS) != 0 }
      if (fileOS.isEmpty) fileOS += FileOS.VOS_UNKNOWN
      val dwFileType = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 9, dwordSize, raf))
      val fileType = FileType.values.find(_.getValue == dwFileType).getOrElse(FileType.VFT_UNKNOWN)
      val dwFileSubtype = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 10, dwordSize, raf))
      val fileSubtype = {
        if (fileType == FileType.VFT_DRV)
          DrvFileSubtype.values.find(_.getValue == dwFileSubtype).getOrElse(new UndefinedSubtype(dwFileSubtype, true))
        else if (fileType == FileType.VFT_FONT)
          FontFileSubtype.values.find(_.getValue == dwFileSubtype).getOrElse(new UndefinedSubtype(dwFileSubtype, true))
        else new UndefinedSubtype(dwFileSubtype)
      }
      val dwFileDateMS = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 11, dwordSize, raf))
      val dwFileDateLS = ByteArrayUtil.bytesToLong(loadBytes(offset + dwordSize * 12, dwordSize, raf))
      Some(new VsFixedFileInfo(dwSignature, wMajorVersion, wMinorVersion, dwFileVersionMS,
        dwFileVersionLS, dwProductVersionMS, dwProductVersionLS, dwFileFlagsMask,
        dwFileFlags, fileOS.toList, fileType, fileSubtype, dwFileDateMS, dwFileDateLS))
    } else None
  }

}