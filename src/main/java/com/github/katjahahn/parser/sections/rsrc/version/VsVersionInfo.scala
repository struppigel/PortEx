/*******************************************************************************
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
 ******************************************************************************/
package com.github.katjahahn.parser.sections.rsrc.version

import java.io.File
import com.github.katjahahn.parser.sections.rsrc.Resource
import com.github.katjahahn.parser.PhysicalLocation
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.{ using, hex }
import com.github.katjahahn.parser.ByteArrayUtil
import java.io.RandomAccessFile

class VsVersionInfo(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val value: VsFixedFileInfo,
  val children: Array[Byte]) {
  
  override def toString(): String = 
    s"""|wLength: $wLength
        |wValueLength: $wValueLength
        |wType: $wType
        |szKey: $szKey
        |
        |VsFixedFileInfo:
        |$value
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
      val offset = loc.from + wordSize * 3 + signature.length * wordSize
      val vsFixedFileInfo = VsFixedFileInfo(offset, wValueLength, raf)
      val children = null //TODO implement
      new VsVersionInfo(wLength, wValueLength, wType, szKey, vsFixedFileInfo, children)
    }
  }
}