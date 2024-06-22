/**
 * *****************************************************************************
 * Copyright 2014 Karsten Hahn
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
package com.github.struppigel.parser.sections.debug

import com.github.struppigel.parser.ByteArrayUtil._
import com.github.struppigel.parser.IOUtil._
import com.github.struppigel.parser.ScalaIOUtil.using
import CodeviewInfo._
import com.github.struppigel.parser.PhysicalLocation

import java.io.{File, RandomAccessFile}
import scala.collection.JavaConverters._

class CodeviewInfo(val age: Long,
                   val guid: Array[Byte],
                   val filePath: String,
                   val offset: Long) {
  
  def getPhysicalLocations(): java.util.List[PhysicalLocation] = 
    (new PhysicalLocation(offset, filePathOffset + filePath.length()) :: Nil).asJava
  

  def getInfo(): String = NL +
    "Codeview" + NL +
      "--------" + NL +
      s"Age:  $age" + NL +
      s"GUID: ${guidToString(guid)}" + NL +
      s"File: $filePath" + NL

}

object CodeviewInfo {

  /* offsets and sizes in bytes */
  private val guidOffset = 4
  private val ageOffset = 0x14
  private val filePathOffset = 0x18

  private val signatureSize = 4
  private val guidSize = 16
  private val ageSize = 4

  def guidToString(guid: Array[Byte]): String = {
    val part1 = guid.slice(0, 4).reverse
    val part2 = guid.slice(4, 6).reverse
    val part3 = guid.slice(6, 8).reverse
    val part4 = guid.slice(8, 10)
    val part5 = guid.slice(10, 16)
    byteToHex(part1, "") + "-" + byteToHex(part2, "") + "-" +
      byteToHex(part3, "") + "-" + byteToHex(part4, "") + "-" + byteToHex(part5, "")
  }

  def getInstance(ptrToRaw: Long, pefile: File): CodeviewInfo = {
    val maybe = apply(ptrToRaw, pefile)
    if (maybe.isDefined) maybe.get
    else throw new IllegalStateException("RSDS signature not found")
  }

  def apply(ptrToRaw: Long, pefile: File): Option[CodeviewInfo] = {
    using(new RandomAccessFile(pefile, "r")) { raf =>
      //check signature
      val signature = new String(loadBytes(ptrToRaw, signatureSize, raf))
      if (signature.equals("RSDS")) {
        val guid = loadBytes(ptrToRaw + guidOffset, guidSize, raf)
        val age = bytesToInt(loadBytes(ptrToRaw + ageOffset, ageSize, raf))
        val filePath = readNullTerminatedUTF8String(ptrToRaw + filePathOffset, raf)
        Some(new CodeviewInfo(age, guid, filePath, ptrToRaw))
      } else None
    }
  }
}