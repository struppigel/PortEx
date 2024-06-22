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

package com.github.struppigel.parser.sections.rsrc.version

import com.github.struppigel.parser.IOUtil._
import com.github.struppigel.parser.ByteArrayUtil

import java.io.RandomAccessFile

class VarFileInfo(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val children: Array[Var]) extends FileInfo {

  override def toString(): String =
    szKey + NL +
    "------------" + NL + 
  children.mkString(NL)

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
    if(szKey == signature) {
      val childrenOffset = offset + wordSize * 3 + signature.length * wordSize
      val children = readChildren(childrenOffset, raf)
      new VarFileInfo(wLength, wValueLength, wType, szKey, children)
    } else new VarFileInfo(wLength, wValueLength, wType, szKey, Array.empty)
  }

  private def readChildren(offset: Long, raf: RandomAccessFile): Array[Var] = {
    //TODO implement
    Array.empty
  }
}