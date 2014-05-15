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
package com.github.katjahahn.tools

import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader
import java.io.File
import java.io.RandomAccessFile
import com.github.katjahahn.ByteArrayUtil
import com.github.katjahahn.msdos.MSDOSHeaderKey

class SlackSpaceReader(private val data: PEData) {
  
  type SpaceRange = (Long, Long)
  
  def readMSDOSPESigSpace(): SpaceRange = {
    val module = data.readMSDOSLoadModule()
    val endpoint = module.getImageSize() / 8
    val overlay = data.getMSDOSHeader().get(MSDOSHeaderKey.OVERLAY_NR)
    println(data.getMSDOSHeader().getInfo())
    val peSigOffset = data.getPESignature().getOffset()
    (endpoint, peSigOffset)
  }
  
  def getInfo(): String = "MSDOS - PESignature: " + readMSDOSPESigSpace
  
  def getBytesFor(range: SpaceRange): Array[Byte] = {
    using(new RandomAccessFile(data.getFile, "r")){raf =>
    	raf.seek(range._1)
    	val length = (range._2 - range._1).toInt
    	println("length: " + length)
    	val bytes = Array.fill(length)(0.toByte)
    	raf.readFully(bytes)
    	bytes
    }
  }
  
  private def using[A <: { def close(): Unit }, B](param: A)(f: A => B): B =
    try { f(param) } finally { param.close() }

}

object SlackSpaceReader {
  
  def main(args: Array[String]): Unit = {
    val data = PELoader.loadPE(new File("Holiday_Island.exe"))
    val reader = new SlackSpaceReader(data)
    val range = reader.readMSDOSPESigSpace()
    println("range: " + range)
    val bytes = reader.getBytesFor(range)
    val info = ByteArrayUtil.byteToHex(bytes)
    println("info size: " + bytes.length)
    println(info)
    println(new String(bytes))
  }
  
}
