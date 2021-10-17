/** *****************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * **************************************************************************** */
package com.github.katjahahn.parser

import com.github.katjahahn.parser.msdos.MSDOSHeader
import com.google.common.primitives.Bytes
import org.apache.logging.log4j.{LogManager, Logger}

/**
 * Reads the Rich Header if it exists
 *
 * @author Karsten Philipp Boris Hahn
 *
 */
class RichHeader( private  val decodedRich : Array[Byte], private val xorKey : Array[Byte]) {

  case class RichEntry(pid: Int, pv : Int, pc : Int)

  private val logger = LogManager.getLogger(classOf[RichHeader].getName)

  /**
   * Returns the decoded Rich header starting and including 'DanS', but excluding 'Rich'
   *
   * @return byte array of the decoded Rich header
   */
  // TODO verify that xorKey is also the checksum of COFFHeader
  def getDecodedRichHeaderBytes: Array[Byte] = decodedRich.clone()

  /**
   * Parse and compose list of all entries in the decoded Rich header
   *
   * @return list of all Rich entries
   */
  def getRichEntries(): List[RichEntry] = {
    val wordLen = 4
    // skip DanS and padding bytes, we start by slicing into blocks of 4 bytes already removing DanS as first block
    val dataBlocks = for(i <- wordLen until decodedRich.length by wordLen) yield decodedRich.slice(i, i + wordLen)
    // remove padding of 0 byte words TODO adjust to 16 byte alignment
    val paddingRemoved = dataBlocks.dropWhile(_.sameElements(Array[Byte](0,0,0,0)))
    logger.debug("Removed padding and DanS size " + (decodedRich.length - (paddingRemoved.length * 4)))
    // each entry is 8 bytes, where the first 2 bytes are the pid, the next 2 bytes the pv and the last 4 bytes the pc
    // note that paddingRemoved consists of blocks with 4 bytes, whereas one entry is 8 bytes
    val result = for(i <- paddingRemoved.indices by 2) yield
      RichEntry(
        pid = ByteArrayUtil.bytesToInt(paddingRemoved(i).slice(0, 2)), // bytes 0-1 == Pid
        pv = ByteArrayUtil.bytesToInt(paddingRemoved(i).slice(2, 4)),  // bytes 2-3 == Pv
        pc = ByteArrayUtil.bytesToInt(paddingRemoved(i + 1))           // bytes 4-7 == Pc
      )
    result.toList
  }

  def getInfo : String = getRichEntries().mkString(IOUtil.NL)
}

object RichHeader {

  private val logger = LogManager.getLogger(classOf[RichHeader].getName)

  val richMagic : Array[Byte] = "Rich".getBytes
  val danSMagic : Array[Byte] = "DanS".getBytes

  private val wordLen = 4

  def apply(bytes: Array[Byte]) : RichHeader = {
    val richOffset = Bytes.indexOf(bytes, richMagic)
    if(richOffset == -1) throw new FileFormatException("No Rich Header found")
    if(bytes.length < richOffset + 8) throw new FileFormatException("Rich Header malformed or truncated")
    val xorKey = bytes.slice(richOffset + 4, richOffset + 8)
    // decode rich header backwards
    val decodedRich = decodeRichHeader(bytes, richOffset, xorKey)
    println(ByteArrayUtil.byteToHex(decodedRich))
    new RichHeader(decodedRich, xorKey)
  }

  private def decodeRichHeader(bytes: Array[Byte], richOffset: Int, xorKey: Array[Byte]) : Array[Byte] = {
    // start by finding DanS
    var danSOffset = -1
    for (i <- richOffset - richMagic.length to 0 by -wordLen) {
      val encodedDword : Array[Byte] = bytes.slice(i, i + wordLen)
      val decodedDword = for(j <- 0 until wordLen) yield (encodedDword(j) ^ xorKey(j)).toByte
      if (decodedDword.sameElements(danSMagic)) danSOffset = i
    }
    // no DanS found
    if(danSOffset == -1) throw new FileFormatException("Rich header malformed, no DanS found")

    // construct decoded header bytes, currently doesn't include "Rich"
    val encoded = bytes.slice(danSOffset, richOffset)
    // only decode until "Rich"
    val decoded = for (i <- encoded.indices) yield (encoded(i) ^ xorKey(i % wordLen)).toByte

    decoded.toArray
  }

  def newInstance(headerbytes : Array[Byte]) : RichHeader = apply(headerbytes)

}
