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

package com.github.katjahahn.tools

import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.optheader.WindowsEntryKey

import java.nio.{ByteBuffer, ByteOrder}
import java.nio.channels.FileChannel

object ChecksumVerifier {
  
  def hasValidChecksum(peData: PEData): Boolean = {
    val checksum = peData.getOptionalHeader.get(WindowsEntryKey.CHECKSUM)
    val computedChecksum = computeChecksum(peData)
    checksum == computedChecksum
  }
  
  def computeChecksum(peData: PEData): Long = {
    val file = peData.getFile
    val ch = FileChannel.open(file.toPath)
    val checksumOffset = peData.getOptionalHeader.getField(WindowsEntryKey.CHECKSUM).getOffset
    ch.position(0)
    var sum = 0L
    val top = Math.pow(2, 32).toLong
    val overlay = new Overlay(file)
    val length = (if (overlay.exists) overlay.getOffset else ch.size)
    val byteArray: Array[Byte] = Array.fill(length.toInt)(0.toByte)
    var buffer = ByteBuffer.wrap(byteArray)
    buffer.order(ByteOrder.LITTLE_ENDIAN)

    ch.read(buffer)
    buffer.putInt(checksumOffset.toInt, 0x0000)

    buffer.position(0)
    while (buffer.hasRemaining() && buffer.remaining() >= 4) {
      sum += buffer.getInt() & 0xffffffffL
      if (sum > top) {
        sum = (sum & 0xffffffffL) + (sum >> 32)
      }
    }
    sum = (sum & 0xffff) + (sum >> 16)
    sum = sum + (sum >> 16)
    sum = sum & 0xffff
    sum += length
    sum
  }

}