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

package com.github.struppigel.tools

import com.github.struppigel.parser.PEData
import com.github.struppigel.parser.optheader.WindowsEntryKey

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
    val length = file.length()
    val byteArray: Array[Byte] = Array.fill(length.toInt)(0.toByte)
    val buffer = ByteBuffer.wrap(byteArray)
    buffer.order(ByteOrder.LITTLE_ENDIAN)

    ch.read(buffer)

    // overwrite checksum with zeroes
    buffer.putInt(checksumOffset.toInt, 0x0000)

    // start calculation
    buffer.position(0)
    while (buffer.hasRemaining() && buffer.remaining() >= 4) {
      sum += buffer.getInt() & 0xffffffffL
      if (sum > top) {
        sum = (sum & 0xffffffffL) + (sum >>> 32)
      }

    }
    // calculation on padded remainder
    val remainingBytes: Array[Byte] = Array.fill(4)(0.toByte)
    var i = 0
    while (buffer.hasRemaining()) {
      remainingBytes(i) = buffer.get()
      i += 1
    }
    sum += ByteBuffer.wrap(remainingBytes).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xffffffffL
    if (sum > top) {
      sum = (sum & 0xffffffffL) + (sum >>> 32)
    }
    // fold
    var high = sum >>> 16
    sum &= 0xFFFF
    sum += high
    high = sum >>> 16
    sum += high
    sum &= 0xFFFF
    sum += length
    sum
  }

}