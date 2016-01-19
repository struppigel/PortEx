package com.github.katjahahn.tools

import java.io.File
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.optheader.WindowsEntryKey
import java.nio.channels.FileChannel
import java.nio.ByteBuffer
import java.nio.ByteOrder
import com.github.katjahahn.parser.PEData

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