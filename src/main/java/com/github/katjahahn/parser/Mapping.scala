package com.github.katjahahn.parser

import java.io.RandomAccessFile

/**
 * Maps all addresses of a virtual range to all addresses of the physical range.
 * <p>
 * Both ranges have to be of the same size.
 * The bytes are read from file only on request, making it possible to map large files.
 *
 * @author Katja Hahn
 *
 * @param va the virtual address range
 * @param physA the physical address range
 * @param the PEData object the mapping belongs to
 */
class Mapping(val va: VirtRange, val physA: PhysRange, private val data: PEData) {
  require(va.end - va.start == physA.end - physA.start)

  /**
   * Returns the byte at the virtual offset.
   * Requires the offset to be within the virtual range of the mapping.
   *
   * @param virtOffset the virtual offset to read the byte from
   * @return byte at virtOffset
   */
  def apply(virtOffset: Long): Byte = {
    require(va.contains(virtOffset))
    val pStart = physA.start
    val relOffset = virtOffset - va.start
    val readLocation = pStart + relOffset
    val file = data.getFile
    using(new RandomAccessFile(file, "r")) { raf =>
      raf.seek(readLocation)
      raf.readByte()
    }
  }

  /**
   * Returns size number of bytes at the virtual offset from mapping m.
   * Requires the offset + size to be within the virtual range of the mapping.
   *
   * @param virtOffset the virtual offset to start reading the bytes from
   * @param the size of the returned array
   * @return array containing the bytes starting from virtOffset
   */
  def apply(virtOffset: Long, size: Int): Array[Byte] = {
    require(va.contains(virtOffset) && va.contains(virtOffset + size))
    val pStart = physA.start
    val relOffset = virtOffset - va.start
    val readLocation = pStart + relOffset
    val file = data.getFile
    using(new RandomAccessFile(file, "r")) { raf =>
      raf.seek(readLocation)
      val length = (Math.min(readLocation + size, file.length) - readLocation).toInt
      val bytes = zeroBytes(length)
      raf.readFully(bytes)
      bytes ++ zeroBytes(size - length)
    }
  }

  /**
   * Fills an array with 0 bytes of the size
   */
  private def zeroBytes(size: Int): Array[Byte] =
    if (size >= 0) {
      Array.fill(size)(0.toByte)
    } else Array()

  private def using[A, B <: { def close(): Unit }](closeable: B)(f: B => A): A =
    try { f(closeable) } finally { closeable.close() }

}

/**
 * Simply a range.
 */
abstract class Range(val start: Long, val end: Long) {
  def unpack(): (Long, Long) = (start, end)

  /**
   * Returns whether the value is within the range.
   * 
   * @param value the value to check
   * @return true iff value is within range (start and end inclusive)
   */
  def contains(value: Long): Boolean =
    start <= value && end >= value
}

/**
 * Represents a range of virtual addresses
 */
class VirtRange(start: Long, end: Long) extends Range(start, end)

/**
 * Represents a range of physical addresses
 */
class PhysRange(start: Long, end: Long) extends Range(start, end)