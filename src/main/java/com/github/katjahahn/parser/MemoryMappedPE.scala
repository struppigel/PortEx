package com.github.katjahahn.parser

import com.github.katjahahn.parser.sections.SectionTable
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.SectionHeaderKey._
import com.github.katjahahn.parser.sections.SectionLoader
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.optheader.OptionalHeader
import java.nio.file.Files

/**
 * Represents the PE file content as it is mapped to memory.
 * <p>
 * Only maps section bytes for now. This is the first test with the content loaded
 * all at once. Will be changed later.
 */
class MemoryMappedPE(private val bytes: Array[Byte]) {

  private var relativeVA = 0

  //Java getters and setters
  def getRelativeVA() = relativeVA
  def setRelativeVA(value: Int): Unit = relativeVA = value

  def apply(i: Int): Byte = bytes(relativeVA + i)
  def get(i: Int): Byte = apply(i)

  def length(): Int = bytes.length

  def slice(from: Long, until: Long): Array[Byte] = bytes.slice(from.toInt, until.toInt)
  def indexWhere(p: Byte => Boolean, from: Int): Long = bytes.indexWhere(p, from)

  //TODO remove
  def getArray(): Array[Byte] = bytes

}

object MemoryMappedPE {

  def newInstance(data: PEData, secLoader: SectionLoader): MemoryMappedPE =
    apply(data, secLoader)

  def apply(data: PEData, secLoader: SectionLoader): MemoryMappedPE = {
    val bytes = readMemoryMappedSectionBytes(data, secLoader)
    new MemoryMappedPE(bytes)
  }

  /**
   * Reads all section bytes at once into a byte array.
   */
  private def readMemoryMappedSectionBytes(data: PEData, secLoader: SectionLoader): Array[Byte] = {
    val optHeader = data.getOptionalHeader
    val table = data.getSectionTable
    if (optHeader.isLowAlignmentMode()) {
      Files.readAllBytes(data.getFile.toPath)
    } else {
      val maxVA = getMaxVA(table)
      //TODO here is the problem -- it might be that it doesn't fit in an Int
      val bytes = Array.fill(maxVA.toInt)(0.toByte)
      for (header <- table.getSectionHeaders().asScala) {
        val start = header.get(VIRTUAL_ADDRESS)
        val end = header.get(VIRTUAL_ADDRESS) + header.getAlignedVirtualSize()
        val secBytes = secLoader.loadSectionBytes(header.getNumber()).bytes
        for (i <- start until Math.min(end, secBytes.length + start)) {
          bytes(i.toInt) = secBytes((i - start).toInt)
        }
      }
      bytes
    }
  }

  private def getMaxVA(table: SectionTable): Long =
    table.getSectionHeaders().asScala.foldRight(0L) { (header, max) =>
      val headerEnd = header.get(VIRTUAL_ADDRESS) + header.getAlignedVirtualSize()
      if (headerEnd > max) headerEnd else max
    }

}