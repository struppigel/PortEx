package com.github.katjahahn.parser.sections.idata

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.ByteArrayUtil._
import com.github.katjahahn.parser.IOUtil.{ NL }
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.HeaderKey
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.MemoryMappedPE

class DelayLoadDirectoryEntry private (
  private val entries: Map[DelayLoadDirectoryKey, StandardField],
  private val offset: Long,
  private val name: String) {

  def apply(key: DelayLoadDirectoryKey): Long = entries(key).value
  
  def getInfo(): String = entries.values.mkString("\n")
  
  override def toString(): String = getInfo()

}

object DelayLoadDirectoryEntry {

  private val delayLoadSpec = "delayimporttablespec"
  val delayDirSize = 32

  def apply(mmbytes: MemoryMappedPE, fileOffset: Long,
    virtualAddress: Long): DelayLoadDirectoryEntry = {
    val format = new SpecificationFormat(0, 1, 2, 3)
    val delayLoadBytes = mmbytes.slice(virtualAddress, virtualAddress + delayDirSize)
    val entries = IOUtil.readHeaderEntries(classOf[DelayLoadDirectoryKey],
      format, delayLoadSpec, delayLoadBytes, fileOffset).asScala.toMap
    val nameRVA = entries(DelayLoadDirectoryKey.NAME).value.toInt
    val name = getASCIIName(nameRVA, virtualAddress, mmbytes)
    new DelayLoadDirectoryEntry(entries, fileOffset, name)
  }

  private def getASCIIName(nameRVA: Int, virtualAddress: Long,
    mmbytes: MemoryMappedPE): String = {
    val offset = nameRVA
    val nullindex = mmbytes.indexWhere(_ == 0, offset)
    new String(mmbytes.slice(offset, nullindex))
  }
}