package com.github.katjahahn.parser.sections.idata

import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.StandardField
import DelayLoadSection._

class DelayLoadSection(private val delayLoadTable: DelayLoadTable) extends SpecialSection {
  
  override def isEmpty(): Boolean = true
  
  override def getOffset(): Long = 0
  
  override def getInfo(): String = delayLoadTable.values.mkString("\n")

}

object DelayLoadSection {
  
  type DelayLoadTable = Map[DelayLoadDirectoryKey, StandardField]
  
  private def delayLoadSpec = "delayimporttablespec"
  private def delayDirSize = 32
  
  def apply(loadInfo: LoadInfo): DelayLoadSection = {
    val mmbytes = loadInfo.memoryMapped
    val virtualAddress = loadInfo.va
    val offset = loadInfo.fileOffset
    val format = new SpecificationFormat(0, 1, 2, 3)
    val delayLoadBytes = mmbytes.slice(virtualAddress, virtualAddress + delayDirSize)
    val entries = IOUtil.readHeaderEntries(classOf[DelayLoadDirectoryKey],
      format, delayLoadSpec, delayLoadBytes, offset).asScala.toMap
    new DelayLoadSection(entries)
  }
  
  def newInstance(loadInfo: LoadInfo): DelayLoadSection = apply(loadInfo)
  
}