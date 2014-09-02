package com.github.katjahahn.parser.sections.idata

import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.StandardField
import DelayLoadSection._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.MemoryMappedPE
import org.apache.logging.log4j.LogManager

class DelayLoadSection(private val delayLoadTable: DelayLoadTable) extends SpecialSection {

  override def isEmpty(): Boolean = true

  override def getOffset(): Long = 0

  override def getInfo(): String = delayLoadTable.mkString("\n\n")

}

object DelayLoadSection {

  private final val logger = LogManager.getLogger(ImportSection.getClass().getName())

  type DelayLoadTable = List[DelayLoadDirectoryEntry]

  def apply(loadInfo: LoadInfo): DelayLoadSection = {
    val mmbytes = loadInfo.memoryMapped
    val virtualAddress = loadInfo.va
    val offset = loadInfo.fileOffset
    val delayLoadTable = readDirEntries(mmbytes, virtualAddress, offset)
    new DelayLoadSection(delayLoadTable)
  }

  private def readDirEntries(mmbytes: MemoryMappedPE,
    virtualAddress: Long, fileOffset: Long): List[DelayLoadDirectoryEntry] = {
    val delayDirSize = DelayLoadDirectoryEntry.delayDirSize
    val directoryTable = ListBuffer[DelayLoadDirectoryEntry]()
    var isLastEntry = false
    var i = 0
    do {
      logger.info(s"reading ${i + 1}. entry")
      readDirEntry(i, mmbytes, virtualAddress, fileOffset) match {
        case Some(entry) =>
          logger.info("------------start-----------")
          logger.info("dir entry read: " + entry)
          logger.info("------------end-------------")
          directoryTable += entry
        case None => isLastEntry = true
      }
      i += 1
    } while (!isLastEntry)
    directoryTable.toList
  }

  var counter = 0

  private def readDirEntry(nr: Int, mmbytes: MemoryMappedPE,
    virtualAddress: Long, fileOffset: Long): Option[DelayLoadDirectoryEntry] = {
    val delayDirSize = DelayLoadDirectoryEntry.delayDirSize
    val from = nr * delayDirSize + virtualAddress
    logger.info("reading from: " + from)
    val until = from + delayDirSize
    logger.info("reading until: " + until)
    val entrybytes = mmbytes.slice(from, until)
    if (entrybytes.length < delayDirSize) return None

    /**
     * @return true iff the given entry is not the last empty entry or null entry
     */
    def isEmpty(entry: DelayLoadDirectoryEntry): Boolean =
      entry(DelayLoadDirectoryKey.MODULE_HANDLE) == 0

    val entry = DelayLoadDirectoryEntry(mmbytes, fileOffset + (nr * delayDirSize),
      virtualAddress + (nr * delayDirSize))
    if (isEmpty(entry)) None else
      Some(entry)
  }

  def newInstance(loadInfo: LoadInfo): DelayLoadSection = apply(loadInfo)

}