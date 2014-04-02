package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.IOUtil
import com.github.katjahahn.StandardEntry
import com.github.katjahahn.ByteArrayUtil._
import scala.collection.JavaConverters._
import com.github.katjahahn.sections.rsrc.ResourceDirectoryTableKey._
import scala.collection.mutable.ListBuffer

class ResourceDirectoryTable (
  private val header: Map[ResourceDirectoryTableKey, StandardEntry],
  private val entries: List[ResourceDirectoryEntry]) {

  def getInfo(): String = ""
}

object ResourceDirectoryTable {

  type Header = Map[ResourceDirectoryTableKey, StandardEntry]
  type Specification = Map[String, Array[String]]

  private val entrySize = 8;
  private val resourceDirOffset = 16;
  private val specLocation = "rsrcdirspec"

  def apply(tableBytes: Array[Byte], offset: Long): ResourceDirectoryTable = {
    val spec = IOUtil.readMap(specLocation).asScala.toMap
    val header = readHeader(spec, tableBytes)
    val nameEntries = header(NR_OF_NAME_ENTRIES).value.toInt
    val idEntries = header(NR_OF_ID_ENTRIES).value.toInt
    val entries = readEntries(header, nameEntries, idEntries, tableBytes, offset)
    return new ResourceDirectoryTable(header, entries)
  }

  private def readHeader(spec: Specification,
    tableBytes: Array[Byte]): Header = {
    for ((s1, s2) <- spec) yield {
      val key = ResourceDirectoryTableKey.valueOf(s1)
      val value = getBytesLongValue(tableBytes,
        Integer.parseInt(s2(1)), Integer.parseInt(s2(2)))
      val standardEntry = new StandardEntry(key, s2(0), value)
      (key, standardEntry)
    }
  }

  private def readEntries(header: Header, nameEntries: Int, idEntries: Int,
    tableBytes: Array[Byte], offset: Long): List[ResourceDirectoryEntry] = {
    var entries = ListBuffer.empty[ResourceDirectoryEntry]
    for (i <- 0 until nameEntries + idEntries) {
      val offset = resourceDirOffset + i * entrySize
      val endpoint = offset + entrySize
      val entryNr = i + 1
      val entryBytes = tableBytes.slice(offset, endpoint)
      val isNameEntry = i < nameEntries
      entries += ResourceDirectoryEntry(isNameEntry, entryBytes, entryNr, 
          tableBytes, offset)
    }
    entries.toList
  }
}