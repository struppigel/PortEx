package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._

abstract class ResourceDirectoryEntry
case class SubDirEntry(id: IDOrName, table: ResourceDirectoryTable) extends ResourceDirectoryEntry
case class DataEntry(id: IDOrName, data: ResourceDataEntry) extends ResourceDirectoryEntry

abstract class IDOrName
case class ID(id: Long) extends IDOrName
case class Name(rva: Long, name: String) extends IDOrName

object ResourceDirectoryEntry {

  private val specLocation = "resourcedirentryspec";

  def apply(isNameEntry: Boolean, entryBytes: Array[Byte],
    entryNr: Int, tableBytes: Array[Byte], offset: Long): ResourceDirectoryEntry = {
    val entries = readEntries(entryBytes)
    val rva = entries("DATA_ENTRY_RVA_OR_SUBDIR_RVA")
    val id = getID(entries("NAME_RVA_OR_INTEGER_ID"), isNameEntry)
    if (isDataEntryRVA(rva)) {
      createDataEntry(rva, id, tableBytes, offset)
    } else {
      createSubDirEntry(rva, id, tableBytes, offset)
    }
  }

  private def readEntries(entryBytes: Array[Byte]): Map[String, Long] = {
    val spec = IOUtil.readMap(specLocation).asScala.toMap
    val valueOffset = 2
    val valueSize = 3
    for ((sKey, sVal) <- spec) yield {
      val value = getBytesLongValue(entryBytes,
        Integer.parseInt(sVal(valueOffset)),
        Integer.parseInt(sVal(valueSize)))
      (sKey, value)
    }
  }

  private def getID(value: Long, isNameEntry: Boolean): IDOrName =
    if (isNameEntry) {
      val name = null //TODO
      Name(value, name)
    } else {
      ID(value)
    }

  private def removeHighestBit(value: Long): Long = {
    val mask = 0x7FFFFFFF
    (value & mask)
  }

  private def createDataEntry(rva: Long, id: IDOrName,
    tableBytes: Array[Byte], offset: Long): DataEntry = {
    val entryBytes = tableBytes.slice((rva - offset).toInt,
      (rva - offset + ResourceDataEntry.size).toInt)
    val data = ResourceDataEntry(entryBytes)
    DataEntry(id, data)
  }

  private def createSubDirEntry(rva: Long, id: IDOrName,
    tableBytes: Array[Byte], offset: Long): SubDirEntry = {
    val address = removeHighestBit(rva)
    val resourceBytes = tableBytes.slice((address - offset).toInt, tableBytes.length)
    val table = ResourceDirectoryTable(resourceBytes, address)
    SubDirEntry(id, table)
  }

  private def isDataEntryRVA(value: Long): Boolean = {
    val mask = 1 << 31
    (value & mask) == 0
  }

}