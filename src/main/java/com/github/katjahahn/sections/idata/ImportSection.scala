package com.github.katjahahn.sections.idata

import com.github.katjahahn.sections.PESection
import com.github.katjahahn.IOUtil
import ImportSection._
import com.github.katjahahn.StandardEntry
import scala.collection.JavaConverters._
import com.github.katjahahn.StandardDataEntry
import com.github.katjahahn.PEModule._
import com.github.katjahahn.StandardDataEntry
import IDataEntryKey._
import com.github.katjahahn.optheader.OptionalHeader
import com.github.katjahahn.optheader.OptionalHeader.MagicNumber._

class ImportSection(
  private val idatabytes: Array[Byte],
  private val virtualAddress: Int,
  private val optHeader: OptionalHeader) extends PESection {

  private var dirEntries = List.empty[IDataEntry]

  override def read(): Unit = {
    readDirEntries()
    readLookupTableEntries()
  }

  private def readLookupTableEntries(): Unit = {
    for (dirEntry <- dirEntries) {
      var entry: LookupTableEntry = null
      var offset = dirEntry(I_ADDR_TABLE_RVA) - virtualAddress
      println("va: " + virtualAddress)
      println("offset: " + offset)
      val EntrySize = optHeader.getMagicNumber match {
        case PE32 => 4
        case PE32_PLUS => 8
        case ROM => throw new IllegalArgumentException
      }
      do {
        entry = LookupTableEntry(idatabytes, offset.toInt, EntrySize, virtualAddress)
        if(!entry.isInstanceOf[NullEntry]) dirEntry.addLookupTableEntry(entry)
        offset += EntrySize
      } while (!entry.isInstanceOf[NullEntry])
    }
  }

  private def readDirEntries(): Unit = {
    var isLastEntry = false
    var i = 0
    do {
      readDirEntry(i) match {
        case Some(entry) => dirEntries = dirEntries :+ entry
        case None => isLastEntry = true
      }
      i += 1
    } while (!isLastEntry)
  }

  private def readDirEntry(nr: Int): Option[IDataEntry] = {
    val from = nr * ENTRY_SIZE
    val until = from + ENTRY_SIZE
    val entrybytes = idatabytes.slice(from, until)

    //TODO this condition is wrong, i read somewhere that the lookup table rva
    //doesn't have to be specified in which case the IAT RVA would be taken
    def isEmpty(entry: IDataEntry): Boolean =
//      entry.entries.values.forall(v => v == 0)
      entry(I_LOOKUP_TABLE_RVA) == 0 && entry(I_ADDR_TABLE_RVA) == 0

    val entry = IDataEntry(entrybytes, I_DIR_ENTRY_SPEC)
    entry.name = getASCIIName(entry)
    if (isEmpty(entry)) None else
      Some(entry)
  }

  private def entryDescription(): String =
    (for (e <- dirEntries)
      yield e.getInfo() + NL + NL).mkString

  private def getASCIIName(entry: IDataEntry): String = {
    def getName(value: Int): String = {
      val offset = value - virtualAddress
      val nullindex = idatabytes.indexWhere(b => b == 0, offset)
      new String(idatabytes.slice(offset, nullindex))
    }
    getName(entry(NAME_RVA).toInt)
  }

  override def getInfo(): String =
    s"""|--------------
	|Import section
	|--------------
    |
    |$entryDescription""".stripMargin

}

object ImportSection {

  private final val I_DIR_ENTRY_SPEC = "idataentryspec"
  private final val HINT_NAME_TABLE_SPEC = "hintnametablespec"
  private final val ENTRY_SIZE = 20

}