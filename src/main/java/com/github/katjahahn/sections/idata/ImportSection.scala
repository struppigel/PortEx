package com.github.katjahahn.sections.idata

import com.github.katjahahn.sections.PESection
import com.github.katjahahn.FileIO
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

//  type IDataEntry = StandardDataEntry[IDataEntryKey.type]

  private val hintNameTableSpec = FileIO.readMap(HINT_NAME_TABLE_SPEC).asScala.toMap

  private var dirEntries = List.empty[IDataEntry]

  override def read(): Unit = {
    readDirEntries()
    readLookupTableEntries()
  }

  private def readLookupTableEntries(): Unit = {
    for (dirEntry <- dirEntries) {
      var entry: LookupTableEntry = null
      var currOffset = dirEntry(I_LOOKUP_TABLE_RVA) - virtualAddress
      val EntrySize = optHeader.getMagicNumber() match {
        case PE32 => 32
        case PE32_PLUS => 64
        case ROM => throw new IllegalArgumentException
      }
      do {
        entry = LookupTableEntry(idatabytes, currOffset, optHeader.getMagicNumber, virtualAddress)
        dirEntry.addLookupTableEntry(entry)
        currOffset += EntrySize
      } while (entry.isInstanceOf[NullEntry])
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

    def isEmpty(entry: IDataEntry): Boolean =
      entry(I_LOOKUP_TABLE_RVA) == 0

    val entry = new IDataEntry(entrybytes, I_DIR_ENTRY_SPEC)
    entry.read()
    if (isEmpty(entry)) None else
      Some(entry)
  }

  private def entryDescription(): String =
    (for (e <- dirEntries)
      yield e.getInfo() + NL + "ASCII Name: " + getASCIIName(e) + NL + NL).mkString

  private def getASCIIName(entry: IDataEntry): String = {
    def getName(value: Int): String = {
      val offset = value - virtualAddress
      val nullindex = idatabytes.indexWhere(b => b == 0, offset)
      new String(idatabytes.slice(offset, nullindex))
    }
    getName(entry(NAME_RVA))
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