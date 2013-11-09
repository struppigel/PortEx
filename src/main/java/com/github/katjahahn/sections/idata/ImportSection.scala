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

  type IDataEntry = StandardDataEntry[IDataEntryKey.type]

  private val iLookupTableSpec = FileIO.readMap(I_LOOKUP_TABLE_SPEC).asScala.toMap
  private val hintNameTableSpec = FileIO.readMap(HINT_NAME_TABLE_SPEC).asScala.toMap

  private var dirEntries = List.empty[IDataEntry]
  private var lookupTableEntries = List.empty[IDataEntry]

  override def read(): Unit = {
    val offset = readDirEntries()
    readLookupTableEntries(offset)
  }

  //TODO implement for all table entries
  private def readLookupTableEntries(offset: Int): Unit = {
    val (mask, length) = optHeader.getMagicNumber match {
      case PE32 => (0x80000000L, 4)
      case PE32_PLUS => (0x8000000000000000L, 8)
      case ROM => throw new IllegalArgumentException
    }
    val value = getBytesLongValue(idatabytes, offset, length)
    println(idatabytes.slice(offset, offset + length).mkString(" "))
    val isOrdinal = (value & mask) == 1
    println("is ord: " + isOrdinal)
    println(value & 0x7FFFFFFF)
    val address = value - virtualAddress
    println(getASCII(address.toInt + 2)) //gets name from hint/name table
  }

  private def readDirEntries(): Int = {
    var isLastEntry = false
    var i = 0
    do {
      readDirEntry(i) match {
        case Some(entry) => dirEntries = dirEntries :+ entry
        case None => isLastEntry = true
      }
      i += 1
    } while (!isLastEntry)
    val offset = i * ENTRY_SIZE
    offset
  }

  private def readDirEntry(nr: Int): Option[IDataEntry] = {
    val from = nr * ENTRY_SIZE
    val until = from + ENTRY_SIZE
    val entrybytes = idatabytes.slice(from, until)

    def isEmpty(entry: IDataEntry): Boolean =
      entry.entries.forall(e => e.key != "I_LOOKUP_TABLE_RVA" || e.value == 0)

    val entry = new IDataEntry(entrybytes, I_DIR_ENTRY_SPEC)
    entry.read()
    if (isEmpty(entry)) None else
      Some(entry)
  }

  private def entryDescription(): String =
    (for (e <- dirEntries)
      yield e.getInfo() + NL + "ASCII Name: " + getASCIIName(e) + NL + NL).mkString
      
  private def getASCII(offset: Int): String = {
    val nullindex = idatabytes.indexWhere(b => b == 0, offset)
    new String(idatabytes.slice(offset, nullindex + 2))
  }

  private def getASCIIName(entry: IDataEntry): String = {
    def getName(value: Int): String = {
      val offset = value - virtualAddress
      getASCII(offset)
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
  private final val I_LOOKUP_TABLE_SPEC = "ilookuptablespec"
  private final val HINT_NAME_TABLE_SPEC = "hintnametablespec"
  private final val ENTRY_SIZE = 20

}