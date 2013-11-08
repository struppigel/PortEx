package com.github.katjahahn.sections.idata

import com.github.katjahahn.sections.PESection
import com.github.katjahahn.FileIO
import ImportSection._
import com.github.katjahahn.StandardEntry
import scala.collection.JavaConverters._
import com.github.katjahahn.StandardDataEntry
import com.github.katjahahn.PEModule._
import com.github.katjahahn.StandardDataEntry

class ImportSection(
    private val idatabytes: Array[Byte],
    private val virtualAddress: Int) extends PESection {

  private val iLookupTableSpec = FileIO.readMap(I_LOOKUP_TABLE_SPEC).asScala.toMap
  private val hintNameTableSpec = FileIO.readMap(HINT_NAME_TABLE_SPEC).asScala.toMap

  private var dirEntries = List.empty[StandardDataEntry]

  override def read(): Unit = {
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

  private def readDirEntry(nr: Int): Option[StandardDataEntry] = {
    val from = nr * ENTRY_SIZE
    val until = from + ENTRY_SIZE
    val entrybytes = idatabytes.slice(from, until)

    def isEmpty(entry: StandardDataEntry): Boolean =
      entry.entries.forall(e => e.key != "I_LOOKUP_TABLE_RVA" || e.value == 0)

    val entry = new StandardDataEntry(entrybytes, I_DIR_ENTRY_SPEC)
    entry.read()
    if (isEmpty(entry)) None else
      Some(entry)
  }

  //TODO get name from name rva. this code is just for testing
  private def entryDescription(): String = {
    def names(): String = {
      var s = ""
      for(de <- dirEntries;
          e  <- de.entries) {
        if(e.key == "NAME_RVA") {
          s += getName(e.value) + NL
          println("get name " + s)
        }
      }
      s
    } 
    def getName(value: Int): String = {
      val offset = value - virtualAddress
      val nullindex = {
        var index = 0
        for(i <- offset until idatabytes.length) {
          if(idatabytes(i) == '\0') 
            index = i
        }
        index
      }
      val namebytes: Array[Byte] = idatabytes.slice(offset, nullindex + 2)
      new String(namebytes)
    }
    dirEntries.mkString(NL + NL) + NL + names()
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