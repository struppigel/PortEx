package com.github.katjahahn.sections.idata

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import com.github.katjahahn.FileIO
import com.github.katjahahn.StandardEntry
import scala.collection.JavaConverters._
import com.github.katjahahn.PEModule._
import com.github.katjahahn.sections.idata.IDataEntryKey._

class IDataEntry(private val entrybytes: Array[Byte], 
    private val specLocation: String) extends PEModule {

  private val specification = FileIO.readMap(specLocation).asScala.toMap

  var entries: Map[IDataEntryKey, StandardEntry] = Map.empty
  var lookupTableEntries: List[LookupTableEntry] = Nil
  var name: String = _

  def addLookupTableEntry(e: LookupTableEntry): Unit = {
    lookupTableEntries = lookupTableEntries :+ e
  }

  //TODO reuse that read method and use factory to create
  override def read(): Unit = {
    val buffer = ListBuffer.empty[StandardEntry]
    for ((key, specs) <- specification) {
      val description = specs(0)
      val offset = Integer.parseInt(specs(1))
      val size = Integer.parseInt(specs(2))
      val value = getBytesIntValue(entrybytes, offset, size)
      val entry = new StandardEntry(key, description, value)
      buffer += entry
    }
    entries = buffer map { t => (IDataEntryKey.withName(t.key), t) } toMap
  }

  def apply(key: IDataEntryKey): Int = {
    entries(key).value
  }

  override def getInfo(): String = s"""${entries.values.mkString(NL)} 
  |ASCII name: $name
  |
  |lookup table entries
  |--------------------
  |${lookupTableEntries.mkString(NL + NL)}""".stripMargin

  override def toString(): String = getInfo()

} 