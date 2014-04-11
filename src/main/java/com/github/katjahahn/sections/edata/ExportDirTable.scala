package com.github.katjahahn.sections.edata

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.StandardEntry
import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._
import com.github.katjahahn.PEModule._
import com.github.katjahahn.PEModule

class ExportDirTable(
    private val entries: Map[ExportDirTableKey, StandardEntry]) extends PEModule {
  
  override def read(): Unit = {}
  override def getInfo(): String = entries.values.mkString(NL)

}

object ExportDirTable {

  private val edataTableSpec = "edatadirtablespec"

  def apply(entrybytes: Array[Byte]): ExportDirTable = {
    val specification = IOUtil.readMap(edataTableSpec).asScala.toMap
    val buffer = ListBuffer.empty[StandardEntry]
    for ((key, specs) <- specification) {
      val description = specs(0)
      val offset = Integer.parseInt(specs(1))
      val size = Integer.parseInt(specs(2))
      val value = getBytesLongValue(entrybytes.clone, offset, size)
      val ekey = ExportDirTableKey.valueOf(key)
      val entry = new StandardEntry(ekey, description, value)
      buffer += entry
    }
    val entries: Map[ExportDirTableKey, StandardEntry] = (buffer map { t => (t.key.asInstanceOf[ExportDirTableKey], t) }).toMap;
    new ExportDirTable(entries)
  }

}