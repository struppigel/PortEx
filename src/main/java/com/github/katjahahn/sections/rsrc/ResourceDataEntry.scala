package com.github.katjahahn.sections.rsrc
import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._
import com.github.katjahahn.StandardEntry

class ResourceDataEntry(private val data: Map[ResourceDataEntryKey, StandardEntry]) {

}

object ResourceDataEntry {
  val size = 16
  private val specLocation = "resourcedataentryspec"

  def apply(entryBytes: Array[Byte]): ResourceDataEntry = {
    val spec = IOUtil.readMap(specLocation).asScala.toMap
    val data = for ((sKey, sVal) <- spec) yield {
      val key = ResourceDataEntryKey.valueOf(sKey)
      val value = getBytesLongValue(entryBytes,
        Integer.parseInt(sVal(1)), Integer.parseInt(sVal(2)))
      val description = sVal(0)
      (key, new StandardEntry(key, description, value))
    }
    new ResourceDataEntry(data)
  }
}