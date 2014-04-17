package com.github.katjahahn.sections.debug

import com.github.katjahahn.PEModule
import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.StandardEntry
import com.github.katjahahn.ByteArrayUtil._
import DebugSection._
import com.github.katjahahn.PELoader
import java.io.File
import com.github.katjahahn.sections.SectionLoader
import DebugDirTableKey._
import java.util.Date

class DebugSection private (
  private val directoryTable: DebugDirectoryTable,
  private val typeDescription: String) extends PEModule {

  override def getInfo(): String = 
    s"""|-------------
        |Debug Section
        |-------------
        |
        |${directoryTable.values.map(s => s.key match {
          case TYPE => "Type: " + typeDescription
          case TIME_DATE_STAMP => "Time date stamp: " + getTimeDateStamp().toString
          case _ => s.toString
          }).mkString(PEModule.NL)}""".stripMargin
        
  override def read(): Unit = {}
          
  def getTimeDateStamp(): Date = new Date(get(TIME_DATE_STAMP) * 1000)
        
  def get(key: DebugDirTableKey): Long = directoryTable(key).value
  
  def getTypeDescription(): String = typeDescription
  
}

object DebugSection {

  type DebugDirectoryTable = Map[DebugDirTableKey, StandardEntry]

  private val debugspec = "debugdirentryspec"
    
  def main(args: Array[String]): Unit = {
    val file = new File("src/main/resources/testfiles/ntdll.dll")
    val data = PELoader.loadPE(file)
    val loader = new SectionLoader(data)
    val debug = loader.loadDebugSection()
    println(debug.getInfo())
  }

  def apply(debugbytes: Array[Byte]): DebugSection = {
    val specification = IOUtil.readMap("debugdirentryspec").asScala.toMap
    val buffer = ListBuffer.empty[StandardEntry]
    for ((key, specs) <- specification) {
      val description = specs(0)
      val offset = Integer.parseInt(specs(1))
      val size = Integer.parseInt(specs(2))
      val value = getBytesLongValue(debugbytes.clone, offset, size)
      val ekey = DebugDirTableKey.valueOf(key)
      val entry = new StandardEntry(ekey, description, value)
      buffer += entry
    }
    val entries: DebugDirectoryTable = (buffer map { t => (t.key.asInstanceOf[DebugDirTableKey], t) }).toMap;
    val types = IOUtil.getCharacteristicsDescriptions(entries(DebugDirTableKey.TYPE).value, "debugtypes").asScala.toList
    new DebugSection(entries, types(0))
  }
}