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

class DebugSection private (
  private val directoryTable: DebugDirectoryTable) extends PEModule {

  override def getInfo(): String = 
    s"""|-------------
        |Debug Section
        |-------------
        |
        |${directoryTable.values.mkString(PEModule.NL)}""".stripMargin
        
  override def read(): Unit = {}
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
    new DebugSection(entries)
  }
}