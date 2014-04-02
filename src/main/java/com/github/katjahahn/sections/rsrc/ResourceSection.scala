package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.sections.PESection
import scala.collection.JavaConverters._
import com.github.katjahahn.IOUtil

class ResourceSection(
  private val rsrcbytes: Array[Byte],
  private val virtualAddress: Long) extends PESection {
  
  private var resourceTable: ResourceDirectoryTable = null
  
  //TODO super(rsrc bytes) call
  
  override def read(): Unit = {
    resourceTable = ResourceDirectoryTable(rsrcbytes, 0)
  }

  override def getInfo(): String = resourceTable.getInfo
}