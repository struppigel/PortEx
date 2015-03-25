package com.github.katjahahn.parser.sections.idata

import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.PhysicalLocation
import com.github.katjahahn.parser.Location
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.IOUtil

class BoundImportSection private (
    private val offset: Long) extends SpecialSection {
  
  def getImports(): java.util.List[ImportDLL] = null //TODO implement

  /**
   * {@inheritDoc}
   */
  override def getOffset(): Long = offset

  /**
   * {@inheritDoc}
   */
  override def isEmpty(): Boolean = false

  /**
   *
   * @return a list with all locations the import information has been written to.
   */
  def getPhysicalLocations(): java.util.List[PhysicalLocation] = {
    List.empty[PhysicalLocation].asJava
  }

  /**
   * Returns a decription of all entries in the import section.
   *
   * @return a description of all entries in the import section
   */
  override def getInfo(): String =
    s"""|--------------
        |Bound Imports
        |--------------
        |
        |-todo-""".stripMargin

}

object BoundImportSection {

  def apply(loadInfo: LoadInfo): BoundImportSection = {
     val format = new SpecificationFormat(0, 1, 2, 3)
     null
    }
  
  /**
   * The instance of this class is usually created by the section loader.
   *
   * @param loadInfo
   * @return ImportSection instance
   */
  def newInstance(loadInfo: LoadInfo): BoundImportSection = apply(loadInfo)

}