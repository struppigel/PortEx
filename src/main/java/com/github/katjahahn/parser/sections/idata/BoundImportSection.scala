/**
 * *****************************************************************************
 * Copyright 2016 Katja Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */

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