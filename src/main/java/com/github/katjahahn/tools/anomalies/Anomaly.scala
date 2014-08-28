/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn.tools.anomalies

import scala.collection.JavaConverters._
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.optheader.DataDirEntry
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.sections.SectionHeaderKey
import com.github.katjahahn.parser.sections.idata.ImportDLL
import com.github.katjahahn.parser.PhysicalLocation

/**
 * PE file anomaly or malformation.
 */
abstract class Anomaly() {

  override def toString(): String = description

  /**
   * The description of the anomaly
   */
  def description(): String

  /**
   * Returns a list of all locations relevant for the anomaly
   */
  def locations(): java.util.List[PhysicalLocation]

  /**
   * Represents a field or structure this anomaly is associated with
   */
  def key(): FieldOrStructureKey

  /**
   * The anomaly type
   */
  def getType(): AnomalyType = subtype.getSuperType

  /**
   * The subtype of the anomaly
   */
  def subtype(): AnomalySubType

}

/**
 * Represents unusual location, order, number or size of PE structures, e.g.
 * collapsed, overlapping, moved to overlay
 */
case class StructureAnomaly(
  structure: PEStructureKey,
  override val description: String,
  override val subtype: AnomalySubType,
  slocations: List[PhysicalLocation]) extends Anomaly {
  require(subtype.getSuperType == AnomalyType.STRUCTURE,
    subtype + " must have anomaly type STRUCTURE!")

  override def locations = slocations.asJava
  override def key = structure
}

/**
 * A deprectated value is not zero as expected.
 */
case class FieldAnomaly(
  val field: StandardField,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {
  require(subtype.getSuperType != AnomalyType.STRUCTURE,
    subtype + " must not have anomaly type STRUCTURE!")

  override def locations = List(new PhysicalLocation(field.getOffset(),
    field.getSize())).asJava
  override def key = field.key
}

/**
 * A reserved datadir value has been used.
 */
case class DataDirAnomaly(
  val dataDirEntry: DataDirEntry,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {

  override def locations = List(new PhysicalLocation(dataDirEntry.getTableEntryOffset,
    dataDirEntry.getTableEntrySize)).asJava
  override val key = dataDirEntry.getKey
}

case class SectionNameAnomaly(val header: SectionHeader,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {

  override def locations = List(new PhysicalLocation(header.getNameOffset,
    header.getNameSize)).asJava
  override def key = SectionHeaderKey.NAME
}

case class ImportAnomaly(val imports: List[ImportDLL],
  override val description: String,
  override val subtype: AnomalySubType,
  override val key: FieldOrStructureKey) extends Anomaly {

  override def locations = imports.flatMap(i => i.getLocations().asScala).asJava
}
