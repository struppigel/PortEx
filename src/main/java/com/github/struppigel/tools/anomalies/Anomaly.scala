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
package com.github.struppigel.tools.anomalies

import com.github.struppigel.parser.optheader.DataDirEntry
import com.github.struppigel.parser.sections.{SectionHeader, SectionHeaderKey}
import com.github.struppigel.parser.sections.clr.{MetadataRoot, StreamHeader}
import com.github.struppigel.parser.sections.idata.ImportDLL
import com.github.struppigel.parser.sections.rsrc.Resource
import com.github.struppigel.parser.{PhysicalLocation, RichHeader, StandardField}
import com.github.struppigel.tools.Overlay

import scala.collection.JavaConverters._

/**
 * PE file anomaly or malformation.
 */
abstract class Anomaly() {

  override def toString: String = description()

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

  override def locations: java.util.List[PhysicalLocation] = List(new PhysicalLocation(field.getOffset(),
    field.getSize())).asJava
  override def key = field.getKey
}

/**
 * A reserved datadir value has been used.
 */
case class DataDirAnomaly(
  val dataDirEntry: DataDirEntry,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {

  override def locations: java.util.List[PhysicalLocation] = List(new PhysicalLocation(dataDirEntry.getTableEntryOffset,
    dataDirEntry.getTableEntrySize)).asJava
    override val key = dataDirEntry.getKey
}

case class SectionAnomaly(val header: SectionHeader,
  override val description: String,
  override val subtype: AnomalySubType,
  readSize: Long, lowAlign : Boolean) extends Anomaly {
  
  override def locations: java.util.List[PhysicalLocation] =
    List(new PhysicalLocation(header.getAlignedPointerToRaw(lowAlign), readSize)).asJava
  override def key = PEStructureKey.SECTION 
}

case class SectionNameAnomaly(val header: SectionHeader,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {

  override def locations: java.util.List[PhysicalLocation] = List(new PhysicalLocation(header.getNameOffset,
    header.getNameSize)).asJava
  override def key = SectionHeaderKey.NAME
}

case class ResourceAnomaly(val resource: Resource,
                           override val description: String,
                           override val subtype: AnomalySubType) extends Anomaly {
  
  override def locations: java.util.List[PhysicalLocation] = List(resource.rawBytesLocation).asJava
  override def key = PEStructureKey.RESOURCE_SECTION //TODO correct key?
}

case class ImportAnomaly(val imports: List[ImportDLL],
  override val description: String,
  override val subtype: AnomalySubType,
  override val key: FieldOrStructureKey) extends Anomaly {

  override def locations: java.util.List[PhysicalLocation] = imports.flatMap(i => i.getLocations().asScala).asJava
}

case class RichHeaderAnomaly(private val rich : RichHeader,
                             override val description: String,
                             override val subtype: AnomalySubType) extends Anomaly {
  override def key = PEStructureKey.RICH_HEADER
  override def locations: java.util.List[PhysicalLocation] = List(rich.getPhysicalLocation()).asJava
}

case class ClrMetadaRootAnomaly(private val metadataRoot : MetadataRoot,
                            override val description: String,
                            override val subtype: AnomalySubType) extends Anomaly {
  override def key = PEStructureKey.CLR_SECTION
  override def locations: java.util.List[PhysicalLocation] = metadataRoot.getPhysicalLocations.asJava
}

case class ClrStreamAnomaly(private val metadataRoot : MetadataRoot,
                            private val streamHeader : StreamHeader,
                            override val description: String,
                            override val subtype: AnomalySubType) extends Anomaly {
  override def key = PEStructureKey.CLR_SECTION
  override def locations: java.util.List[PhysicalLocation] = {
    val bsjb = metadataRoot.getBSJBOffset
    val streamOffset = streamHeader.offset
    val size = streamHeader.size
    List(new PhysicalLocation(bsjb + streamOffset, size)).asJava
  }
}

case class OverlayAnomaly(val overlay: Overlay,
                           override val description: String,
                           override val subtype: AnomalySubType) extends Anomaly {

  override def locations: java.util.List[PhysicalLocation] = List(new PhysicalLocation(overlay.getOffset, overlay.getSize)).asJava
  override def key = PEStructureKey.OVERLAY
}

case class ComplexReHintAnomaly(override val description: String) extends Anomaly {

  // we probably don't need the scan locations here
  override def locations: java.util.List[PhysicalLocation] = Nil.asJava
  override def key = PEStructureKey.MULTIPLE_STRUCTURES
  override def subtype = AnomalySubType.COMPLEX_RE_HINT
}
