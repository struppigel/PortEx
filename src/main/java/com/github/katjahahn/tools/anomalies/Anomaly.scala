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

import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.optheader.DataDirEntry

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
  structure: PEStructure,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {
  require(subtype.getSuperType == AnomalyType.STRUCTURE)
  
  override def key = structure
}

/**
 * A deprectated value is not zero as expected.
 */
case class FieldAnomaly(
  val field: StandardField,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {
  require(subtype.getSuperType != AnomalyType.STRUCTURE)
  
  override def key = field.key
}

/**
 * A reserved datadir value has been used.
 */
case class DataDirAnomaly(
  val dataDirEntry: DataDirEntry,
  override val description: String,
  override val subtype: AnomalySubType) extends Anomaly {

  override val key = dataDirEntry.key
}
