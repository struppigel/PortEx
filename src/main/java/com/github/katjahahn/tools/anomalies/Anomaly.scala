/*******************************************************************************
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
 ******************************************************************************/
package com.github.katjahahn.tools.anomalies

import com.github.katjahahn.StandardField
import com.github.katjahahn.optheader.DataDirEntry

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
   * Represents a field this anomaly is associated with
   */
  def field(): StandardField
  
  /**
   * The anomaly type
   */
  def getType(): AnomalyType

}

/**
 * Represents unusual location, order, number or size of PE structures, e.g.
 * collapsed, overlapping, moved to overlay
 */
case class StructuralAnomaly(override val description: String) extends Anomaly {
  override def field = null
  override def getType = AnomalyType.STRUCTURE
}

/**
 * A deprectated value is not zero as expected.
 */
case class DeprecatedAnomaly(field: StandardField, override val description: String) extends Anomaly {
  override def getType = AnomalyType.DEPRECATED
}

/**
 * A value is wrong according to the pecoff specification, e.g. it is incoherent
 * or doesn't fulfull alignment specifications.
 */
case class WrongValueAnomaly(field: StandardField, override val description: String) extends Anomaly{
  override def getType = AnomalyType.WRONG;
}

/**
 * A non standard value has been used. This is not against the pecoff specification,
 * it is just unusual.
 */
case class NonDefaultAnomaly(field: StandardField, override val description: String) extends Anomaly{
  override def getType = AnomalyType.NON_DEFAULT
}

/**
 * A reserved value has been used.
 */
case class ReservedAnomaly(field: StandardField, override val description: String) extends Anomaly{
  override def getType = AnomalyType.RESERVED
}

/**
 * A reserved datadir value has been used.
 */
case class ReservedDataDirAnomaly(dataDirEntry: DataDirEntry, override val description: String) extends Anomaly {
  
  override val field = new StandardField(dataDirEntry.key, dataDirEntry.toString(), null)
  
  override def getType = AnomalyType.RESERVED
}
