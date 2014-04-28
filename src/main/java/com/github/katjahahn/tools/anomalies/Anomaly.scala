package com.github.katjahahn.tools.anomalies

import com.github.katjahahn.StandardEntry
import com.github.katjahahn.optheader.DataDirEntry

class Anomaly(val description: String) {
  
  override def toString(): String = description
  
}

/**
 * A deprectated value is not zero as expected.
 */
case class DeprecatedAnomaly(standardEntry: StandardEntry, override val description: String) extends Anomaly(description) 

/**
 * A value is wrong according to the pecoff specification, e.g. it is incoherent 
 * or doesn't fulfull alignment specifications.
 */
case class WrongValueAnomaly(standardEntry: StandardEntry, override val description: String) extends Anomaly(description)

/**
 * A non standard value has been used. This is not against the pecoff specification,
 * it is just unusual.
 */
case class NonDefaultAnomaly(standardEntry: StandardEntry, override val description: String) extends Anomaly(description)

/**
 * A reserved value has been used.
 */
case class ReservedAnomaly(standardEntry: StandardEntry, override val description: String) extends Anomaly(description)

/**
 * A reserved datadir value has been used.
 */
case class ReservedDataDirAnomaly(dataDirEntry: DataDirEntry, override val description: String) extends Anomaly(description)