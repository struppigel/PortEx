package com.github.katjahahn.tools.anomalies

import com.github.katjahahn.StandardEntry

class Anomaly(val description: String) {
  
  override def toString(): String = description
  
}

case class DeprecatedAnomaly(standardEntry: StandardEntry, override val description: String) extends Anomaly(description)