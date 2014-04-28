package com.github.katjahahn.tools.anomalies

import com.github.katjahahn.PEData

abstract class AnomalyScanner(val data: PEData) {
  
  def scanReport(): String

  def scan(): List[Anomaly]
  
}