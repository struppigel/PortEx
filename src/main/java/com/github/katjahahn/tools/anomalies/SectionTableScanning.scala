package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer

trait SectionTableScanning extends AnomalyScanner {

  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    super.scan ::: anomalyList.toList
  }
}