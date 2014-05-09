package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.IOUtil._
import scala.collection.JavaConverters._

trait MSDOSHeaderScanning extends AnomalyScanner {
  
  //TODO recognize non-standard header

  abstract override def scanReport(): String =
    "Applied MSDOS Header Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkCollapsedHeader()
    super.scan ::: anomalyList.toList
  }
  
  private def checkCollapsedHeader(): List[Anomaly] = {
    val sig = data.getPESignature()
    val e_lfanew = sig.getOffset()
    if(e_lfanew < 0x40) { 
      val description = "Collapsed MSDOS Header, PE Signature offset is at 0x" + java.lang.Long.toHexString(e_lfanew)
      List(StructuralAnomaly(description))
    } else Nil
  }

}