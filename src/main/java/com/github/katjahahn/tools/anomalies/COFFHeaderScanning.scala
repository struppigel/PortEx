package com.github.katjahahn.tools.anomalies

import com.github.katjahahn.PEData
import com.github.katjahahn.coffheader.COFFFileHeader
import com.github.katjahahn.coffheader.COFFHeaderKey
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import scala.collection.JavaConverters._

trait COFFHeaderScanning extends AnomalyScanner {

  abstract override def scan(): List[Anomaly] = {
    val coff = data.getCOFFFileHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if (coff == null) return Nil
    anomalyList ++= checkDeprecated(COFFHeaderKey.NR_OF_SYMBOLS, coff)
    anomalyList ++= checkDeprecated(COFFHeaderKey.POINTER_TO_SYMB_TABLE, coff)
    anomalyList ++= checkCharacteristics(coff)
    super.scan ::: anomalyList.toList
  }

  private def checkDeprecated(key: COFFHeaderKey, coff: COFFFileHeader): List[Anomaly] = {
    val entry = coff.getEntry(key)
    if (entry.value != 0) {
      List(DeprecatedAnomaly(entry, "COFF File Header: Deprecated value for NumberOfSymbols is " + entry.value))
    } else Nil

  }

  private def checkCharacteristics(coff: COFFFileHeader): List[Anomaly] = {
    val characteristics = coff.getCharacteristicsDescriptions().asScala
    characteristics.foldRight(List[Anomaly]())((ch, list) => 
      if (ch.contains("DEPRECATED")) {
        val entry = coff.getEntry(COFFHeaderKey.CHARACTERISTICS)
        val description = "Deprecated Characteristic in COFF File Header: " + ch
        DeprecatedAnomaly(entry, description) :: list
      } else list
    )
  }

}