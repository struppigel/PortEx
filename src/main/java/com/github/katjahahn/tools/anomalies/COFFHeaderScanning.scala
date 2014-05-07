package com.github.katjahahn.tools.anomalies

import com.github.katjahahn.PEData
import com.github.katjahahn.coffheader.COFFFileHeader
import com.github.katjahahn.coffheader.COFFHeaderKey
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import scala.collection.JavaConverters._
import com.github.katjahahn.IOUtil
import com.github.katjahahn.optheader.OptionalHeader

trait COFFHeaderScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied COFF Header Scanning" + IOUtil.NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val coff = data.getCOFFFileHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if (coff == null) return Nil
    anomalyList ++= checkDeprecated(COFFHeaderKey.NR_OF_SYMBOLS, coff)
    anomalyList ++= checkDeprecated(COFFHeaderKey.POINTER_TO_SYMB_TABLE, coff)
    anomalyList ++= checkCharacteristics(coff)
    anomalyList ++= checkNumberOfSections(coff)
    anomalyList ++= checkSizeOfOptHeader(coff)
    super.scan ::: anomalyList.toList
  }
  
  private def checkSizeOfOptHeader(coff: COFFFileHeader): List[Anomaly] = {
    val size = coff.get(COFFHeaderKey.SIZE_OF_OPT_HEADER)
    val entry = coff.getEntry(COFFHeaderKey.SIZE_OF_OPT_HEADER)
    val opt = data.getOptionalHeader()
    if(size < opt.getMinSize) {
      val description = "Collapsed Headers: The SizeOfOptionalHeader is too small, namely: " + size
      List(WrongValueAnomaly(entry, description))
    } else if(size > opt.getMaxSize) {
      val description = "COFF File Header: SizeOfOptionalHeader is too large, namely: " + size
      List(WrongValueAnomaly(entry, description))
    } else Nil
  }

  private def checkNumberOfSections(coff: COFFFileHeader): List[Anomaly] = {
    val sectionMax = 96
    val sectionNr = coff.get(COFFHeaderKey.SECTION_NR)
    if (sectionNr > sectionMax) {
      val entry = coff.getEntry(COFFHeaderKey.SECTION_NR)
      val description = "COFF File Header: Section Number shouldn't be greater than " + sectionMax + ", but is " + sectionNr
      List(WrongValueAnomaly(entry, description))
    } else Nil
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
      } else list)
  }

}