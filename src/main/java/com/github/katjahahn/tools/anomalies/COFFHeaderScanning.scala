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

import com.github.katjahahn.PEData
import com.github.katjahahn.coffheader.COFFFileHeader
import com.github.katjahahn.coffheader.COFFHeaderKey
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import scala.collection.JavaConverters._
import com.github.katjahahn.IOUtil
import com.github.katjahahn.optheader.OptionalHeader
import com.github.katjahahn.tools.Overlay

/**
 * Scans the COFF File Header for anomalies.
 * 
 * @author Katja Hahn
 */
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
    anomalyList ++= checkPEHeaderLocation(coff)
    super.scan ::: anomalyList.toList
  }  
  
  private def checkPEHeaderLocation(coff: COFFFileHeader): List[Anomaly] = {
    val overlayLoc = new Overlay(data.getFile()).getOffset
    if(coff.getOffset() >= overlayLoc) {
      List(StructuralAnomaly("PE Header moved to Overlay."))
    } else Nil
  }
  
  private def checkSizeOfOptHeader(coff: COFFFileHeader): List[Anomaly] = {
    val size = coff.get(COFFHeaderKey.SIZE_OF_OPT_HEADER)
    val entry = coff.getEntry(COFFHeaderKey.SIZE_OF_OPT_HEADER)
    val opt = data.getOptionalHeader()
    if(size < opt.getMinSize) {
      val description = s"COFF File Header: The SizeOfOptionalHeader (${size}) is too small"
      List(WrongValueAnomaly(entry, description), StructuralAnomaly("Collapsed Optional Header, Section Table entries might not be valid."))
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
