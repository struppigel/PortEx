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
import AnomalySubType._
import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.tools.Overlay
import com.github.katjahahn.parser.IOUtil.{ NL }
import com.github.katjahahn.parser.coffheader.COFFFileHeader
import com.github.katjahahn.parser.coffheader.COFFHeaderKey
import com.github.katjahahn.parser.sections.SectionHeaderKey

/**
 * Scans the COFF File Header for anomalies.
 *
 * @author Katja Hahn
 */
trait COFFHeaderScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied COFF Header Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val coff = data.getCOFFFileHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if (coff == null) return Nil
    anomalyList ++= checkDeprecated(COFFHeaderKey.NR_OF_SYMBOLS, coff, DEPRECATED_NR_OF_SYMB)
    anomalyList ++= checkDeprecated(COFFHeaderKey.POINTER_TO_SYMB_TABLE, coff, DEPRECATED_PTR_TO_SYMB_TABLE)
    anomalyList ++= checkCharacteristics(coff)
    anomalyList ++= checkNumberOfSections(coff)
    anomalyList ++= checkSizeOfOptHeader(coff)
    anomalyList ++= checkPEHeaderLocation(coff)
    super.scan ::: anomalyList.toList
  }

  /**
   * Checks if the PE Headers are in the expected location, meaning after the
   * MSDOS stub and before the sections.
   *
   * @param coff the coff file header
   * @return list of anomalies
   */
  private def checkPEHeaderLocation(coff: COFFFileHeader): List[Anomaly] = {
    val overlayLoc = new Overlay(data.getFile()).getOffset
    if (coff.getOffset() >= overlayLoc) {
      List(StructuralAnomaly("PE Header moved to Overlay.", PE_HEADER_IN_OVERLAY))
    } else Nil
  }

  /**
   * Checks for a collapsed Optional Header and if the SizeOfOptionalHeader
   * is unnecessarily large.
   *
   * @param coff the coff file header
   * @return anomaly list
   */
  private def checkSizeOfOptHeader(coff: COFFFileHeader): List[Anomaly] = {
    val size = coff.get(COFFHeaderKey.SIZE_OF_OPT_HEADER)
    val entry = coff.getField(COFFHeaderKey.SIZE_OF_OPT_HEADER)
    val opt = data.getOptionalHeader()
    if (size < opt.getMinSize) {
      val description = s"COFF File Header: The SizeOfOptionalHeader (${size}) is too small"
      List(WrongValueAnomaly(entry, description, TOO_SMALL_OPTIONAL_HEADER),
        StructuralAnomaly("Collapsed Optional Header, Section Table entries might not be valid.", 
            COLLAPSED_OPTIONAL_HEADER))
    } else if (size > opt.getMaxSize) {
      val description = "COFF File Header: SizeOfOptionalHeader is too large, namely: " + size
      List(WrongValueAnomaly(entry, description, TOO_LARGE_OPTIONAL_HEADER))
    } else Nil
  }

  /**
   * Checks the section number maximum value.
   *
   * @param coff the coff file header
   * @return anomaly list
   */
  private def checkNumberOfSections(coff: COFFFileHeader): List[Anomaly] = {
    val sectionMax = 96
    val sectionNr = coff.get(COFFHeaderKey.SECTION_NR)
    val entry = coff.getField(COFFHeaderKey.SECTION_NR)
    if (sectionNr > sectionMax) {
      val description = "COFF File Header: Section Number shouldn't be greater than " + sectionMax + ", but is " + sectionNr
      List(WrongValueAnomaly(entry, description, TOO_MANY_SECTIONS))
    } else if (sectionNr == 0) {
      val description = "COFF File Header: Sectionless PE"
      List(WrongValueAnomaly(entry, description, SECTIONLESS))
    } else Nil
  }

  /**
   * Checks if the value for the given key is set in the coff file header.
   * Returns a DeprecatedAnomaly if it is.
   *
   * This method doesn't know if the given fields are deprecated or not.
   * It just assumes they are.
   *
   * @param key the key of the coff file header field that shall be checked.
   * @param coff
   * @return anomaly list
   */
  private def checkDeprecated(key: COFFHeaderKey, coff: COFFFileHeader, subtype: AnomalySubType): List[Anomaly] = {
    val entry = coff.getField(key)
    if (entry.value != 0) {
      val description = "COFF File Header: Deprecated value for " + key.toString + " is " + entry.value
      List(DeprecatedAnomaly(entry, description, subtype))
    } else Nil

  }

  /**
   * Checks the file characteristics for deprecated and reserved flags.
   *
   * @param coff coff file header
   * @return anomaly list
   */
  private def checkCharacteristics(coff: COFFFileHeader): List[Anomaly] = {
    val characteristics = coff.getCharacteristics().asScala
    characteristics.foldRight(List[Anomaly]())((ch, list) =>
      if (ch.isDeprecated) {
        val entry = coff.getField(COFFHeaderKey.CHARACTERISTICS)
        val description = "Deprecated Characteristic in COFF File Header: " + ch
        DeprecatedAnomaly(entry, description, DEPRECATED_FILE_CHARACTERISTICS) :: list
      } else if (ch.isReserved) {
        val entry = coff.getField(COFFHeaderKey.CHARACTERISTICS)
        val description = "Reserved Characteristic in COFF File Header: " + ch
        ReservedAnomaly(entry, description, RESERVED_FILE_CHARACTERISTICS) :: list
      } else list)
  }

}
