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
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.PESignature
import com.github.katjahahn.parser.PhysicalLocation
import java.util.Date
import java.util.Calendar

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
    anomalyList ++= checkTimeStamp(coff)
    super.scan ::: anomalyList.toList
  }
  
  /**
   * Checks if the time stamp is too low or in the future
   * TODO add future time stamp
   * @param coff the coff file header
   * @return list of anomalies
   */
  private def checkTimeStamp(coff: COFFFileHeader): List[Anomaly] = {
    val timestampField = coff.getField(COFFHeaderKey.TIME_DATE)
    val timestamp = timestampField.getValue
    val date = coff.getTimeDate
    val cal = Calendar.getInstance();
    cal.setTime(date);
    val year = cal.get(Calendar.YEAR);
    val currentDate = new Date()
    if (timestamp == 0x2A425E19) { //date is exactly Sat Jun 20 00:22:17 1992
       List(FieldAnomaly(timestampField,
        "COFF Header: Time date stamp 0x2A425E19 is a known bug for Delphi 4 - Delphi 2006 ", TIME_DATE_TOO_LOW))
    } else if (year < 1995) { //date is in past
      List(FieldAnomaly(timestampField,
        "COFF Header: Time date stamp is too far in the past", TIME_DATE_TOO_LOW))
    } else if (currentDate.compareTo(date) < 0) { //date is in future
      List(FieldAnomaly(timestampField,
        "COFF Header: Time date stamp is in the future", TIME_DATE_IN_FUTURE))
    } else Nil
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
    val peOffset = data.getPESignature().getOffset()
    if (peOffset >= overlayLoc) {
      //the real physical size of all headers
      val locSize = PESignature.PE_SIG.length + COFFFileHeader.HEADER_SIZE +
        coff.getSizeOfOptionalHeader() + data.getSectionTable().getSize()

      val locations = List(new PhysicalLocation(peOffset, locSize))
      List(StructureAnomaly(PEStructureKey.PE_FILE_HEADER,
        "PE Header moved to Overlay.", PE_HEADER_IN_OVERLAY, locations))
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
      val locations = List(new PhysicalLocation(opt.getOffset(), size),
        new PhysicalLocation(entry.getOffset(), entry.getSize()))

      List(StructureAnomaly(PEStructureKey.OPTIONAL_HEADER,
        "Collapsed Optional Header, Section Table entries might not be valid.",
        COLLAPSED_OPTIONAL_HEADER, locations))

    } else if (size > opt.getMaxSize) {

      val description = "COFF File Header: SizeOfOptionalHeader is too large, namely: " + size
      List(FieldAnomaly(entry, description, TOO_LARGE_OPTIONAL_HEADER))

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
    val locations = List(new PhysicalLocation(entry.getOffset(), entry.getSize()))
    if (sectionNr > sectionMax) {
      val secTable = data.getSectionTable()
      val secTableLoc = new PhysicalLocation(secTable.getOffset(), secTable.getSize())
      val description = "COFF File Header: Section Number shouldn't be greater than " + sectionMax + ", but is " + sectionNr
      List(StructureAnomaly(PEStructureKey.SECTION_TABLE, description, TOO_MANY_SECTIONS, secTableLoc :: locations))
    } else if (sectionNr == 0) {
      val description = "COFF File Header: Sectionless PE"
      List(StructureAnomaly(PEStructureKey.SECTION_TABLE, description, SECTIONLESS, locations))
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
    if (entry.getValue != 0) {
      val description = "COFF File Header: Deprecated value for " + key.toString + " is " + entry.getValue
      List(FieldAnomaly(entry, description, subtype))
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
        FieldAnomaly(entry, description, DEPRECATED_FILE_CHARACTERISTICS) :: list
      } else if (ch.isReserved) {
        val entry = coff.getField(COFFHeaderKey.CHARACTERISTICS)
        val description = "Reserved Characteristic in COFF File Header: " + ch
        FieldAnomaly(entry, description, RESERVED_FILE_CHARACTERISTICS) :: list
      } else list)
  }

}
