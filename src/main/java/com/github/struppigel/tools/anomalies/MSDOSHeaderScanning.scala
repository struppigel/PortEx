/**
 * *****************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
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
package com.github.struppigel.tools.anomalies

import com.github.struppigel.parser.IOUtil._
import com.github.struppigel.parser.PhysicalLocation
import com.github.struppigel.parser.msdos.MSDOSHeaderKey
import com.github.struppigel.tools.sigscanner.{Signature, SignatureScanner}

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

/**
 * Scans the MSDOS Header for anomalies
 *
 * @author Karsten Hahn
 */
trait MSDOSHeaderScanning extends AnomalyScanner {

  //TODO recognize non-standard header

  abstract override def scanReport(): String =
    "Applied MSDOS Header Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkCollapsedHeader()
    anomalyList ++= checkLargeELfanew()
    anomalyList ++= checkSignatures()
    super.scan ::: anomalyList.toList
  }
  
  /**
   * Checks if e_lfanew points to second half of file
   *
   * @return anomaly list
   */
  private def checkLargeELfanew(): List[Anomaly] = {
    val msdos = data.getMSDOSHeader()
    val e_lfanew = msdos.getField(MSDOSHeaderKey.E_LFANEW)
    if (e_lfanew.getValue > (data.getFile.length() / 2)) {
      val description = "e_lfanew points to second half of the file, the value is 0x" + java.lang.Long.toHexString(e_lfanew.getValue)
      List(FieldAnomaly(e_lfanew, description, AnomalySubType.LARGE_E_LFANEW))
    } else Nil
  }

  /**
   * Checks if the MSDOS header is collapsed. Returns a structural anomaly if true.
   *
   * @return anomaly list
   */
  private def checkCollapsedHeader(): List[Anomaly] = {
    val sig = data.getPESignature
    val e_lfanew = sig.getOffset
    if (e_lfanew < 0x40) {
      val locations = List(new PhysicalLocation(0, e_lfanew))
      val description = "Collapsed MSDOS Header, PE Signature offset is at 0x" + java.lang.Long.toHexString(e_lfanew)
      List(StructureAnomaly(PEStructureKey.MSDOS_HEADER, description, 
          AnomalySubType.COLLAPSED_MSDOS_HEADER, locations))
    } else Nil
  }

  private def checkSignatures(): List[Anomaly] = {
    val results = data.getMSDOSSignatures.asScala
    if(results.nonEmpty && results.exists(_.getName.toLowerCase() == "innosetup")) {
      List(GenericReHintAnomaly("MSDOS Header has Inno Setup signature 'InUn' at offset 0x30"))
    } else Nil
  }
  
  //TODO maybe not reserved anymore? add to thesis?
  private def checkReservedFields(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val msdos = data.getMSDOSHeader()
    val entries = msdos.getHeaderEntries.asScala
    for(entry <- entries) {
      if(entry.getDescription.contains("Reserved")) {
        val description = "MSDOS Header: Reserved field set: " + entry.getDescription
        anomalyList += FieldAnomaly(entry, description, AnomalySubType.RESERVED_MSDOS_FIELD)
      }
    }
    anomalyList.toList
  }

  //TODO non-default stub

}
