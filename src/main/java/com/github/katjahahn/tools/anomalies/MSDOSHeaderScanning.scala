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

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.IOUtil._
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.Location

/**
 * Scans the MSDOS Header for anomalies
 *
 * @author Katja Hahn
 */
trait MSDOSHeaderScanning extends AnomalyScanner {

  //TODO recognize non-standard header

  abstract override def scanReport(): String =
    "Applied MSDOS Header Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkCollapsedHeader()
    super.scan ::: anomalyList.toList
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
      val locations = List(new Location(0, e_lfanew))
      val description = "Collapsed MSDOS Header, PE Signature offset is at 0x" + java.lang.Long.toHexString(e_lfanew)
      List(StructureAnomaly(PEStructureKey.MSDOS_HEADER, description, 
          AnomalySubType.COLLAPSED_MSDOS_HEADER, locations))
    } else Nil
  }

  //TODO non-default stub

}
