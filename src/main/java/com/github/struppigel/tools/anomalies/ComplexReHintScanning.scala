/** *****************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * **************************************************************************** */

package com.github.struppigel.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.struppigel.parser.IOUtil.NL
import com.github.struppigel.parser.sections.SectionLoader

import scala.collection.JavaConverters._

/**
 * Scans for RE hints that are related to multiple PE structures.
 */
trait ComplexReHintScanning extends AnomalyScanner {
  abstract override def scanReport(): String =
    "Applied CLR Anomaly Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkElectronPackage()
    super.scan ::: anomalyList.toList
  }

  private def checkElectronPackage(): List[Anomaly] = {
    val headers = data.getSectionTable.getSectionHeaders.asScala
    if(headers.exists(_.getName == "CPADinfo")) {
      if (data.loadPDBPath() == "electron.exe.pdb"){
        val description = "This is an Electron Package executable. Look for .asar archive in resources. This might be a separate file."
        return List(ComplexReHintAnomaly(description, AnomalySubType.ELECTRON_PACKAGE_RE_HINT))
      }
    }
    Nil
  }
}
