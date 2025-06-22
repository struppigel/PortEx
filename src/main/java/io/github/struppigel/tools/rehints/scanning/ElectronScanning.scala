/** *****************************************************************************
 * Copyright 2024 Karsten Phillip Boris Hahn
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
package io.github.struppigel.tools.rehints.scanning

import io.github.struppigel.tools.anomalies.{AnomalySubType}
import io.github.struppigel.tools.rehints.{ReHintType}

import scala.collection.mutable.ListBuffer
import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.tools.anomalies.{Anomaly, GenericReHintAnomaly, SectionNameAnomaly}
import io.github.struppigel.tools.rehints.{ReHint, ReHintScanner, StandardReHint}
import scala.collection.JavaConverters._

/**
 * Scans for RE hints that are related to multiple PE structures.
 */
trait ElectronScanning extends ReHintScanner {
  abstract override def scanReport(): String =
    "Electron Scanning" + NL + super.scanReport

  abstract override def scan(): List[ReHint] = {
    val reList = ListBuffer[ReHint]()
    reList ++= checkElectron()
    super.scan ::: reList.toList
  }

  private def checkElectron(): List[ReHint] = {
    val headers = data.getSectionTable.getSectionHeaders.asScala
    val cpad = headers.find(_.getName == "CPADinfo")
    if (cpad.isDefined) {
      val secNameAnom = SectionNameAnomaly(cpad.get, "Section name 'CPADinfo'", AnomalySubType.UNUSUAL_SEC_NAME)
      if (data.loadPDBPath() == "electron.exe.pdb") {
        val pdbPathAnom = GenericReHintAnomaly("PDB path is 'electron.exe.pdb'")
        val anoms: List[Anomaly] = secNameAnom :: pdbPathAnom :: Nil
        return List(StandardReHint(anoms.asJava, ReHintType.ELECTRON_PACKAGE_RE_HINT))
      }
    }
    Nil
  }

}
