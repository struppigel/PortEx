/**
 * *****************************************************************************
 * Copyright 2022 Karsten Philipp Boris Hahn
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
 * ****************************************************************************
 */
package io.github.struppigel.tools.anomalies

import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.parser.RichHeader

import scala.collection.mutable.ListBuffer

trait RichHeaderScanning extends AnomalyScanner {

  abstract override def scanReport(): String = {
    "Applied Rich Header Anomaly Scanning" + NL + super.scanReport
  }

  abstract override def scan(): List[Anomaly] = {
    val rich = data.maybeGetRichHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if(rich.isPresent) {
      anomalyList ++= checkValidChecksum(rich.get)
    }
    super.scan ::: anomalyList.toList
  }

  private def checkValidChecksum(rich : RichHeader): List[Anomaly] = {
    if(!rich.isValidChecksum()) {
      return List(new RichHeaderAnomaly(rich,
        "Invalid Rich Header checksum, this means the header was manipulated after linking",
        AnomalySubType.RICH_CHECKSUM_INVALID))
    }
    Nil
  }

}
