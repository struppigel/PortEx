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
package com.github.katjahahn.tools.anomalies
import com.github.katjahahn.parser.IOUtil.NL
import com.github.katjahahn.parser.PhysicalLocation
import com.github.katjahahn.parser.ScalaIOUtil.filteredString
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.clr.CLRSection

import scala.collection.mutable.ListBuffer

trait ClrScanning extends AnomalyScanner {
  abstract override def scanReport(): String =
    "Applied CLR Anomaly Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val clr = new SectionLoader(data).maybeLoadCLRSection()
    val anomalyList = ListBuffer[Anomaly]()
    if (!clr.isPresent) return Nil
    anomalyList ++= checkStringsHeap(clr.get)
    super.scan ::: anomalyList.toList
  }

  private def checkStringsHeap(clr : CLRSection): List[Anomaly] = {
    val metadataRoot = clr.metadataRoot
    val streamHeader = metadataRoot.streamHeaders.find(_.name == "#Strings")
    val stringsHeap = metadataRoot.maybeGetStringsHeap
    if(!stringsHeap.isPresent || !streamHeader.isDefined) return Nil
    val heap= stringsHeap.get()
    val filteredStrings = heap.getArray().filter(filteredString(_).length > 0)
    // one less because first string is always empty
    val unreadableCount = heap.getArray().length - filteredStrings.length - 1
    if(unreadableCount > 0) {
      return List(new ClrStreamAnomaly(new java.util.LinkedList[PhysicalLocation](), "There is a total of " + unreadableCount +
        " unreadable strings in #Strings, this is a common obfuscation", AnomalySubType.UNREADABLE_CHARS_IN_STRINGS_HEAP))
    }
    Nil
  }
}
