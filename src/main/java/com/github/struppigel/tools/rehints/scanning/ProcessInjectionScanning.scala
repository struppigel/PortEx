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

package com.github.struppigel.tools.rehints.scanning

import com.github.struppigel.tools.rehints.ReHintScannerUtils.{filterAnomalies, hasAnomaly}
import com.github.struppigel.tools.rehints.{ReHint, ReHintScanner, ReHintType, StandardReHint}

import scala.collection.mutable.ListBuffer
import com.github.struppigel.parser.IOUtil.NL
import com.github.struppigel.tools.anomalies.{Anomaly, AnomalySubType}

import scala.collection.JavaConverters._

trait ProcessInjectionScanning extends ReHintScanner {

  abstract override def scanReport(): String =
  "Applied ProcessInjectionScanning" + NL + super.scanReport

  abstract override def scan(): List[ReHint] = {
    val reList = ListBuffer[ReHint]()
    reList ++= scanThreadNameCalling()
    reList ++= scanProcessDoppelgaenging()
    reList ++= scanDotNetInjection()
    super.scan ::: reList.toList
  }

  private def miscInjectionAnomalies(): List[Anomaly] = {
    val miscDescriptions = List(
      "might decode data",
      "may add a section",
      "may be used to carve out a process",
      "may get image base offset address from PEB",
      "used to find and load data from resources",
      "allocates memory",
      "creates a process",
      "opens a process",
      "runs the specified application",
      "used to iterate processes",
      "may set PAGE_EXECUTE for memory region",
      "dynamically resolves imports",
      "writes to memory",
      "used to iterate processes" )
    filterAnomalies(anomalies, miscDescriptions, AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT)
  }

  private def scanThreadNameCalling(): List[ReHint] = {
    val importNames = List("GetThreadDescription", "SetThreadDescription")
    if(importNames.forall(hasAnomaly(anomalies, _, AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT))) {
      val reAnomList = filterAnomalies(anomalies, importNames, AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT) ::: miscInjectionAnomalies
      List(StandardReHint(reAnomList.asJava, ReHintType.THREAD_NAME_CALLING_INJECTION_HINT))
    } else Nil
  }

  private def scanProcessDoppelgaenging(): List[ReHint] = {
    val filtered = filterAnomalies(anomalies, "Process Doppelgänging", AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT)
    if(filtered.size >= 3) {
      val reAnomList = filtered ::: miscInjectionAnomalies
      List(StandardReHint(reAnomList.asJava, ReHintType.PROCESS_DOPPELGAENGING_INJECTION_HINT))
    } else Nil
  }

  private def scanDotNetInjection(): List[ReHint] = {
    val importNames = List("CLRCreateInstance", "ExecuteInDefaultAppDomain")
    if(importNames.forall(hasAnomaly(anomalies, _, AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT))) {
      val reAnomList = filterAnomalies(anomalies, importNames, AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT) ::: miscInjectionAnomalies
      List(StandardReHint(reAnomList.asJava, ReHintType.NATIVE_DOT_NET_UNPACKING_RE_HINT))
    } else Nil
  }

}
