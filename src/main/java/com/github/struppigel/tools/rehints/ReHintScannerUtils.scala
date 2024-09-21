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
package com.github.struppigel.tools.rehints

import com.github.struppigel.parser.{PEData, ScalaIOUtil}
import com.github.struppigel.tools.anomalies.{Anomaly, AnomalySubType, GenericReHintAnomaly, ResourceAnomaly, SectionNameAnomaly}

import scala.collection.JavaConverters._


object ReHintScannerUtils {

  def hasAnomaly(anomalies: java.util.List[Anomaly], filterString: String, anomalySubType: AnomalySubType): Boolean =
    !filterAnomalies(anomalies, filterString, anomalySubType).isEmpty

  def filterAnomalies(anomalies: java.util.List[Anomaly], filterStrings: List[String], anomalySubType: AnomalySubType): List[Anomaly] =
    filterStrings.flatMap(filter => filterAnomalies(anomalies, filter, anomalySubType))

  def filterAnomalies(anomalies: java.util.List[Anomaly], filterStrings: List[String]): List[Anomaly] =
    filterStrings.flatMap(filter => filterAnomalies(anomalies, filter))

  def filterAnomalies(anomalies: java.util.List[Anomaly], filterString: String): List[Anomaly] =
    anomalies.asScala.filter(a => a.description().toLowerCase().contains(filterString.toLowerCase())).toList

  def filterAnomalies(anomalies: java.util.List[Anomaly], filterString: String, anomalySubType: AnomalySubType): List[Anomaly] =
    anomalies.asScala.filter(a =>
      a.subtype() == anomalySubType &&
        a.description().toLowerCase().contains(filterString.toLowerCase())).toList

  def constructReHintIfAnyPdbPath(pathes : List[String], data: PEData, reHintType: ReHintType): Option[ReHint] = {
    val filtered = pathes.filter(data.loadPDBPath().contains(_))
    if (filtered.isEmpty) Option.empty
    else {
      val anoms : List[Anomaly] = filtered.map(p => new GenericReHintAnomaly("PDB path contains '" + p + "'"))
      val reHint = StandardReHint(anoms.asJava, reHintType)
      Some(reHint)
    }
  }

  def constructReHintIfAnySectionName(names: List[String], data: PEData, rhType: ReHintType): Option[ReHint] = {
    val sections = data.getSectionTable.getSectionHeaders.asScala
    val anoms : List[Anomaly] = sections.filter(h => names.contains(h.getName))
      .map(h => {
        val description = s"Section name ${h.getName}"
        SectionNameAnomaly(h, description, AnomalySubType.UNUSUAL_SEC_NAME)
      })
      .toList

    if (anoms.isEmpty) None
    else Some(StandardReHint(anoms.asJava, rhType))
  }

  def constructAnomalyIfVersionInfoContains(versionKey : String, versionValue : String, data: PEData): List[Anomaly] = {
    val versionInfo = data.loadVersionInfo()
    if(versionInfo.isPresent && versionInfo.get().getVersionStrings().containsKey(versionKey)) {
      val value = versionInfo.get().getVersionStrings().get(versionKey)
      if (value.contains(versionValue)) {
        val anoms: List[Anomaly] = GenericReHintAnomaly("Version Info contains '" + versionKey + "' with the value '" + versionValue + "'") :: Nil
        anoms
      } else Nil
    }
    else Nil
  }

  def peHasSignature(pedata: PEData, sigSubstring : String): Boolean = {
    pedata.getSignatures.asScala.exists(sig => sig.getName.toLowerCase() contains sigSubstring.toLowerCase())
  }

  def constructAnomaliesForAnySignature(pedata: PEData, sigSubstring: String): List[Anomaly] =
    if(peHasSignature(pedata, sigSubstring)) {
      val sigs = pedata.getSignatures.asScala.filter(sig => sig.getName contains sigSubstring)
      sigs.map(sig => GenericReHintAnomaly("Matches signature " + sig.getName)).toList
    }
    else Nil

  def constructReHintIfAnyResourceName(names: List[String], data: PEData, rhType: ReHintType): Option[ReHint] = {
    val resources = data.loadResources().asScala.filter(res => names contains res.getName())
    val anoms : List[Anomaly] = resources.map {res =>
      val offset = res.rawBytesLocation.from
      val name = res.getName()
      val description = s"Resource named ${name} in resource ${ScalaIOUtil.hex(offset)}"
      ResourceAnomaly(res, description , AnomalySubType.RESOURCE_NAME)
    }.toList
    if (anoms.isEmpty) None else Some(StandardReHint(anoms.asJava, rhType))
  }

  def optionToList(option : Option[ReHint]): List[ReHint] =
    if(option.isDefined) List(option.get) else Nil


}
