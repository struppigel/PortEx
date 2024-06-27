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

import com.github.struppigel.tools.anomalies.{AnomalySubType, OverlayAnomaly}
import com.github.struppigel.tools.rehints.{ReHint, ReHintScanner, ReHintType, StandardReHint}

import scala.collection.mutable.ListBuffer
import com.github.struppigel.parser.IOUtil.NL

import scala.collection.JavaConverters._

trait EmbeddedFileScanning extends ReHintScanner {

  abstract override def scanReport(): String =
    "Applied EmbeddedFileScanning" + NL + super.scanReport

  abstract override def scan(): List[ReHint] = {
    val reList = ListBuffer[ReHint]()
    reList ++= checkResourceFileTypes()
    reList ++= checkOverlayFileTypes()
    super.scan ::: reList.toList
  }

  private def checkResourceFileTypes(): List[ReHint] = {
    val exeAnoms = anomalies.asScala.filter(a => a.subtype() == AnomalySubType.RESOURCE_FILE_TYPE && a.description().contains("executable"))
    val reHintsExe = if (exeAnoms.isEmpty) Nil else
      List(StandardReHint(exeAnoms.asJava, ReHintType.EMBEDDED_EXE_RE_HINT))

    val archiveAnoms = anomalies.asScala.filter(a =>
      a.subtype() == AnomalySubType.RESOURCE_FILE_TYPE && a.description().contains("archive"))
    val reHintsArchive = if (archiveAnoms.isEmpty) Nil else
      List(StandardReHint(exeAnoms.asJava, ReHintType.ARCHIVE_RE_HINT))

    reHintsArchive ::: reHintsExe ::: Nil
  }

  private def checkOverlayFileTypes(): List[ReHint] = {
    val rhList = ListBuffer[ReHint]()

    def addReHintIfFilter(filterString: String, hintType: ReHintType): Boolean = {
      val filtered = anomalies.asScala.filter(a =>
        a.subtype() == AnomalySubType.OVERLAY_HAS_SIGNATURE && a.description().contains(filterString))
      if(filtered.isEmpty) false
      else {
        rhList += StandardReHint(filtered.asJava, hintType)
        true
      }
    }

    def addReHintForAnyFilter(filterStringList : List[String], reHintType: ReHintType): Unit = {
      filterStringList.takeWhile(addReHintIfFilter(_, reHintType))
    }

    addReHintIfFilter("installer", ReHintType.INSTALLER_RE_HINT )
    addReHintIfFilter("archive", ReHintType.ARCHIVE_RE_HINT)
    addReHintIfFilter("executable", ReHintType.EMBEDDED_EXE_RE_HINT)
    addReHintForAnyFilter(List("sfx", "self-extract"), ReHintType.SFX_RE_HINT)
    addReHintIfFilter("NSIS", ReHintType.NULLSOFT_RE_HINT)
    rhList.toList
  }
}
