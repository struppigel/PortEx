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

import scala.collection.JavaConverters._
import io.github.struppigel.tools.anomalies.{AnomalySubType}
import io.github.struppigel.tools.rehints.{ReHintType}

import scala.collection.mutable.ListBuffer
import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.tools.rehints.{ReHint, ReHintScanner, StandardReHint}

trait PyInstallerScanning extends ReHintScanner {

  abstract override def scanReport(): String =
    "Applied PyInstallerScanning" + NL + super.scanReport

  abstract override def scan(): List[ReHint] = {
    val reList = ListBuffer[ReHint]()
    reList ++= _scan()
    super.scan ::: reList.toList
  }

  private def _scan(): List[ReHint] = {
    val filtered = anomalies.asScala.filter(a =>
      a.subtype() == AnomalySubType.OVERLAY_HAS_SIGNATURE && a.description().contains("zlib archive"))
    if (!filtered.isEmpty) {
      val zlib = filtered.head
      val filteredPy = anomalies.asScala.filter(a => a.subtype() == AnomalySubType.RE_HINT && a.description().contains("PyInstaller"))
      if(!filteredPy.isEmpty) {
        val pyinstaller = filteredPy.head
        val anoms = zlib :: pyinstaller :: Nil
        return List(StandardReHint(anoms.asJava, ReHintType.PYINSTALLER_RE_HINT))
      }
    }
    Nil
  }
}