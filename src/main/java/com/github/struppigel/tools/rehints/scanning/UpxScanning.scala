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

import com.github.struppigel.tools.rehints.ReHintScannerUtils.{constructReHintIfAnySectionName, optionToList}
import com.github.struppigel.tools.rehints.{ReHint, ReHintScanner, ReHintType}

import scala.collection.mutable.ListBuffer
import com.github.struppigel.parser.IOUtil.NL
import scala.collection.JavaConverters._

trait UpxScanning extends ReHintScanner {

  abstract override def scanReport(): String =
    "Applied UpxScanning" + NL + super.scanReport

  abstract override def scan(): List[ReHint] = {
    val reList = ListBuffer[ReHint]()
    reList ++= checkSectionNames()
    super.scan ::: reList.toList
  }

  private def checkSectionNames(): List[ReHint] = {
    val sectionNames = List("UPX0", "UPX1", "UPX2", "UPX!", ".UPX0", ".UPX1", ".UPX2")
    optionToList(constructReHintIfAnySectionName(sectionNames, data, ReHintType.UPX_PACKER_RE_HINT))
  }

}
