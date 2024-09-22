package com.github.struppigel.tools.sigscanner.v2
/*******************************************************************************
 * Copyright 2024 Karsten Hahn
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
 ******************************************************************************/
import com.github.struppigel.parser.{PEData, PELoader}
import com.github.struppigel.tools.sigscanner.v2.PESignatureScanner.{ScanResult, SignatureMatch, logger}
import org.apache.logging.log4j.LogManager

import java.io.File
import scala.Function.tupled
import scala.collection.JavaConverters._

class PESignatureScanner(signatures : List[Signature]) {

  def _scan(pe : PEData) : List[ScanResult] = {
    // filter only scan locations that are required by the signatures
    val scanLocations = ScanLocation.values().filter(l => signatures.exists(_.scanLocations.contains(l)))
    // for each scan location get a scanner and scan
    val results = scanLocations.flatMap(loc => loc.getScanner.scan(pe, signatures))
    results.toList
  }

  def scan(pe : PEData) : java.util.List[SignatureMatch] =
    (_scan(pe) map tupled {(sig,addr) => new SignatureMatch(sig, addr)}).asJava
}

object PESignatureScanner {

  private val logger = LogManager.getLogger(PESignatureScanner.getClass.getName)

  /**
   * A file offset/address
   */
  type Address = Long

  /**
   * a scan result is a signature and the address where it was found
   */
  type ScanResult = (Signature, Address)

  /**
   * Same as a scan result but for Java usage
   */
  class SignatureMatch(val signature: Signature, val address: Address)

}