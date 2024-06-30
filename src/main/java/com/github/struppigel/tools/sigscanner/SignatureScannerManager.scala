/**
 * *****************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
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
 * ****************************************************************************
 */
package com.github.struppigel.tools.sigscanner

import com.github.struppigel.parser.PEData
import com.github.struppigel.parser.sections.SectionLoader
import com.github.struppigel.tools.Overlay

import scala.collection.JavaConverters._

/**
 * Interface to access all relevant signatures for PE files easily from Java.
 * Uses lazy loading for each signature group.
 *
 * @param pedata
 */
class SignatureScannerManager(pedata: PEData) {

  lazy private val peidSigs = SignatureScanner.newInstance()._scanAll(pedata.getFile).map(SignatureScanner.toMatchedSignature(_))
  def getPEIDSignatures() : java.util.List[MatchedSignature] = peidSigs.asJava

  lazy private val overlaySigs = {
    val offset = new Overlay(pedata).getOffset
    // scan with signatures that are specific to the overlay only
    val overlaySpecific = new SignatureScanner(SignatureScanner._loadOverlaySigs())
      ._scanAt(pedata.getFile, offset)
      .map(SignatureScanner.toMatchedSignature(_))
    // scan overlay with filetype signatures
    val fileTypes = FileTypeScanner(pedata.getFile)._scanAt(offset)
      .map(SignatureScanner
      .toMatchedSignature(_))
    overlaySpecific ::: fileTypes
  }
  def getOverlaySignatures(): java.util.List[MatchedSignature] = overlaySigs.asJava

  lazy private val resourceSigs : List[MatchedSignature] = {
    val loader = new SectionLoader(pedata)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent && !maybeRSRC.get.isEmpty) {
      val rsrc = maybeRSRC.get
      val resources = rsrc.getResources().asScala
      // obtain resource offsets
      val offsets = resources.map(_.rawBytesLocation.from)
      // scan at each offset with filetype signatures
      val fileTypes = offsets.flatMap(FileTypeScanner(pedata.getFile)._scanAt(_))
      // convert to matched signature instances
      fileTypes.map(SignatureScanner.toMatchedSignature(_)).toList
    } else Nil
  }
  def getResourceSignatures() : java.util.List[MatchedSignature] = resourceSigs.asJava

  lazy private val msdosSigs : List[MatchedSignature] = {
    // we only have one signature so far
    val pattern = List[Byte](0x49, 0x6E, 0x55, 0x6E).map(Some(_))
    val sig = new Signature(name="InnoSetup", epOnly = false, pattern.toArray)
    val scanner = new SignatureScanner(List(sig))
    val results = scanner._scanAt(pedata.getFile, 0x30)
    results.map(SignatureScanner.toMatchedSignature(_))
  }
  def getMSDOSSignatures() : java.util.List[MatchedSignature] = msdosSigs.asJava

  def getAllSignatures() : java.util.List[MatchedSignature] =
    (peidSigs ::: overlaySigs ::: msdosSigs ::: resourceSigs).asJava


}