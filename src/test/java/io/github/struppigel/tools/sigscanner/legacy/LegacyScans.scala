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
package io.github.struppigel.tools.sigscanner.legacy

import io.github.struppigel.parser.PEData
import io.github.struppigel.parser.sections.SectionLoader
import io.github.struppigel.tools.Overlay
import io.github.struppigel.tools.sigscanner.legacy.LegacySignatureScanner.ScanResult

import java.io.File
import scala.collection.JavaConverters._

/**
 * A signature match as produced by the v1 scanner.
 *
 * @param group the v1 signature group: peid, overlay, resource, msdos, jar2exe or filetype0
 * @param name the v1 signature name, including the brackets of INI style databases
 * @param address the file offset of the match
 */
case class LegacyMatch(group: String, name: String, address: Long)

/**
 * Reproduces the signature groups of the v1 SignatureScannerManager, plus the
 * Jar2Exe whole file scan and the file type scan for non-PE files.
 *
 * @param asShipped if true, the scanners are created the way v1 did it
 *                  (signature databases are loaded for each call and the file
 *                  type scanner is rebuilt for every resource); if false, all
 *                  scanners are built once and reused
 */
class LegacyScans(asShipped: Boolean = true) {

  private lazy val peidScanner = LegacySignatureScanner().prebuild()
  private lazy val overlayScanner = new LegacySignatureScanner(LegacySignatureScanner.loadOverlaySigs()).prebuild()
  private lazy val fileTypeScanner = new LegacySignatureScanner(LegacySignatureScanner.loadFileTypeSigs()).prebuild()
  private lazy val javaWrapperScanner = new LegacySignatureScanner(LegacySignatureScanner.loadJavaWrapperSigs()).prebuild()

  private def peid(): LegacySignatureScanner =
    if (asShipped) LegacySignatureScanner() else peidScanner

  private def overlay(): LegacySignatureScanner =
    if (asShipped) new LegacySignatureScanner(LegacySignatureScanner.loadOverlaySigs()) else overlayScanner

  private def fileTypes(): LegacySignatureScanner =
    if (asShipped) new LegacySignatureScanner(LegacySignatureScanner.loadFileTypeSigs()) else fileTypeScanner

  private def javaWrappers(): LegacySignatureScanner =
    if (asShipped) new LegacySignatureScanner(LegacySignatureScanner.loadJavaWrapperSigs()) else javaWrapperScanner

  private def toMatches(group: String, results: List[ScanResult]): List[LegacyMatch] =
    results.map { case (sig, addr) => LegacyMatch(group, sig.name, addr) }

  def peidMatches(file: File): List[LegacyMatch] =
    toMatches("peid", peid()._scanAll(file))

  def overlayMatches(pedata: PEData): List[LegacyMatch] = {
    val offset = new Overlay(pedata).getOffset
    val overlaySpecific = overlay()._scanAt(pedata.getFile, offset)
    val fileTypeResults = fileTypes()._scanAt(pedata.getFile, offset)
    toMatches("overlay", overlaySpecific ::: fileTypeResults)
  }

  def resourceMatches(pedata: PEData): List[LegacyMatch] = {
    val loader = new SectionLoader(pedata)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent && !maybeRSRC.get.isEmpty) {
      val offsets = maybeRSRC.get.getResources().asScala.map(_.rawBytesLocation.from)
      toMatches("resource", offsets.flatMap(fileTypes()._scanAt(pedata.getFile, _)).toList)
    } else Nil
  }

  def msdosMatches(pedata: PEData): List[LegacyMatch] = {
    val pattern = List[Byte](0x49, 0x6E, 0x55, 0x6E).map(Some(_))
    val sig = new LegacySignature(name = "InnoSetup", epOnly = false, pattern.toArray)
    toMatches("msdos", new LegacySignatureScanner(List(sig))._scanAt(pedata.getFile, 0x30))
  }

  /** All groups v1 PEData.getSignatures() returned. */
  def allPEMatches(pedata: PEData): List[LegacyMatch] =
    peidMatches(pedata.getFile) ::: overlayMatches(pedata) ::: msdosMatches(pedata) ::: resourceMatches(pedata)

  /** Whole file scan of the Jar2ExeScanner. */
  def jar2exeMatches(file: File): List[LegacyMatch] =
    toMatches("jar2exe", javaWrappers()._findAllEPFalseMatches(file))

  /** File type scan at offset 0, as PortExAnalyzer does it for non-PE files. */
  def fileType0Matches(file: File): List[LegacyMatch] =
    toMatches("filetype0", fileTypes()._scanAt(file, 0))
}
