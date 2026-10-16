/**
 * *****************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools.sigscanner

import java.io.File
import scala.collection.JavaConverters._

/**
 * The signature databases that come with PortEx. They are loaded and compiled
 * once on first use and shared by all callers.
 */
object DefaultSignatures {

  private val folder = "/data/signatures/"

  /** packers, protectors and compilers, mostly at the entry point */
  lazy val packers: SignatureDatabase = SignatureDatabase.loadResource(folder + "packers.sig")

  /** installers and archives in the overlay */
  lazy val installers: SignatureDatabase = SignatureDatabase.loadResource(folder + "installers.sig")

  /** file type magic numbers in the overlay, resources and at the start of files */
  lazy val fileTypes: SignatureDatabase = SignatureDatabase.loadResource(folder + "filetypes.sig")

  /** Java wrappers, searched in the whole file */
  lazy val javaWrappers: SignatureDatabase = SignatureDatabase.loadResource(folder + "javawrappers.sig")

  /** packers, protectors, cryptors, installers and SFX converted from Detect It Easy */
  lazy val die: SignatureDatabase = SignatureDatabase.loadResource(folder + "die.sig")

  /** the signatures PEData scans: packers, installers, file types and the Detect It Easy signatures */
  lazy val pe: SignatureDatabase = SignatureDatabase.merge(packers, installers, fileTypes, die)

  lazy val peScanner: SignatureScanner = new SignatureScanner(pe)

  lazy val fileTypeScanner: SignatureScanner = new SignatureScanner(fileTypes)

  lazy val javaWrapperScanner: SignatureScanner = new SignatureScanner(javaWrappers)

  /**
   * Scans a file that is no PE file or cannot be parsed as one with the
   * signatures PEData scans. Only the locations file and eof are scanned, so
   * the matches are mostly file types. For PE files use
   * PEData.getSignatureMatches().
   *
   * @param file the file
   * @return matched signatures
   */
  def scanFile(file: File): java.util.List[SignatureMatch] = _scanFile(file).asJava

  def _scanFile(file: File): IndexedSeq[SignatureMatch] = peScanner._scanFile(file)

  def getPackers: SignatureDatabase = packers

  def getInstallers: SignatureDatabase = installers

  def getFileTypes: SignatureDatabase = fileTypes

  def getJavaWrappers: SignatureDatabase = javaWrappers

  def getDie: SignatureDatabase = die

  def getPE: SignatureDatabase = pe

  def getPEScanner: SignatureScanner = peScanner

  def getFileTypeScanner: SignatureScanner = fileTypeScanner

  def getJavaWrapperScanner: SignatureScanner = javaWrapperScanner
}
