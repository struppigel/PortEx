/**
 * *****************************************************************************
 * Copyright 2016 Katja Hahn
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

package com.github.katjahahn.tools.sigscanner

import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.tools.sigscanner.SignatureScanner.{ScanResult, SignatureMatch}

import java.io.File
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

class FileTypeScanner(sigscanner: SignatureScanner, file: File) {

  def _scanAt(offset: Long): List[ScanResult] =
    sigscanner._scanAt(file, offset)

  def scanAt(offset: Long): java.util.List[SignatureMatch] =
    sigscanner.scanAt(file, offset)

  def scanAtReport(offset: Long): java.util.List[String] =
    sigscanner.scanAtToString(file, offset)

}

object FileTypeScanner {

  private val signatureFile = "customsigs_GCK.txt"

  def main(args: Array[String]): Unit = {
    val file = new File("/home/katja/samples/test")
    for (i <- Range(212000, file.length.toInt)) {
      FileTypeScanner(file).scanAtReport(i).asScala.foreach(println)
    }
  }

  def apply(file: File): FileTypeScanner = {
    val signatures = loadSignatures().filter { s => s.bytesMatched() >= 3 || s.name == "MS-DOS or Portable Executable" }
    val sigscanner = new SignatureScanner(signatures)
    new FileTypeScanner(sigscanner, file)
  }

  private def loadSignatures(): List[Signature] = {
    val sigs = ListBuffer[Signature]()
    val sigArrays = IOUtil.readArray(signatureFile, ",").asScala
    for (array <- sigArrays) {
      val name = array(0)
      val bytes = array(1)
      //      if (bytes.length() > 8) {
      sigs += Signature(name, false, bytes)
      //      }
    }
    sigs.toList
  }

}

