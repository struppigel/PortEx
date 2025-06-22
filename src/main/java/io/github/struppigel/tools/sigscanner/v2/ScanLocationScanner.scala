package io.github.struppigel.tools.sigscanner.v2

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
import io.github.struppigel.parser.ScalaIOUtil.using
import io.github.struppigel.parser.{IOUtil, PEData}
import io.github.struppigel.parser.optheader.StandardFieldEntryKey.ADDR_OF_ENTRY_POINT
import io.github.struppigel.parser.sections.SectionLoader
import io.github.struppigel.tools.Overlay
import PESignatureScanner.ScanResult

import java.io.RandomAccessFile

// generic scanner
abstract class ScanLocationScanner {
  def scan(pe : PEData, signatures : List[Signature]): List[ScanResult]
}

// implements methods for scanners that have exactly one location
abstract class SingleScanLocationScanner extends ScanLocationScanner {

  val DEFAULT_SCAN_SIZE = 0x2000

  def getLocationStart(pe : PEData): Long

  def getLocationBytes(pe : PEData): Array[Byte] = {
    val file = pe.getFile
    using(new RandomAccessFile(file, "r")) { raf =>
      return IOUtil.loadBytesSafely(getLocationStart(pe), getLocationSize(pe), raf)
    }
  }

  def locationExists(pe: PEData): Boolean

  def getLocationSize(pe : PEData): Int = DEFAULT_SCAN_SIZE

  def scan(pe : PEData, signatures : List[Signature]): List[ScanResult] = {
    if(!locationExists(pe)) return Nil
    val bytes = getLocationBytes(pe)
    val absoluteOffset = getLocationStart(pe)
    signatures.filter(_.matches(bytes)._1).map(s => (s, s.matches(bytes)._2 + absoluteOffset))
  }
}

/** concrete location scanners **/

class EntryPointSigScanner() extends SingleScanLocationScanner {

  def maybeGetEntryPoint(pe: PEData): Option[Long] = {
    val rva = pe.getOptionalHeader().getStandardFieldEntry(ADDR_OF_ENTRY_POINT).getValue
    if(rva <= 0) return None

    val loader = new SectionLoader(pe)
    val offset = loader.getFileOffset(rva)
    if (offset <= pe.getFile.length()) return Some(offset)
    else return None
  }

  override def getLocationStart(pe: PEData): Long = {
    val maybeEp = maybeGetEntryPoint(pe)
    if(maybeEp.isDefined) return maybeEp.get
    else -1
  }

  override def locationExists(pe: PEData): Boolean = maybeGetEntryPoint(pe).isDefined
}

class OverlaySigScanner() extends SingleScanLocationScanner {

  // uses default scan size for now!

  override def locationExists(pe: PEData): Boolean =
    new Overlay(pe).exists()

  override def getLocationStart(pe: PEData): Long =
    new Overlay(pe).getOffset
}

class MSDosStubSigScanner() extends SingleScanLocationScanner {

  override def getLocationStart(pe: PEData): Long = 0

  override def getLocationSize(pe : PEData): Int = {
    val headerSize = pe.getMSDOSHeader.getHeaderSize.toInt
    val peSigOffset = pe.getPESignature.getOffset.toInt
    // the whole stub shall be included, but in case of overlapping headers we may have check which offset is bigger
    math.max(headerSize, peSigOffset)
  }

  // since this is a PE location, the stub must exist
  override def locationExists(pe: PEData): Boolean = true
}



