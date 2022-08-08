/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
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

package com.github.katjahahn.parser.sections.clr
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.clr.MetadataRootKey._
import com.github.katjahahn.parser._
import com.google.common.base.Optional

import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import scala.annotation.tailrec
import scala.collection.JavaConverters._

class MetadataRoot (
                     val metadataEntries : Map[MetadataRootKey, StandardField],
                     val offset : Long,
                     val versionString : String,
                     val streamHeaders : List[StreamHeader],
                     private val optimizedStream: Option[OptimizedStream]){

  def maybeGetOptimizedStream : Optional[OptimizedStream] = {
    optimizedStream match {
      case Some(str) => Optional.of(str)
      case None => Optional.absent()
    }
  }

  def getInfo: String = "Metadata Root:" + NL + "-------------" + NL + metadataEntries.values.mkString(NL) + NL +
    "version: " + versionString + NL + NL +
    "Stream headers: " + streamHeaders.map(_.name).mkString(", ") + NL
}

object MetadataRoot {
  private val metaRootSpec = "clrmetarootspec"
  private val metaRootSpec2 = "clrmetarootspec2"
  private val versionOffset = 16
  // specification format for both specs
  private val formatMeta = new SpecificationFormat(0, 1, 2, 3)

  def apply(mmbytes: MemoryMappedPE, data: PEData, metadataVA: Long, metadataSize: Long): MetadataRoot = {
    // load first part of meta data root
    val metadataFileOffset = new SectionLoader(data).getFileOffset(metadataVA)
    val metaRootEntriesPart = loadMetaRootEntriesFirstPart(mmbytes, metadataVA, metadataSize, metadataFileOffset)
    // load version and version length
    val versionString  = loadVersionString(metadataFileOffset, data)
    val versionLength = alignToFourBytes(metaRootEntriesPart(LENGTH).getValue)
    // load remaining header entries that are dependent on version length
    val flagsNStreamsEntries = loadFlagsAndStreams(mmbytes, metadataVA, formatMeta, versionLength)
    // construct complete metadataRootEntries, avoid overwriting with 0 entries for missing data
    val metaRootEntries = metaRootEntriesPart ++
      Map(FLAGS -> flagsNStreamsEntries(FLAGS), STREAMS -> flagsNStreamsEntries(STREAMS))

    throwIfBadMagic(metaRootEntries(SIGNATURE).getValue)
    // load stream headers in metadata root
    val streamHeadersVA =  metadataVA + versionOffset + versionLength + 4 // 4 = size of flags + streams
    val streamHeaders = readStreamHeaders(metaRootEntries(STREAMS).getValue, streamHeadersVA, mmbytes)
    // load optimized stream
    val optimizedStream = maybeLoadOptimizedStream(streamHeaders, metadataVA, mmbytes)
    // create MetadataRoot
    new MetadataRoot(metaRootEntries, metadataFileOffset, versionString, streamHeaders, optimizedStream)
  }

  private def maybeLoadOptimizedStream( streamHeaders : List[StreamHeader], metadataVA : Long, mmbytes: MemoryMappedPE): Option[OptimizedStream] = {
    streamHeaders.find(_.name == "#~") match {
      case Some(header) => Some(OptimizedStream(header.size, metadataVA + header.offset, mmbytes))
      case None => None
    }
  }

  private def loadMetaRootEntriesFirstPart(mmbytes: MemoryMappedPE, metadataVA: Long, metadataSize: Long, metadataFileOffset: Long) = {
    val metaBytes = mmbytes.slice(metadataVA, metadataVA + metadataSize)
    val metaRootEntriesPart = IOUtil.readHeaderEntries(classOf[MetadataRootKey],
      formatMeta, metaRootSpec, metaBytes, metadataFileOffset).asScala.toMap
    metaRootEntriesPart
  }

  private def loadFlagsAndStreams(mmbytes: MemoryMappedPE, metadataVA: Long, formatMeta: SpecificationFormat, versionLength: Long) = {
    val flagsVA = metadataVA + versionOffset + versionLength
    val tempBytes = mmbytes.slice(flagsVA, flagsVA + 4)
    IOUtil.readHeaderEntries(classOf[MetadataRootKey],
      formatMeta, metaRootSpec2, tempBytes, 0).asScala
  }

  private def loadVersionString(metadataFileOffset: Long, data: PEData): String = {
    ScalaIOUtil.using(new RandomAccessFile(data.getFile, "r")) { raf =>
      IOUtil.readNullTerminatedUTF8String(metadataFileOffset + versionOffset, raf)
    }
  }

  private def throwIfBadMagic(magic : Long): Unit = {
    // BSJB
    if(magic != 0x424a5342){
      throw new FileFormatException("No BSJB signature!")
    }
  }

  private def readStreamHeaders(nr: Long, startOffset: Long, mmbytes: MemoryMappedPE): List[StreamHeader] = {
    if(nr <= 0) List()
    else {
      val va = startOffset
      val offset = mmbytes.getBytesLongValue(va, 4)
      val size = mmbytes.getBytesLongValue(va + 4, 4)
      val nameOffset = va + 8
      val nameLen = Math.min(mmbytes.indexWhere(_ == 0, nameOffset) - nameOffset, 32L) + 1 //minimum 32 characters, includes zero term
      val namePaddedLen = alignToFourBytes(nameLen)
      // TODO anomaly if not zero terminated header?
      val name_zero = new String(mmbytes.slice(nameOffset, nameOffset + nameLen), StandardCharsets.UTF_8)
      // remove zero term
      val name = name_zero.substring(0,name_zero.length - 1)
      new StreamHeader(offset, size, name) :: readStreamHeaders(nr - 1, nameOffset + namePaddedLen, mmbytes)
    }
  }

  @tailrec
  private def alignToFourBytes(value: Long): Long = {
    if (value % 4 == 0) value
    else alignToFourBytes(value + 1)
  }


}

class StreamHeader(val offset: Long, val size : Long, val name: String){}
