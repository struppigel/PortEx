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
import com.github.katjahahn.parser._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.clr.MetadataRoot.{alignToFourBytes, versionOffset}
import com.github.katjahahn.parser.sections.clr.MetadataRootKey._
import org.apache.logging.log4j.LogManager

import java.io.{IOException, RandomAccessFile}
import java.nio.charset.StandardCharsets
import java.util.Optional
import scala.annotation.tailrec
import scala.collection.JavaConverters._

class MetadataRoot (
                     val metadataEntries : Map[MetadataRootKey, StandardField],
                     val offset : Long,
                     val versionString : String,
                     val streamHeaders : List[StreamHeader],
                     private val optimizedStream: Option[OptimizedStream],
                     private val guidHeap: Option[GuidHeap],
                     private val stringsHeap: Option[StringsHeap],
                     private val blobHeap : Option[BlobHeap],
                     val nonZeroTerminatedHeaders: List[StreamHeader]) {

  // for anomaly checks
  def versionStringNotReadable : Boolean = versionString == MetadataRoot.NOT_READABLE_STRING
  // Getters for Java access
  def getMetaDataEntries : java.util.Map[MetadataRootKey, StandardField] = metadataEntries.asJava
  def getVersionString : String = versionString
  def getOffset : Long = offset
  def getStreamHeaders : java.util.List[StreamHeader] = streamHeaders.asJava
  // the maybe stream getters, also for Java
  def maybeGetOptimizedStream : Optional[OptimizedStream] = optionToOptional(optimizedStream)
  def maybeGetGuidHeap : Optional[GuidHeap] = optionToOptional(guidHeap)
  def maybeGetStringsHeap : Optional[StringsHeap] = optionToOptional(stringsHeap)
  def maybeGetBlobHeap : Optional[BlobHeap] = optionToOptional(blobHeap)
  def maybeGetStreamHeaderByName(name : String): java.util.Optional[StreamHeader] =
    optionToOptional(streamHeaders.find(_.name == name))

  def getPhysicalLocations: List[PhysicalLocation] = {
    // version length + padding
    val versionLength = alignToFourBytes(metadataEntries(MetadataRootKey.LENGTH).getValue)
    // total size of metadata root
    val sizeOfFlagsNStreams = 4
    val streamHeaderSizes = streamHeaders.map(_.getHeaderSize).sum
    val size = versionOffset + versionLength + sizeOfFlagsNStreams + streamHeaderSizes
    List(new PhysicalLocation(offset, size))
  }

  private def optionToOptional[A](convertee : Option[A]) : Optional[A] = {
    convertee match {
      case Some(s) => Optional.of(s)
      case None => Optional.empty()
    }
  }

  def getBSJBOffset: Long = metadataEntries(MetadataRootKey.SIGNATURE).getOffset

  def getInfo: String = "Metadata Root:" + NL + "-------------" + NL + metadataEntries.values.mkString(NL) + NL +
    "version: " + versionString + NL + NL +
    "Stream headers: " + streamHeaders.map(_.name).mkString(", ") + NL
}

object MetadataRoot {
  private val logger = LogManager.getLogger(classOf[MetadataRoot].getName)
  val NOT_READABLE_STRING = "<not readable>"
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
    val metaRootEntries = (metaRootEntriesPart ++
      Map(FLAGS -> flagsNStreamsEntries(FLAGS), STREAMS -> flagsNStreamsEntries(STREAMS))
      ).filter(e => e._2.getDescription != "this field was not set")

    throwIfBadMagic(metaRootEntries(SIGNATURE).getValue)

    // load stream headers in metadata root
    val streamHeadersVA =  metadataVA + versionOffset + versionLength + 4 // 4 = size of flags + streams
    val (streamHeaders, nonZeroTerminatedHeaders) = readStreamHeaders(metaRootEntries(STREAMS).getValue, streamHeadersVA, mmbytes)
    // load opt stream temporarily for reading heap sizes
    val optTemp = maybeLoadOptimizedStream(streamHeaders, metadataVA, mmbytes, None, None, None)
    if( optTemp.isDefined) {
      val strIndexSize = optTemp.get.getStringHeapSize
      val blobIndexSize = optTemp.get.getBlobHeapSize
      val guidIndexSize = optTemp.get.getGUIDHeapSize
      // load streams if present
      val stringsHeap = maybeLoadStringHeap(streamHeaders, metadataVA, mmbytes, strIndexSize)
      val guidHeap = maybeLoadGuidHeap(streamHeaders, metadataVA, mmbytes, guidIndexSize)
      val blobHeap = maybeLoadBlobHeap(streamHeaders, metadataVA, mmbytes, blobIndexSize)
      val optimizedStream = maybeLoadOptimizedStream(streamHeaders, metadataVA, mmbytes, stringsHeap, guidHeap, blobHeap)
      // create MetadataRoot with optimized stream
      return new MetadataRoot(metaRootEntries, metadataFileOffset, versionString, streamHeaders, optimizedStream, guidHeap, stringsHeap, blobHeap, nonZeroTerminatedHeaders)
    }
    // No optimized stream found, create MetadataRoot without it
    new MetadataRoot(metaRootEntries, metadataFileOffset, versionString, streamHeaders, None, None, None, None, nonZeroTerminatedHeaders)
  }

  private def maybeLoadOptimizedStream( streamHeaders : List[StreamHeader], metadataVA : Long, mmbytes: MemoryMappedPE,
                                        stringsHeap : Option[StringsHeap], guidHeap : Option[GuidHeap], blobHeap : Option[BlobHeap]): Option[OptimizedStream] = {
    streamHeaders.find(_.name == "#~") match {
      case Some(header) => Some(OptimizedStream(header.size, metadataVA + header.offset, mmbytes, stringsHeap, guidHeap, blobHeap))
      case None => None
    }
  }

  private def maybeLoadStringHeap(streamHeaders : List[StreamHeader], metadataVA : Long, mmbytes: MemoryMappedPE, indexSize : Int) : Option[StringsHeap] = {
    streamHeaders.find(_.name == "#Strings") match {
      case Some(header) => Some(StringsHeap(header.size, metadataVA + header.offset, mmbytes, indexSize))
      case None => None
    }
  }

  private def maybeLoadGuidHeap(streamHeaders : List[StreamHeader], metadataVA : Long, mmbytes: MemoryMappedPE, indexSize : Int) : Option[GuidHeap] = {
    streamHeaders.find(_.name == "#GUID") match {
      case Some(header) => Some(GuidHeap(header.size, metadataVA + header.offset, mmbytes, indexSize))
      case None => None
    }
  }

  private def maybeLoadBlobHeap(streamHeaders : List[StreamHeader], metadataVA : Long, mmbytes: MemoryMappedPE, indexSize : Int) : Option[BlobHeap] = {
    streamHeaders.find(_.name == "#Blob") match {
      case Some(header) => Some(BlobHeap(header.size, metadataVA + header.offset, mmbytes, indexSize))
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
      try {
        val version = IOUtil.readNullTerminatedUTF8String(metadataFileOffset + versionOffset, raf)
        if (version == null || version.isEmpty) {
          logger.warn("Could not read .NET version string!")
          NOT_READABLE_STRING
        } else version
      } catch {
        case _: IOException => logger.warn("Could not read .NET version string!")
                               return NOT_READABLE_STRING
      }
    }
  }

  private def throwIfBadMagic(magic : Long): Unit = {
    // BSJB
    if(magic != 0x424a5342){
      throw new FileFormatException("No BSJB signature!")
    }
  }

  /**
   * Reads nr amount of stream headers from the startOffset in the given mmbytes
   * @param nr the number of stream headers to load
   * @param startOffset the offset into mmbytes
   * @param mmbytes the memory mapped PE object
   * @return tuple of list of all loaded stream headers and list of stream headers with non-zero term anomaly
   */
  private def readStreamHeaders(nr: Long, startOffset: Long, mmbytes: MemoryMappedPE): (List[StreamHeader], List[StreamHeader]) = {
    if(nr <= 0) (List(),List())
    else {
      val va = startOffset
      val offset = mmbytes.getBytesLongValue(va, 4)
      val size = mmbytes.getBytesLongValue(va + 4, 4)
      val nameOffset = va + 8
      val nameLen = Math.min(mmbytes.indexWhere(_ == 0, nameOffset) - nameOffset, 32L) + 1 //minimum 32 characters, includes zero term
      val namePaddedLen = alignToFourBytes(nameLen)
      // create name without zero term
      val name = new String(mmbytes.slice(nameOffset, nameOffset + nameLen - 1), StandardCharsets.UTF_8)
      val result : StreamHeader =  new StreamHeader(offset, size, name)
      // check for zero term anomaly
      val hasZeroTerm = mmbytes.get(nameOffset + nameLen - 1) == 0.toByte
      val nonZeroTerminatedHeaders = if(!hasZeroTerm) List(result) else List[StreamHeader]()
      // recursive call
      val (nextHeaders, nextNonZeroTerminatedHeaders) = readStreamHeaders(nr - 1, nameOffset + namePaddedLen, mmbytes)
      // prepending results from recursive call
      (result :: nextHeaders, nonZeroTerminatedHeaders ::: nextNonZeroTerminatedHeaders)
    }
  }

  @tailrec
  def alignToFourBytes(value: Long): Long = {
    if (value % 4 == 0) value
    else alignToFourBytes(value + 1)
  }


}

/**
 * Represents a stream header
 *
 * @param offset offset of stream
 * @param size size of stream
 * @param name name of stream
 */
class StreamHeader(val offset: Long, val size : Long, val name: String) {
  /**
   * Size of the header
   * @return size of header in bytes
   */
  def getHeaderSize: Long = 8 + alignToFourBytes(name.length)
}
