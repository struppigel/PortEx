package com.github.katjahahn.parser.sections.clr
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.clr.MetadataRootKey._
import com.github.katjahahn.parser.{FileFormatException, IOUtil, MemoryMappedPE, PEData, ScalaIOUtil, StandardField}

import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import scala.annotation.tailrec

class MetadataRoot (
                     val metadataEntries : Map[MetadataRootKey, StandardField],
                     val offset : Long,
                     val versionString : String,
                     val streamHeaders : List[StreamHeader]){

  def getInfo: String = "Metadata Root:" + NL + "-------------" + NL + metadataEntries.values.mkString(NL) + NL +
    "version: " + versionString + NL + NL +
    "Stream headers: " + streamHeaders.map(_.name).mkString(", ") + NL
}

object MetadataRoot {
  val metaRootSpec = "clrmetarootspec"
  val metaRootSpec2 = "clrmetarootspec2"

  def apply(mmbytes: MemoryMappedPE, data: PEData, metadataVA: Long, metadataSize: Long): MetadataRoot = {
    // load first part of meta data root
    val metadataFileOffset = new SectionLoader(data).getFileOffset(metadataVA)
    val metaBytes = mmbytes.slice(metadataVA, metadataVA + metadataSize)
    val formatMeta = new SpecificationFormat(0, 1, 2, 3)
    val metaRootEntriesPart = IOUtil.readHeaderEntries(classOf[MetadataRootKey],
      formatMeta, metaRootSpec, metaBytes, metadataFileOffset).asScala.toMap
    // load version string and determine offset to flags and streams
    val versionOffset = 16
    var versionString = ""
    ScalaIOUtil.using(new RandomAccessFile(data.getFile, "r")) { raf =>
      versionString = IOUtil.readNullTerminatedUTF8String(metadataFileOffset + versionOffset, raf)
    }
    // load remaining header entries that are dependent on version length
    val versionLength = alignToFourBytes(metaRootEntriesPart(LENGTH).getValue)
    val flagsVA =  metadataVA + versionOffset + versionLength
    val tempBytes = mmbytes.slice(flagsVA, flagsVA + 4)
    val entriesTail = IOUtil.readHeaderEntries(classOf[MetadataRootKey],
      formatMeta, metaRootSpec2, tempBytes, 0).asScala

    val metaRootEntries = metaRootEntriesPart ++
      Map(FLAGS -> entriesTail(FLAGS), STREAMS -> entriesTail(STREAMS))

    throwIfBadMagic(metaRootEntries(SIGNATURE).getValue)
    // load stream headers
    val streamHeadersVA =  metadataVA + versionOffset + versionLength + 4 // 4 = size of flags + streams
    val streamHeaders = readStreamHeaders(metaRootEntries(STREAMS).getValue, streamHeadersVA, mmbytes)
    // create MetadataRoot
    new MetadataRoot(metaRootEntries, metadataFileOffset, versionString, streamHeaders)
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
      val name = new String(mmbytes.slice(nameOffset, nameOffset + nameLen), StandardCharsets.UTF_8)
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
