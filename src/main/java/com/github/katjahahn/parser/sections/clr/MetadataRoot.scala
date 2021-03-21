package com.github.katjahahn.parser.sections.clr
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.{IOUtil, MemoryMappedPE, PEData, ScalaIOUtil, StandardField}

import java.io.RandomAccessFile

class MetadataRoot (
                     val metadataEntries : Map[MetadataRootKey, StandardField],
                     val offset : Long,
                     val versionString : String){

  def getInfo(): String = "Metadata Root:" + NL + "-------------" + NL + metadataEntries.values.mkString(NL) + NL +
  "Version: " + versionString + NL
}

object MetadataRoot {

  val Magic = "BSJB".getBytes()
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
    val versionLength = alignVersionLength(metaRootEntriesPart.get(MetadataRootKey.LENGTH).get.getValue)
    val versionOffset = 16
    var versionString = ""
    ScalaIOUtil.using(new RandomAccessFile(data.getFile, "r")) { raf =>
      versionString = IOUtil.readNullTerminatedUTF8String(metadataFileOffset + versionOffset, raf)
    }
    // load remaining stuff that's dependent on version length
    val metaOffsetAfterVersion = metadataFileOffset + versionOffset + versionLength
    val metaRootEntriesTail = IOUtil.readHeaderEntries(classOf[MetadataRootKey],
      formatMeta, metaRootSpec2, metaBytes, metaOffsetAfterVersion).asScala
    val flags = metaRootEntriesTail.get(MetadataRootKey.FLAGS).get
    val streams = metaRootEntriesTail.get(MetadataRootKey.STREAMS).get
    // construct the full entry map
    val metaRootEntries = metaRootEntriesPart ++ Map(MetadataRootKey.FLAGS -> flags, MetadataRootKey.STREAMS -> streams)
    new MetadataRoot(metaRootEntries, metadataFileOffset, versionString)
  }

  private def alignVersionLength(value: Long): Long = {
    var x = value
    while (x % 4 != 0) x += 1
    x
  }
}
