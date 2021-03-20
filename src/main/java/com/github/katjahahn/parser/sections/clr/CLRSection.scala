package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.{FileFormatException, IOUtil, MemoryMappedPE, PEData, PELoader, PhysicalLocation}
import com.github.katjahahn.parser.sections.{SectionLoader, SpecialSection}
import com.github.katjahahn.parser.sections.debug.DebugSection.debugspec
import com.github.katjahahn.parser.sections.debug.{DebugDirectoryKey, DebugSection}
import org.apache.logging.log4j.LogManager

import collection.JavaConverters._
import java.util
import java.io.File

class CLRSection() extends SpecialSection {

  /**
   * Returns whether the special section has no entries.
   *
   * @return true if no entries, false otherwise
   */
  override def isEmpty: Boolean = ???

  /**
   * Returns a list of physical address ranges this special section is parsed from.
   *
   * @return list of locations
   */
  override def getPhysicalLocations: util.List[PhysicalLocation] = ???

  /**
   * Returns the file offset for the beginning of the module.
   *
   * @return file offset for the beginning of the module
   */
  override def getOffset: Long = ???

  /**
   * Returns a description string of the {@link Header}.
   *
   * @return description string
   */
  override def getInfo: String = ???
}

object CLRSection extends App {

  val Magic = "BSJB".getBytes()
  val metaRootSpec = "clrmetarootspec"
  val logger = LogManager.getLogger(CLRSection.getClass().getName())

  new SectionLoader(new File("portextestfiles/testfiles/decrypt_STOPDjvu.exe")).loadCLRSection()

  def apply(mmbytes: MemoryMappedPE, offset: Long, virtualAddress: Long, data: PEData): CLRSection = {

    val clrSize = 0x1000 //FIXME this is a temp value
    val clrbytes = mmbytes.slice(virtualAddress, virtualAddress + clrSize)
    val signature = clrbytes.take(Magic.length)
    if(!signature.sameElements(Magic)) {
      logger.warn("Magic BSJB not found")
      throw new FileFormatException("Magic BSJB not found!")
    }
    //val format = new SpecificationFormat(0, 1, 2, 3)
    //val entries = IOUtil.readHeaderEntries(classOf[MetadataRootKey],
    // format, metaRootSpec, clrbytes, offset).asScala.toMap
    //val debugTypeValue = entries(DebugDirectoryKey.TYPE).getValue
    new CLRSection()
  }

  /**
   * Creates an instance of the DebugSection for the given debug bytes.
   *
   * @param li the load information
   * @return debugsection instance
   */
  def newInstance(li: LoadInfo): CLRSection =
    apply(li.memoryMapped, li.fileOffset, li.va, li.data)


}
