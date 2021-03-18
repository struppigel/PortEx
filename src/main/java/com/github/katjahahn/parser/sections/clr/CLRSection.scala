package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.{MemoryMappedPE, PEData, PhysicalLocation}
import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.sections.debug.DebugSection
import org.apache.logging.log4j.LogManager

import java.util

class CLRSection(val generalMetadata: GeneralMetadata) extends SpecialSection {

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

object CLRSection {

  /**
   * BSJB
   */
  val magic = 0x424A5342

  val logger = LogManager.getLogger(DebugSection.getClass().getName())

  def apply(mmbytes: MemoryMappedPE, offset: Long, virtualAddress: Long, data: PEData): CLRSection = {
    val meta = new GeneralMetadata(majorversion = 0, minorversion = 0, extradata = 0, versionLen = 0, versionString = "", fFlags = 0, padding = 0, streamNr = 0)
    new CLRSection(meta)
  }

  /**
   * Creates an instance of the DebugSection for the given debug bytes.
   *
   * @param loadInfo the load information
   * @return debugsection instance
   */
  def newInstance(li: LoadInfo): CLRSection =
    apply(li.memoryMapped, li.fileOffset, li.va, li.data)


}
