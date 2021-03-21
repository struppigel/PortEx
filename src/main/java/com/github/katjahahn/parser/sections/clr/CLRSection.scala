package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.sections.{SectionLoader, SpecialSection}
import org.apache.logging.log4j.LogManager

import java.io.{File, RandomAccessFile}
import java.util
import scala.collection.JavaConverters._

class CLRSection(val cliHeader: Map[CLIHeaderKey, StandardField],
                 val metadataRoot: MetadataRoot,
                 private val fileOffset: Long) extends SpecialSection {

  /**
   * Returns whether the special section has no entries.
   *
   * @return true if no entries, false otherwise
   */
  override def isEmpty: Boolean = cliHeader.isEmpty

  /**
   * Returns a list of physical address ranges this special section is parsed from.
   *
   * @return list of locations
   */
  override def getPhysicalLocations: util.List[PhysicalLocation] = List[PhysicalLocation]().asJava

  /**
   * Returns the file offset for the beginning of the module.
   *
   * @return file offset for the beginning of the module
   */
  override def getOffset: Long = fileOffset

  /**
   * Returns a description string of the {@link CLRSection}.
   *
   * @return description string
   */
  override def getInfo: String = {
    val flagsField = cliHeader.get(CLIHeaderKey.FLAGS)
    val flagsVal = {
      if (flagsField.isDefined) flagsField.get.getValue else 0
    }
    val flagsList = ComImageFlag.getAllFor(flagsVal).asScala
    "CLI Header:" + NL +
      "-----------" + NL +
      cliHeader.values.mkString(NL) + NL +
      "Flags:" + NL +
      "\t* " + flagsList.map(_.getDescription).mkString(NL + "\t* ") + NL + NL +
      metadataRoot.getInfo
  }
}

object CLRSection extends App {
  val cliHeaderSpec = "cliheaderspec"
  val logger = LogManager.getLogger(CLRSection.getClass.getName)

  val testfile = new File("portextestfiles/testfiles/CryptoTester.exe")
  val pedata = PELoader.loadPE(testfile)
  //println(new ReportCreator(pedata).headerReports())
  new SectionLoader(testfile).loadCLRSection()

  def apply(mmbytes: MemoryMappedPE, offset: Long, virtualAddress: Long, data: PEData): CLRSection = {
    // load CLI Header
    val cliHeaderSize = 0x48 //always this value acc. to specification
    val clibytes = mmbytes.slice(virtualAddress, virtualAddress + cliHeaderSize)
    val format = new SpecificationFormat(0, 1, 2, 3)
    val cliHeader = IOUtil.readHeaderEntries(classOf[CLIHeaderKey],
      format, cliHeaderSpec, clibytes, offset).asScala.toMap

    val metadataVA = getValOrThrow(cliHeader, CLIHeaderKey.META_DATA_RVA)
    val metadataSize = getValOrThrow(cliHeader, CLIHeaderKey.META_DATA_SIZE)
    val metaRoot = MetadataRoot(mmbytes, data, metadataVA, metadataSize)
    val clr = new CLRSection(cliHeader, metaRoot, offset)
    println(clr.getInfo)
    clr
  }

  private def getValOrThrow(map: Map[CLIHeaderKey, StandardField], key: CLIHeaderKey): Long = {
    map.getOrElse(key, throw new FileFormatException("Key not found " + key)).getValue
  }

  /**
   * Creates an instance of the DebugSection for the given debug bytes.
   *
   * @param li the load information
   * @return debugsection instance
   */
  def newInstance(li: LoadInfo): CLRSection = {
    apply(li.memoryMapped, li.fileOffset, li.va, li.data)
  }


}
