/**
 * *****************************************************************************
 * Copyright 2014 Karsten Hahn
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
package com.github.katjahahn.tools

import com.github.katjahahn.parser.IOUtil.NL
import com.github.katjahahn.parser.coffheader.COFFHeaderKey
import com.github.katjahahn.parser.optheader.{StandardFieldEntryKey, WindowsEntryKey}
import com.github.katjahahn.parser.sections.SectionHeaderKey._
import com.github.katjahahn.parser.sections.clr.CLIHeaderKey.FLAGS
import com.github.katjahahn.parser.sections.clr._
import com.github.katjahahn.parser.sections.debug.DebugType
import com.github.katjahahn.parser.sections.rsrc.Resource
import com.github.katjahahn.parser.sections.rsrc.version.VersionInfo
import com.github.katjahahn.parser.sections.{SectionCharacteristic, SectionHeader, SectionLoader}
import com.github.katjahahn.parser._
import com.github.katjahahn.tools.ReportCreator.{pad, title}
import com.github.katjahahn.tools.anomalies.{Anomaly, PEAnomalyScanner}
import com.github.katjahahn.tools.sigscanner.{FileTypeScanner, Jar2ExeScanner, SignatureScanner}

import java.io.{File, RandomAccessFile}
import java.security.MessageDigest
import scala.collection.JavaConverters._

/**
 * Utility for easy creation of PE file reports.
 *
 * @author Karsten Hahn
 */
class ReportCreator(private val data: PEData) {

  /**
   * Maximum number of sections displayed in one table
   */
  val maxSec = 4

  val reportTitle : String = title("Report For " + data.getFile.getName) + NL +
    s"file size ${hexString(data.getFile.length)}" + NL +
    s"full path ${data.getFile.getAbsolutePath}" + NL + NL

  private var checksumDescription = ""

  private var showAll = false

  /**
   * If all is set to true, every report will be created, even unstable and
   * time-consuming ones. The standard value is false.
   *
   * @param all set to true if all reports shall be created
   */
  def setShowAll(all: Boolean): Unit = { showAll = all }

  /**
   * Generate repors for Section Table, MSDOS header, COFF File Header and Optional Header
   * @return description for the headers
   */
  def headerReports(): String = secTableReport + msdosHeaderReport + richHeaderReport +
    coffHeaderReport + optHeaderReport

  /**
   * Generate report for delay imports, exports, resources, debug.
   * If showAll is true, generate also bound imports and relocactions report.
   * @return reports for special sections
   */
  def specialSectionReports(): String = importsReport +
    { if (showAll) boundImportsReport() else "" } +
    delayImportsReport + exportsReport + resourcesReport + clrReport + debugReport +
    { if (showAll) relocReport() else "" }

  /**
   * Generate reports for overlay, anomalies, PEID signatures, file and import hashes.
   * If showAll is true, also generate report for Jar2Exe scan and file scoring
   * @return additional reports
   */
  def additionalReports(): String = overlayReport +
    anomalyReport + peidReport + hashReport +
    { if (showAll) jar2ExeReport + maldetReport else "" }

  /**
   * Prints a report to stdout.
   */
  def printReport(): Unit = {
    print(reportTitle)
    print(headerReports())
    print(specialSectionReports())
    print(additionalReports())
  }

  /**
   * Generate report for file and import hashes.
   * @return description of file hashes and imphash
   */
  def hashReport(): String = {
    val hasher = new Hasher(data)
    val buf = new StringBuffer()
    val sha256 = MessageDigest.getInstance("SHA-256")
    val md5 = MessageDigest.getInstance("MD5")
    buf.append(title("Hashes") + NL)
    buf.append("MD5:     " + hash(hasher.fileHash(md5)) + NL)
    buf.append("SHA256:  " + hash(hasher.fileHash(sha256)) + NL)
    buf.append("ImpHash: " + ImpHash.createString(data.getFile) + NL)
    val maybeRich = hasher.maybeRichHash()
    if (maybeRich.isPresent) {
      buf.append("Rich:    " + hash(maybeRich.get()) + NL)
    }
    val maybePVRich = hasher.maybeRichPVHash()
    if (maybePVRich.isPresent) {
      buf.append("RichPV:  " + hash(maybePVRich.get()) + NL)
    }
    buf.append(NL)
    val colWidth = 10
    val shaWidth = 64
    val padLength = "1. .rdata    ".length
    val tableHeader = pad("Section", padLength, " ") + pad("Type", colWidth, " ") + pad("Hash Value", shaWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    val table = data.getSectionTable
    for (number <- 1 to table.getNumberOfSections) {
      val header = table.getSectionHeader(number)
      val secName = filteredString(header.getName)
      buf.append(pad(number + ". " + secName, padLength, " ") + pad("MD5", colWidth, " ") +
        pad(hash(hasher.sectionHash(number, md5)), shaWidth, " ") + NL)
      buf.append(pad("", padLength, " ") + pad("SHA256", colWidth, " ") +
        pad(hash(hasher.sectionHash(number, sha256)), shaWidth, " ") + NL)
    }
    buf.append(NL)
    buf.toString
  }

  private def hash(array: Array[Byte]): String = ByteArrayUtil.byteToHex(array, "")

  /**
   * Generate report for the .NET CLI Header
   * @return .NET CLI Header description
   */
  def cliHeaderReport(): String = {
    val loader = new SectionLoader(data)
    val maybeCLR = loader.maybeLoadCLRSection()
    val buf = new StringBuffer()
    if(maybeCLR.isPresent && !maybeCLR.get().isEmpty) {
      val clr = maybeCLR.get()
      val entries = clr.cliHeader.values

      val colWidth = 15
      val padLength = "export address table jumps ".length
      buf.append(title(".NET CLI Header") + NL)

      // construct flags string
      val flagsField = clr.cliHeader.get(FLAGS)
      val flagsVal = {
        if (flagsField.isDefined) flagsField.get.getValue else 0
      }
      val flagsList = ComImageFlag.getAllFor(flagsVal).asScala
      buf.append("Flags:" + NL + "\t* " + flagsList.map(_.getDescription).mkString(NL + "\t* ") + NL + NL)

      val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
      buf.append(tableHeader + NL)
      buf.append(pad("", tableHeader.length, "-") + NL)
      for (entry <- entries) {
        buf.append(pad(entry.getDescription, padLength, " ") + pad(hexString(entry.getValue), colWidth, " ") +
          pad(hexString(entry.getOffset), colWidth, " ") + NL)
      }
    }
    buf.toString + NL
  }

  /**
   * Generate report for the .NET metadata root structure
   * @return .NET metadata root structure description
   */
  def metadataRootReport(): String = {
    val loader = new SectionLoader(data)
    val maybeCLR = loader.maybeLoadCLRSection()
    val buf = new StringBuffer()
    if(maybeCLR.isPresent && !maybeCLR.get().isEmpty) {
      val metadataRoot = maybeCLR.get().metadataRoot
      val entries = metadataRoot.metadataEntries.values
      val colWidth = 15
      val title = ".NET Metadata Root"
      buf.append(standardFieldsReport(title, colWidth, colWidth, entries))

      val streamTblHeader = pad("Stream name", colWidth, " ") + pad("size", colWidth, " ") + pad("offset to BSJB", colWidth + 2, " ") + pad("actual offset", colWidth, " ")
      buf.append(NL + NL + streamTblHeader + NL)
      buf.append(pad("", streamTblHeader.length, "-") + NL)
      val bsjb = metadataRoot.getBSJBOffset()
      for (streamHeader <- metadataRoot.streamHeaders){
        buf.append(pad(streamHeader.name, colWidth, " ") +
          pad(hexString(streamHeader.size), colWidth, " ") +
          pad(hexString(streamHeader.offset), colWidth + 2, " ") +
          pad(hexString(streamHeader.offset + bsjb), colWidth, " ") + NL)
      }
    }
    buf.toString + NL
  }

  def stringsHeapReport(): String = {
    val loader = new SectionLoader(data)
    val maybeCLR = loader.maybeLoadCLRSection()
    val buf = new StringBuffer()
    if(maybeCLR.isPresent && !maybeCLR.get().isEmpty) {
      val metadataRoot = maybeCLR.get().metadataRoot
      val maybeHeap = metadataRoot.maybeGetStringsHeap
      if(!maybeHeap.isPresent) {
        return ""
      }
      val heap = maybeHeap.get()
      buf.append(title("#Strings Heap"))
      val filteredStrings = heap.getArray().filter(filteredString(_).length > 0)
      // one less because first string is always empty
      val unreadableCount = heap.getArray().length - filteredStrings.length - 1
      buf.append("Human-unreadable strings: " + unreadableCount + NL + NL)
      filteredStrings.foreach(s => buf.append(s + NL))
      buf.append(NL)
    }
    buf.toString()
  }

  /**
   * Connects the resolution scope to the entry it is pointing to.
   * Instead of row number and table name, the description contains the name of the entry
   * @param e
   * @param optStream
   * @return
   */
  private def getStringForResolutionScope(e: CLRTableEntry, optStream : OptimizedStream): String = {
    val resolutionscope : CLRCodedIndexField = e.get(CLRTableKey.TYPEREF_RESOLUTION_SCOPE).get.asInstanceOf[CLRCodedIndexField]
    val tbl = resolutionscope.getReferencedTable()

    def getDescriptionForType(t: CLRTableType, k : CLRTableKey, desc : String): String = {
      val o = optStream.getCLRTable(t).get
      val rowNr = resolutionscope.getReferencedRow()
      if(o.getEntries.size >= rowNr && rowNr > 0) {
        val clrTblRow = o.getEntries()(rowNr - 1)
        val clrField = clrTblRow.get(k).get
        desc + " " + clrField.getDescription
      }
      else s"<invalid index into ${t}>"
    }
    tbl match {
      case CLRTableType.ASSEMBLYREF => getDescriptionForType(CLRTableType.ASSEMBLYREF, CLRTableKey.ASSEMBLYREF_NAME, "assemblyref")
      case CLRTableType.MODULE => getDescriptionForType(CLRTableType.MODULE, CLRTableKey.MODULE_NAME, "module")
      case CLRTableType.MODULEREF => getDescriptionForType(CLRTableType.MODULEREF, CLRTableKey.MODULEREF_NAME, "moduleref")
      case CLRTableType.TYPEREF => getDescriptionForType(CLRTableType.TYPEREF, CLRTableKey.TYPEREF_TYPE_NAME, "typeref")
      case _ => "<unknown resolution scope>"
    }
  }

  /**
   * Summary of imported/referenced types of .NET assemblies.
   * Resolves the resolution scope as short textual representation of the entry it points to.
   * Sorting of types by resolution scope.
   * @param optStream
   * @return
   */
  def typeRefTableReport(optStream : OptimizedStream): String = {
    title("TypeRef") + (if(optStream.getCLRTable(CLRTableType.TYPEREF).isDefined) {
      val typerefs = optStream.getCLRTable(CLRTableType.TYPEREF).get
      val sortedTypeRefs = typerefs.getEntries().map(e => (getStringForResolutionScope(e, optStream), e)).sortBy(_._1)

      def entryDescription(e : CLRTableEntry): String = {
        val namespace = e.get(CLRTableKey.TYPEREF_TYPE_NAMESPACE).get
        val typename = e.get(CLRTableKey.TYPEREF_TYPE_NAME).get
        if (namespace.getValue == 0) { typename.getDescription }
        else namespace.getDescription + "." + typename.getDescription
      }
      var currScope = ""
      val descriptions = for( (scope, e) <- sortedTypeRefs) yield {
        val preStr = if(scope != currScope) {currScope = scope; "From " +  scope + ":" + NL} else ""
        preStr + "\t* " + entryDescription(e)
      }
      descriptions.mkString(NL)
    }) + NL
  }

  /**
   * Summary of #~ contents
   * @return
   */
  def optimizedNetStreamReport(): String = {
    val loader = new SectionLoader(data)
    val maybeCLR = loader.maybeLoadCLRSection()
    if(maybeCLR.isPresent && !maybeCLR.get().isEmpty) {
      val metadataRoot = maybeCLR.get().metadataRoot
      val maybeOptStream = metadataRoot.maybeGetOptimizedStream
      if(maybeOptStream.isPresent){
        val optStream = maybeOptStream.get
        val entries = optStream.entries.values
        val padLength = "minor version of table schemata: ".length
        val additions = NL + "Blob heap size: " + optStream.getBlobHeapSize + " bytes" + NL +
          "GUID heap size: " + optStream.getGUIDHeapSize + " bytes" + NL +
          "String heap size: " + optStream.getStringHeapSize + " bytes" + NL + NL
          //"Tables and rows: " + NL + optStream.getTableNamesToSizesMap().mkString(NL) + NL + NL

        def compileInfo(typeList : List[CLRTableType]): String =
          if (typeList.isEmpty) "" else {
            val tbl = optStream.getCLRTable(typeList.head)
            if(tbl.isDefined) tbl.get.toString + NL + NL + compileInfo(typeList.tail)
            else compileInfo(typeList.tail)
          }

        // Tables to display
        val clrTables = compileInfo(
          List( CLRTableType.MODULE,
                CLRTableType.ASSEMBLY,
                CLRTableType.FILE,
                CLRTableType.MANIFESTRESOURCE,
                CLRTableType.MODULEREF,
                //CLRTableType.TYPEREF,
                CLRTableType.EXPORTEDTYPE,
          )) + typeRefTableReport(optStream) + NL

        //val clrTables = compileInfo(List(CLRTableType.CUSTOMATTRIBUTE))
        return standardFieldsReport("#~ Stream", 15, padLength, entries) + additions + clrTables
      }
    }
    ""
  }

  def standardFieldsReport(titleStr: String, colWidth : Int, padLength : Int, entries : Iterable[StandardField]) : String = {
    val buf = new StringBuffer()
    buf.append(title(titleStr) + NL)

    val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    for (entry <- entries) {
      buf.append(pad(entry.getDescription, padLength, " ") +
        pad(hexString(entry.getValue), colWidth, " ") +
        pad(hexString(entry.getOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  /**
   * Generate report for the .NET CLR structures
   * @return .NET structures description
   */
  def clrReport(): String = {
    cliHeaderReport() + metadataRootReport() + optimizedNetStreamReport()
  }

  /**
   * Generate report for the debug structure
   * @return debug description
   */
  def debugReport(): String = {
    val loader = new SectionLoader(data)
    val maybeDebug = loader.maybeLoadDebugSection()
    if (maybeDebug.isPresent && !maybeDebug.get.isEmpty) {
      val debugSec = maybeDebug.get
      val debugEntries = debugSec.getEntries().asScala.toList
      val buf = new StringBuffer()
      var entryNum = 0
      for(debug <- debugEntries) {
        entryNum += 1
        val colWidth = 17
        val padLength = "Address of Raw Data ".length
        buf.append(title("Debug Directory Entry " + entryNum)  + NL)
        val timestampString = if(debugSec.isReproBuild()) "invalid - reproducibility build" else debug.getTimeDateStamp
        buf.append("Time Date Stamp: " + timestampString + NL)
        buf.append("Type: " + debug.getTypeDescription + NL + NL)
        val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
        buf.append(tableHeader + NL)
        buf.append(pad("", tableHeader.length, "-") + NL)
        val entries = debug.getDirectoryTable().values().asScala.toList.sortBy(e => e.getOffset)
        for (entry <- entries) {
          buf.append(pad(entry.getDescription, padLength, " ") + pad(hexString(entry.getValue), colWidth, " ") +
            pad(hexString(entry.getOffset), colWidth, " ") + NL)
        }
        if (debug.getDebugType() == DebugType.CODEVIEW) {
          try {
            buf.append(debug.getCodeView().getInfo())
          } catch {
            case _: IllegalStateException =>
              buf.append("-invalid codeview structure-")
          }
        }
        if (debug.getDebugType() == DebugType.REPRO) {
          buf.append(debug.getRepro().getInfo())
        }
        buf.append(NL)
      }
      buf.toString
    } else ""
  }

  /**
   * Generate relocations report
   * @return relocations description
   */
  def relocReport(): String = {
    val loader = new SectionLoader(data)
    val maybeReloc = loader.maybeLoadRelocSection()
    if (maybeReloc.isPresent && !maybeReloc.get.isEmpty) {
      val reloc = maybeReloc.get
      val buf = new StringBuffer()
      buf.append(title("Relocations") + NL)
      buf.append(reloc.getInfo + NL) //TODO make table
      buf.toString
    } else ""
  }

  /**
   * Generate report for the PE imports
   * @return description of PE imports
   */
  def importsReport(): String = {
    val loader = new SectionLoader(data)
    val maybeImports = loader.maybeLoadImportSection()
    if (maybeImports.isPresent && !maybeImports.get.isEmpty) {
      val idata = maybeImports.get
      val buf = new StringBuffer()
      buf.append(title("Imports") + NL)
      val imports = idata.getImports.asScala
      for (importDll <- imports) {
        buf.append(importDll + NL)
      }
      buf.toString
    } else ""
  }

  /**
   * Generate report for bounds imports
   * @return description of bounds imports
   */
  def boundImportsReport(): String = {
    val loader = new SectionLoader(data)
    val maybeImports = loader.maybeLoadBoundImportSection()
    if (maybeImports.isPresent && !maybeImports.get.isEmpty) {
      val boundImports = maybeImports.get
      val buf = new StringBuffer()
      buf.append(title("Bound Imports") + NL)
      val imports = boundImports.getImports().asScala
      for (importDll <- imports) {
        buf.append(importDll + NL)
      }
      buf.toString
    } else ""
  }

  /**
   * Generate report for delay load imports
   * @return description of delay load imports
   */
  def delayImportsReport(): String = {
    val loader = new SectionLoader(data)
    val maybeImports = loader.maybeLoadDelayLoadSection()
    if (maybeImports.isPresent && !maybeImports.get.isEmpty) {
      val delayLoad = maybeImports.get
      val buf = new StringBuffer()
      buf.append(title("Delay-Load Imports") + NL)
      val imports = delayLoad.getImports().asScala
      for (importDll <- imports) {
        buf.append(importDll + NL)
      }
      buf.toString
    } else ""
  }

  /**
   * Generate report for exported functions
   * @return description of exports
   */
  def exportsReport(): String = {
    val loader = new SectionLoader(data)
    val maybeExports = loader.maybeLoadExportSection()
    if (maybeExports.isPresent && !maybeExports.get.isEmpty) {
      val edata = maybeExports.get
      val buf = new StringBuffer()
      buf.append(title("Exports") + NL)
      val exports = edata.getExportEntries().asScala
      for (export <- exports) {
        buf.append(export + NL)
      }
      buf.toString + NL
    } else ""
  }

  /**
   * Generate report for PE resources
   * @return description of resources
   */
  def resourcesReport(): String = {
    val loader = new SectionLoader(data)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent && !maybeRSRC.get.isEmpty) {
      val rsrc = maybeRSRC.get
      val buf = new StringBuffer()
      buf.append(title("Resources") + NL)
      val resources = rsrc.getResources().asScala
      for (resource <- resources) {
        val offset = resource.rawBytesLocation.from
        val fileTypes = FileTypeScanner(data.getFile)._scanAt(offset)
        val longTypes = fileTypes.
          map(t => t._1.name + " (" + t._1.bytesMatched + " bytes)")
        buf.append(resource)
        if (longTypes.nonEmpty) {
          buf.append(", signatures: " + longTypes.mkString(", "))
        }
        buf.append(NL)
      }
      buf.append(NL)
      buf.append(manifestReport(resources.toList))
      buf.append(versionReport(resources.toList))
      buf.toString
    } else ""
  }

  private def manifestReport(resources: List[Resource]): String = {

    val MAX_MANIFEST_SIZE = 0x2000

    def bytesToUTF8(bytes: Array[Byte]): String = new java.lang.String(bytes, "UTF8").trim()

    def readBytes(resource: Resource): Array[Byte] =
      IOUtil.loadBytesSafely(resource.rawBytesLocation.from, resource.rawBytesLocation.size.toInt,
        new RandomAccessFile(data.getFile, "r"))

    def getResourceString(resource: Resource): String = bytesToUTF8(readBytes(resource))

    def isLegitManifest(resource: Resource): Boolean = {
      val offset = resource.rawBytesLocation.from
      val size = resource.rawBytesLocation.size.toInt
      offset > 0 && size > 0 && size < MAX_MANIFEST_SIZE
    }

    val buf = new StringBuffer()
    val manifestResources = resources.filter { _.getType == "RT_MANIFEST" }
    manifestResources.foreach { resource =>
      if (isLegitManifest(resource)) {
        buf.append(title("Manifest"))
        val versionInfo = getResourceString(resource)
        buf.append(NL + versionInfo + NL)
      } else {
        buf.append(title("Manifest"))
        buf.append(NL + "-broken manifest-" + NL)
      }
    }
    buf.toString + NL
  }

  def manifestReport(): String = {
    val loader = new SectionLoader(data)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent && !maybeRSRC.get.isEmpty) {
      val rsrc = maybeRSRC.get
      val resources = rsrc.getResources().asScala
      manifestReport(resources.toList)
    } else ""
  }

  def versionReport(): String = {
    val loader = new SectionLoader(data)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent && !maybeRSRC.get.isEmpty) {
      val rsrc = maybeRSRC.get
      val resources = rsrc.getResources().asScala
      versionReport(resources.toList)
    } else ""
  }

  private def versionReport(resources: List[Resource]): String = {
    val buf = new StringBuffer()
    val versionResources = resources.filter { _.getType == "RT_VERSION" }
    versionResources.foreach { resource =>
      buf.append(title("Version Information") + NL)
      val versionInfo = VersionInfo(resource, data.getFile)
      buf.append(versionInfo.toString + NL)
    }
    buf.toString + NL
  }

  def jar2ExeReport(): String = {
    val scanner = new Jar2ExeScanner(data.getFile)
    if (scanner.scan().isEmpty) ""
    else title("Jar to EXE Wrapper Scan") + NL + scanner.createReport + NL
  }

  def maldetReport(): String = {
    val scoring = FileScoring.newInstance(data.getFile)
    val report1 = title("File Scoring") + NL + "Malware probability: " +
      (scoring.malwareProbability * 100.0) + " %"
    val report2 = "File Score: " + scoring.fileScore() + NL + NL +
      "Score based on: " + NL +
      scoring._scoreParts().map(m => m._1 + ": " + m._2).mkString(NL)
    report1 + NL + report2 + NL + NL
  }

  def overlayReport(): String = {
    val overlay = new Overlay(data.getFile)
    if (overlay.exists) {
      val chi = ChiSquared.calculate(data.getFile, overlay.getOffset, overlay.getSize)
      val entropy = ShannonEntropy.entropy(data.getFile, overlay.getOffset, overlay.getSize)
      val overlayOffset = overlay.getOffset
      val overlaySigs = SignatureScanner._loadOverlaySigs()
      val sigresults = new SignatureScanner(overlaySigs).scanAtToString(data.getFile, overlayOffset)
      val signatures = NL + { if (sigresults.isEmpty) "none" else sigresults.asScala.mkString(NL) }
      title("Overlay") + NL + "Offset: " +
        hexString(overlayOffset) + NL + "Size: " +
        hexString(overlay.getSize) + NL + ("Chi squared: %1.2f" format chi) + NL +
        ("Entropy: %1.2f" format entropy) + NL +
        "Signatures: " + signatures + NL + NL
    } else ""
  }

  def peidReport(): String = {
    val signatures = SignatureScanner.newInstance().scanAllToString(data.getFile)
    if (signatures.isEmpty) ""
    else title("PEID Signatures") + NL + signatures.asScala.mkString(NL) + NL + NL
  }

  def anomalyReport(): String = {
    val anomalies = PEAnomalyScanner.newInstance(data).getAnomalies.asScala.toList
    val descriptions = anomaliesToDescriptions(anomalies)
    if (descriptions.isEmpty) ""
    else title("Anomalies") + NL +
      "Total anomalies: " + anomalies.size + NL + NL +
      (if (showAll && checksumDescription != "") "* " + checksumDescription + NL else "") +
      ("* " + descriptions.mkString(NL + "* ")) + NL + NL
  }

  /**
   * Retrieve descriptions of anomaly list, consolidate anomaly subtypes that occur very often.
   *
   * @param anomalies
   * @return
   */
  private def anomaliesToDescriptions(anomalies : List[Anomaly]): List[String] = {
    val consolidationLimit = 20
    val subtypeToAnomaly = anomalies.groupBy(_.subtype())
    (subtypeToAnomaly.map{ case (subtype, anoms) =>
      if(anoms.size > consolidationLimit) {
        List(anoms(0).description() + ". There are " + anoms.size + " more cases like this.")
      } else anoms.map(_.description())
    } ).flatten.toList
  }

  def richHeaderReport(): String = {
    val richOptional = data.maybeGetRichHeader
    if (richOptional.isPresent) {
      val rich = richOptional.get()
      val entries = rich.getRichEntries().asScala
      val padLength = "VS2022 v17.1.0 pre 1.0 build 30818  ".length
      val padLength2 = "Utc1900_POGO_O_CPP  ".length
      val buf = new StringBuffer()
      buf.append(title("Rich Header") + NL)
      val xorKey = rich.getXORKey()
      val xorStr = "0x" + xorKey.map("%02X" format _).mkString
      val checksumStr = if(rich.isValidChecksum()) "checksum is valid!" else "checksum is invalid!"
      buf.append("XOR key: " + xorStr + NL)
      buf.append(checksumStr + NL + NL)
      val knownFormats = rich.getKnownFormats().asScala
      if (knownFormats.size > 0) {
        buf.append("XOR key known to be emitted by: " + knownFormats.mkString(", "))
      }
      val tableHeader = pad("object", padLength2, " ") + pad("product", padLength, " ") + pad("file count", 10, " ")
      buf.append(tableHeader + NL)
      buf.append(pad("", tableHeader.length, "-") + NL)
      for (entry <- entries) {
        buf.append(pad(entry.getProductIdStr, padLength2, " ") + pad(entry.getBuildStr, padLength, " ") +
          pad(entry.count.toString, 10, " ") + NL)
      }
      buf.toString + NL
    }
    else ""
  }

  def msdosHeaderReport(): String = {
    val msdos = data.getMSDOSHeader
    val entries = msdos.getHeaderEntries.asScala.sortBy(e => e.getOffset)
    val buf = new StringBuffer()
    val colWidth = 15
    val padLength = "maximum number of paragraphs allocated ".length
    buf.append(title("MSDOS Header") + NL)
    val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    for (entry <- entries) {
      buf.append(pad(entry.getDescription, padLength, " ") + pad(hexString(entry.getValue), colWidth, " ") +
        pad(hexString(entry.getOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  def coffHeaderReport(): String = {
    val coff = data.getCOFFFileHeader
    val buf = new StringBuffer()
    val colWidth = 15
    val padLength = "pointer to symbol table (deprecated) ".length
    buf.append(title("COFF File Header") + NL)
    val padLength1 = "time date stamp  ".length
    val timestampString = if(data.isReproBuild()) "invalid - reproducibility build" else coff.getTimeDate.toLocaleString
    buf.append(pad("time date stamp", padLength1, " ") +
      pad(timestampString, colWidth, " ") + NL)
    buf.append(pad("machine type", padLength1, " ") +
      pad(coff.getMachineType.getDescription, colWidth, " ") + NL)
    buf.append(pad("characteristics", padLength1, " ") + "* " +
      coff.getCharacteristics.asScala.map(_.getDescription).mkString(NL + pad("", padLength1, " ") + "* "))

    buf.append(NL + NL)
    val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    val entries = (for (key <- COFFHeaderKey.values) yield coff.getField(key)).sortBy(e => e.getOffset)
    for (entry <- entries) {
      val description = entry.getDescription.replace("(deprecated for image)", "(deprecated)")
      buf.append(pad(description, padLength, " ") + pad(hexString(entry.getValue), colWidth, " ") +
        pad(hexString(entry.getOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  def optHeaderReport(): String = {
    val opt = data.getOptionalHeader
    val secLoader = new SectionLoader(data)
    val buf = new StringBuffer()
    val colWidth = 17
    val padLength = "pointer to symbol table (deprecated) ".length
    val subsystem = "subsystem:           " + opt.getSubsystem.getDescription
    val dllCharacteristics = {
      if (opt.getDllCharacteristics.isEmpty) "No DLL Characteristics"
      else "DLL Characteristics  * " +
        opt.getDllCharacteristics.asScala.map(_.getDescription).mkString(NL + "                     * ")
    }
    val entryPointDescription = {
      val entryPoint = opt.get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT)
      val maybeHeader = secLoader.maybeGetSectionHeaderByRVA(entryPoint)
      if (maybeHeader.isPresent)
        "entry point is in section " + maybeHeader.get.getNumber + " with name " + maybeHeader.get.getName
      else "entry point is not in a section"
    }

    if (showAll) checksumDescription = {
      val actualChecksum = ChecksumVerifier.computeChecksum(data)
      val headerChecksum = data.getOptionalHeader.get(WindowsEntryKey.CHECKSUM)
      if (actualChecksum == headerChecksum) "Checksum is valid!" else
        "Checksum is invalid. Actual checksum is " + hexString(actualChecksum)
    }

    val linkerversion = opt.getLinkerVersionDescription

    buf.append(title("Optional Header"))
    buf.append(NL + "Magic Number: " + opt.getMagicNumber.getDescription)
    buf.append(NL + checksumDescription)
    buf.append(NL + entryPointDescription)
    buf.append(NL + dllCharacteristics)
    buf.append(NL + subsystem)
    buf.append(NL + "Linker version:      " + linkerversion + NL)
    val standardHeader = pad("standard field", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    val windowsHeader = pad("windows field", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    val tableLine = pad("", standardHeader.length, "-") + NL
    val standardFields = opt.getStandardFields.values.asScala.toList.sortBy(_.getOffset)
    val windowsFields = opt.getWindowsSpecificFields.values.asScala.toList.sortBy(_.getOffset)

    for ((fields, header) <- List((standardFields, standardHeader), (windowsFields, windowsHeader))) {
      buf.append(NL + header + NL + tableLine)
      for (entry <- fields) {
        val description = entry.getDescription.replace("(reserved, must be zero)", "(reserved)").replace("(MS DOS stub, PE header, and section headers)", "")
        buf.append(pad(description, padLength, " ") + pad(hexString(entry.getValue), colWidth, " ") +
          pad(hexString(entry.getOffset), colWidth, " ") + NL)
      }
    }
    val padLengthDataDir = "delay import descriptor ".length
    val dataDirHeader = pad("data directory", padLengthDataDir, " ") + pad("rva", colWidth, " ") + pad("-> offset", colWidth, " ") + pad("size", colWidth, " ") + pad("in section", colWidth, " ") + pad("file offset", colWidth, " ")
    val dataDirs = opt.getDataDirectory.values.asScala.toList.sortBy(e => e.getTableEntryOffset)
    val dataDirTableLine = pad("", dataDirHeader.length, "-") + NL
    buf.append(NL + dataDirHeader + NL + dataDirTableLine)
    for (entry <- dataDirs) {
      val description = entry.getKey.toString
      val maybeHeader = secLoader.maybeGetSectionHeader(entry.getKey)
      val dataVA = entry.getVirtualAddress
      val dataOffset = new SectionLoader(data).maybeGetFileOffset(entry.getVirtualAddress)
      val dataOffsetStr = if (dataOffset.isPresent) hexString(dataOffset.get()) else "n.a."
      val inSection = if (maybeHeader.isPresent) maybeHeader.get.getNumber + " " + maybeHeader.get.getName else "-"
      buf.append(pad(description, padLengthDataDir, " ") + pad(hexString(dataVA), colWidth, " ") +
        pad(dataOffsetStr, colWidth, " ") + pad(hexString(entry.getDirectorySize), colWidth, " ") +
        pad(inSection, colWidth, " ") + pad(hexString(entry.getTableEntryOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  /**
   * Filters all control symbols and extended code from the given string. The
   * filtered string is returned.
   *
   * @return filtered string
   */
  //TODO duplicate of SectionTableScanning method
  private def filteredString(string: String): String = {
    val controlCode: Char => Boolean = (c: Char) => c <= 32 || c == 127
    val extendedCode: Char => Boolean = (c: Char) => c <= 32 || c > 127
    string.filterNot(controlCode).filterNot(extendedCode)
  }

  def secTableReport(): String = {
    val table = data.getSectionTable
    val lowAlign = data.getOptionalHeader.isLowAlignmentMode
    val allSections = table.getSectionHeaders.asScala
    val loader = new SectionLoader(data)
    val build = new StringBuilder()
    build.append(title("Section Table"))
    if (lowAlign){
      build.append("File is in low alignment mode!" + NL)
    }
    for (secs <- allSections.grouped(maxSec).toList) {
      val sections = secs.toList
      val tableHeader = sectionEntryLine(sections, "", (s: SectionHeader) => s.getNumber + ". " + filteredString(s.getName))
      val tableLine = pad("", tableHeader.length, "-") + NL
      build.append(tableHeader + tableLine)
      val entropy = new ShannonEntropy(data)
      val chi2 = new ChiSquared(data)
      build.append(sectionEntryLine(sections, "Entropy", (s: SectionHeader) =>
        "%1.2f" format (entropy.forSection(s.getNumber) * 8)))
      build.append(sectionEntryLine(sections, "Chi squared", (s: SectionHeader) =>
        "%1.2f" format (chi2.forSection(s.getNumber))))
      build.append(sectionEntryLine(sections, "Pointer To Raw Data",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> aligned (act. start)",
        (s: SectionHeader) => if (s.get(POINTER_TO_RAW_DATA) != s.getAlignedPointerToRaw(lowAlign))
          hexString(s.getAlignedPointerToRaw(lowAlign)) else ""))
      build.append(sectionEntryLine(sections, "Size Of Raw Data",
        (s: SectionHeader) => hexString(s.get(SIZE_OF_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> Actual Read Size",
        (s: SectionHeader) => if (s.get(SIZE_OF_RAW_DATA) != loader.getReadSize(s))
          hexString(loader.getReadSize(s)) else ""))
      build.append(sectionEntryLine(sections, "-> Physical End",
        (s: SectionHeader) => hexString(loader.getReadSize(s) + s.getAlignedPointerToRaw(lowAlign))))
      build.append(sectionEntryLine(sections, "Virtual Address",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_ADDRESS))))
      build.append(sectionEntryLine(sections, "-> aligned",
        (s: SectionHeader) => if (s.get(VIRTUAL_ADDRESS) != s.getAlignedVirtualAddress(lowAlign))
          hexString(s.getAlignedVirtualAddress(lowAlign)) else ""))
      build.append(sectionEntryLine(sections, "Virtual Size",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_SIZE))))
      build.append(sectionEntryLine(sections, "-> Actual Virtual Size", (s: SectionHeader) =>
        if (s.get(VIRTUAL_SIZE) != loader.getActualVirtSize(s))
          hexString(loader.getActualVirtSize(s)) else ""))
      build.append(sectionEntryLine(sections, "-> Virtual End",
        (s: SectionHeader) => hexString(s.getAlignedVirtualAddress(lowAlign) + loader.getActualVirtSize(s) )))
      build.append(sectionEntryLine(sections, "Pointer To Relocations",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RELOCATIONS))))
      build.append(sectionEntryLine(sections, "Number Of Relocations",
        (s: SectionHeader) => hexString(s.get(NUMBER_OF_RELOCATIONS))))
      build.append(sectionEntryLine(sections, "Pointer To Line Numbers",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_LINE_NUMBERS))))
      build.append(sectionEntryLine(sections, "Number Of Line Numbers",
        (s: SectionHeader) => hexString(s.get(NUMBER_OF_LINE_NUMBERS))))
      for (ch <- SectionCharacteristic.values) {
        build.append(sectionEntryLine(sections, ch.shortName(),
          (s: SectionHeader) => if (s.getCharacteristics.contains(ch)) "x" else ""))
      }
      build.append(NL)
    }
    build.toString
  }

  private def sectionEntryLine(sections: List[SectionHeader], name: String, conv: SectionHeader => String): String = {
    val colWidth = 15
    val padLength = "POINTER_TO_LINE_NUMBERS  ".length
    val padding = pad(name, padLength, " ")
    val sectionValues = sections.map(s => pad(conv(s), colWidth, " ")).mkString(" ")
    if (sectionValues.trim.isEmpty) "" else
      padding + sectionValues + NL
  }

  private def hexString(value: Long): String =
    "0x" + java.lang.Long.toHexString(value)
}

object ReportCreator {

  def apply(file: File): ReportCreator =
    new ReportCreator(PELoader.loadPE(file))

  def newInstance(file: File): ReportCreator =
    apply(file)

  def title(str: String, padStr : String = "*"): String = str + NL + pad("", str.length, padStr) + NL

  def pad(string: String, length: Int, padStr: String): String = {
    val padding = (for (_ <- string.length until length by padStr.length)
      yield padStr).mkString
    string + padding
  }

}