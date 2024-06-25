package com.github.struppigel.tools.anomalies

import com.github.struppigel.parser.IOUtil._
import com.github.struppigel.parser.sections.SectionLoader
import com.github.struppigel.parser.sections.rsrc.{Name, Resource, ResourceDirectoryEntry, ResourceSection}
import com.github.struppigel.parser.{IOUtil, Location, PEData, ScalaIOUtil}
import com.github.struppigel.tools.sigscanner.{FileTypeScanner, SignatureScanner}

import java.io.RandomAccessFile
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

trait ResourceSectionScanning extends AnomalyScanner {
  abstract override def scanReport(): String =
    "Applied Resource Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val maybeRsrc = new SectionLoader(data).maybeLoadResourceSection()
    if (maybeRsrc.isPresent()) {
      val rsrc = maybeRsrc.get
      val anomalyList = ListBuffer[Anomaly]()
      anomalyList ++= checkFractionatedResources(rsrc)
      anomalyList ++= checkResourceLoop(rsrc)
      anomalyList ++= checkResourceNames(rsrc)
      anomalyList ++= checkInvalidResourceLocations(rsrc, data.getFile.length())
      anomalyList ++= checkResourceFileTypes(rsrc)
      anomalyList ++= checkResourceContents(rsrc, data)
      super.scan ::: anomalyList.toList
    } else super.scan ::: Nil
  }

  private def checkInvalidResourceLocations(rsrc : ResourceSection, filesize : Long): List[Anomaly] = {
    val resources = rsrc.getResources.asScala
    val invalidRes = resources.filter { res =>
      val start = res.rawBytesLocation.from
      val size = res.rawBytesLocation.size
      val end = start + size
      (start <= 0 || size <= 0 || end >= filesize)
    }
    invalidRes.map(res => new ResourceAnomaly(res,
      "Invalid resource location for resource at offset " + ScalaIOUtil.hex(res.rawBytesLocation.from) +
        " with size " + ScalaIOUtil.hex(res.rawBytesLocation.size),
      AnomalySubType.RESOURCE_LOCATION_INVALID)).toList
  }

  private def checkResourceContents(rsrc: ResourceSection, pedata : PEData): List[Anomaly] = {
    val resources = rsrc.getResources().asScala
    val anomalyList = ListBuffer[Anomaly]()

    // TODO this scans the signatures again (if the preconditions are true), you might want to avoid that
    def peHasSignature(sigSubstring : String): Boolean =
      SignatureScanner.newInstance()
        ._scanAll(pedata.getFile, epOnly = false)
          .exists(sig => sig._1.name.toLowerCase() contains sigSubstring.toLowerCase())

    def isPattern(bytesPattern: List[Byte], res : Resource): Boolean = {
      val bytes = IOUtil.loadBytesSafely(res.rawBytesLocation.from, res.rawBytesLocation.size.toInt,
        new RandomAccessFile(data.getFile, "r"))
      bytes sameElements bytesPattern
    }

    val filteredResource = resources.filter(res =>
      res.rawBytesLocation.size == 6 &&
        isPattern(List(1,1,0,0,0,0),res) && peHasSignature("PureBasic")
    )
    if( filteredResource.nonEmpty ) {
      val name = filteredResource.head.getName()
      val offset = filteredResource.head.rawBytesLocation
      val description = s"Signature is PureBasic and Resource {$name} at {$offset} has bytes 0x01 0x01 0x00 0x00 0x00 0x00"
      anomalyList += ResourceAnomaly(filteredResource.head, description, AnomalySubType.SCRIPT_TO_EXE_WRAPPED_RE_HINT)
    }
    anomalyList.toList
  }

  private def checkResourceNames(rsrc: ResourceSection): List[Anomaly] = {

    val resourceNameReHints = Map(">AUTOHOTKEY SCRIPT<" -> AnomalySubType.AHK_RE_HINT, "SCRIPT" -> AnomalySubType.AUTOIT_RE_HINT)

    val anomalyList = ListBuffer[Anomaly]()
    val resources = rsrc.getResources.asScala    
    for (resource <- resources) {
      for ((lvl, id) <- resource.levelIDs) {
        id match {
          case Name(_, name) =>
            val max = ResourceDirectoryEntry.maxNameLength
            val offset = resource.rawBytesLocation.from
            if (name.length >= max) {
              val description = s"Resource name in resource ${name} ${ScalaIOUtil.hex(offset)} at level ${lvl} has maximum length (${max})";
              anomalyList += ResourceAnomaly(resource, description, AnomalySubType.RESOURCE_NAME)
            }
            if (resourceNameReHints isDefinedAt name) {
              val description = s"Resource named ${name} in resource ${ScalaIOUtil.hex(offset)}"
              anomalyList += ResourceAnomaly(resource, description, resourceNameReHints(name))
            }
          case _ => //nothing
        }
      }
    }
    anomalyList.toList
  }

  private def checkResourceFileTypes(rsrc: ResourceSection): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val resources = rsrc.getResources.asScala
    for (resource <- resources) {
      val offset = resource.rawBytesLocation.from
      val fileTypes = FileTypeScanner(data.getFile)._scanAt(offset)
      val archiveResourceSigs = fileTypes filter (_._1.name.toLowerCase() contains "archive")
      val resourceIsArchive = archiveResourceSigs.nonEmpty
      val executableResourceSigs = fileTypes filter (_._1.name.toLowerCase() contains "executable")
      val resourceIsExecutable = executableResourceSigs.nonEmpty
      if(resourceIsArchive) {
        val anySigName = archiveResourceSigs.head._1.name
        val description = s"Resource named ${resource.getName()} in resource ${ScalaIOUtil.hex(offset)} is an archive (${anySigName})"
        anomalyList += ResourceAnomaly(resource, description, AnomalySubType.ARCHIVE_RE_HINT)
      }
      if(resourceIsExecutable) {
        val anySigName = executableResourceSigs.head._1.name
        val description = s"Resource named ${resource.getName()} in resource ${ScalaIOUtil.hex(offset)} is an executable (${anySigName})"
        anomalyList += ResourceAnomaly(resource, description, AnomalySubType.EMBEDDED_EXE_RE_HINT)
      }
    }
    anomalyList.toList
  }

  private def checkResourceLoop(rsrc: ResourceSection): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    if (rsrc.hasLoop) {
      val description = "Detected loop in resource tree!"
      //TODO specify exact location of loop?
      val locs = rsrc.getPhysicalLocations.asScala.toList
      anomalyList += StructureAnomaly(PEStructureKey.RESOURCE_SECTION,
        description, AnomalySubType.RESOURCE_LOOP, locs)
    }
    anomalyList.toList
  }

  private def checkFractionatedResources(rsrc: ResourceSection): List[Anomaly] = {
    val locs = rsrc.getPhysicalLocations.asScala
    val anomalyList = ListBuffer[Anomaly]()
    val loader = new SectionLoader(data)
    val rsrcHeader = loader.maybeGetSectionHeaderByOffset(rsrc.getOffset())
    if (rsrcHeader.isPresent) {

      def isWithinEData(loc: Location): Boolean = {
        val start = rsrcHeader.get().getAlignedPointerToRaw(data.getOptionalHeader.isLowAlignmentMode)
        val end = start + loader.getReadSize(rsrcHeader.get)
        val locEnd = loc.from + loc.size
        //ignores falty locations (indicated by -1 or larger than file size)
        //FIXME find the cause of -1 entries!
        (loc.from >= data.getFile.length) || (loc.from == -1) || (loc.from >= start && locEnd <= end)
      }
      val fractions = locs.filter(!isWithinEData(_)).toList
      if (!fractions.isEmpty) {
        val description = "Resources are fractionated!"
        anomalyList += StructureAnomaly(PEStructureKey.RESOURCE_SECTION, description,
          AnomalySubType.FRACTIONATED_DATADIR, fractions)

      }
    }
    anomalyList.toList
  }
}