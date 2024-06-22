package com.github.struppigel.tools

import com.github.struppigel.parser.{IOUtil, PEData, PhysicalLocation}
import com.github.struppigel.parser.ScalaIOUtil.nonExistingFileFor
import com.github.struppigel.parser.sections.SectionLoader
import com.github.struppigel.parser.sections.rsrc.icon.IconParser

import java.io.{File, IOException}
import java.nio.file.Paths
import scala.collection.JavaConverters._

/**
 * Dumping of several PE file structures and embedded files.
 */
class PEFileDumper(val pedata: PEData, val outFolder: File) {

  def dumpOverlay(): Boolean = {
    var success = false
    println("Dumping overlay ...")
    val overlay = new Overlay(pedata)
    if (overlay.exists()) {
      val outFile = nonExistingFileFor(Paths.get(outFolder.getAbsolutePath, "overlay").toFile)
      overlay.dumpTo(outFile)
      success = true
      println("Overlay successfully dumped to " + outFile.getAbsolutePath)
    } else {
      println("No overlay found")
    }
    success
  }

  def dumpResources(): Unit = {
    println("Dumping resources ...")
    val rsrc = new SectionLoader(pedata).maybeLoadResourceSection()
    if (rsrc.isPresent) {
      val resources = rsrc.get().getResources().asScala
      var nr = 0
      for (r <- resources) {
        nr += 1
        val loc = adjustLocation(r.rawBytesLocation)
        val outFile = nonExistingFileFor(Paths.get(outFolder.getAbsolutePath, nr + "." + r.getType + ".resource").toFile)
        println("Writing resource to " + outFile.getAbsolutePath)
        IOUtil.dumpLocationToFile(loc, pedata.getFile, outFile)
      }
    } else {
      println("No resources found.")
    }
  }

  def dumpPEFiles(): Unit = {
    //println("Searching for embedded PE files ...")
    
  }

  def dumpSections(): Unit = {
    println("Dumping sections ...")
    val secTable = pedata.getSectionTable
    val lowAlign = pedata.getOptionalHeader.isLowAlignmentMode
    val nrOfSections = secTable.getNumberOfSections
    for(nr <- 1 to nrOfSections) {
      val header = secTable.getSectionHeader(nr)
      val from = header.getAlignedPointerToRaw(lowAlign)
      val size = header.getAlignedSizeOfRaw(lowAlign)
      val loc = adjustLocation(new PhysicalLocation(from, size))
      val outFile = nonExistingFileFor(Paths.get(outFolder.getAbsolutePath, nr + header.getName + ".section").toFile)
      println("Writing section to " + outFile.getAbsolutePath)
      IOUtil.dumpLocationToFile(loc, pedata.getFile, outFile)
    }
  }

  def dumpIcons(): Unit = {
    println("Extracting icons ...")
    val grpIcoResources = IconParser.extractGroupIcons(pedata.getFile).asScala
    var nr = 0
    for (grpIconResource <- grpIcoResources) {
      val icoFile = grpIconResource.toIcoFile()
      while (Paths.get(outFolder.getAbsolutePath, nr + ".ico").toFile.exists()) {
        nr += 1
      }
      val dest = Paths.get(outFolder.getAbsolutePath, nr + ".ico").toFile
      icoFile.saveTo(dest)
      println("file " + dest.getName() + " written")
    }
    if(grpIcoResources.isEmpty) println("No icons found.")
  }
  
  private def adjustLocation(loc: PhysicalLocation): PhysicalLocation = {
    val maxLoc = pedata.getFile.length()
    val from = {
      if(loc.from < 0) 0 else 
        if (loc.from > maxLoc) maxLoc else 
          loc.from
    }
    val size = {
      if(loc.size + loc.from < 0) 0 else 
        if (loc.size + loc.from > maxLoc) maxLoc - from else 
          loc.size
    }
    new PhysicalLocation(from, size)
  }

}