package io.github.struppigel.tools

import io.github.struppigel.parser.{IOUtil, PEData}
import io.github.struppigel.parser.ScalaIOUtil.nonExistingFileFor
import io.github.struppigel.parser.sections.SectionLoader
import io.github.struppigel.parser.PhysicalLocation
import io.github.struppigel.parser.sections.rsrc.icon.IconParser
import io.github.struppigel.parser.sections.cert.AuthenticodeSignature

import java.io.{File, IOException}
import java.nio.file.{Files, Paths}
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

  /**
   * Writes each PKCS#7 signature of the certificate table to a .p7b file and
   * each embedded certificate to a .cer file (DER). Entries of other types
   * are written as raw .bin files.
   */
  def dumpCertificates(): Unit = {
    println("Dumping certificates ...")
    val maybeTable = pedata.loadCertificateTable()
    if (!maybeTable.isPresent || maybeTable.get.isEmpty) {
      println("No certificate table found.")
      return
    }
    for (entry <- maybeTable.get.getEntries.asScala) {
      val nr = entry.getIndex
      if (entry.getSignature.isPresent) {
        val signature = entry.getSignature.get
        val p7b = nonExistingFileFor(Paths.get(outFolder.getAbsolutePath, nr + ".signature.p7b").toFile)
        writeBytes(p7b, signature.getEncoded, "signature")
        val all = signature :: allNested(signature)
        var m = 0
        for (s <- all; cert <- s.getCertificates.asScala) {
          val name = sanitize(cert.getSubjectCommonName.orElse("certificate"))
          val cer = nonExistingFileFor(Paths.get(outFolder.getAbsolutePath, nr + "." + m + "." + name + ".cer").toFile)
          writeBytes(cer, cert.getEncoded, "certificate")
          m += 1
        }
      } else if (entry.getX509Certificate.isPresent) {
        val cert = entry.getX509Certificate.get
        val name = sanitize(cert.getSubjectCommonName.orElse("certificate"))
        val cer = nonExistingFileFor(Paths.get(outFolder.getAbsolutePath, nr + ".0." + name + ".cer").toFile)
        writeBytes(cer, cert.getEncoded, "certificate")
      } else {
        val bin = nonExistingFileFor(Paths.get(outFolder.getAbsolutePath, nr + ".wincertificate.bin").toFile)
        writeBytes(bin, entry.getContent, "WIN_CERTIFICATE content")
      }
    }
  }

  private def allNested(s: AuthenticodeSignature): List[AuthenticodeSignature] =
    s.getNestedSignatures.asScala.toList.flatMap(n => n :: allNested(n))

  private def sanitize(name: String): String = {
    val cleaned = name.replaceAll("[^A-Za-z0-9._-]", "_")
    if (cleaned.length > 64) cleaned.substring(0, 64) else cleaned
  }

  private def writeBytes(outFile: File, bytes: Array[Byte], what: String): Unit = {
    Files.write(outFile.toPath, bytes)
    println("Writing " + what + " to " + outFile.getAbsolutePath)
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