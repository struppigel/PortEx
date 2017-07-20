package com.github.katjahahn.tools

import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import com.github.katjahahn.parser.ScalaIOUtil.using
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.PESignature
import com.github.katjahahn.parser.msdos.MSDOSHeader
import com.github.katjahahn.parser.PELoader
/**
 * Automatic repair for PE files or files that should be PE files.
 */
class PEAutoRepair(private val inFile: File, private val outFile: File) {

  /**
   * Repair everything automatically.
   */
  def repair(): Unit = {
    // copy file before editing
    Files.copy(inFile.toPath, outFile.toPath, StandardCopyOption.REPLACE_EXISTING)
    var haveFixed = false

    using(new RandomAccessFile(inFile, "r")) { raf =>
      println("MSDOS Header check ...");
      val headerbytes = IOUtil.loadBytesSafely(0, MSDOSHeader.FORMATTED_HEADER_SIZE, raf)

      if (!MSDOSHeader.hasSignature(headerbytes)) {
        println("MSDOS signature is invalid, repairing ...")
        MSDOSHeader.repairSignature(outFile)
        haveFixed = true
      }

      println("PE signature check ...")
      val pesig: PESignature = new PESignature(inFile);
      if (pesig.exists()) {
        println("PE signature is valid")
      } else {
        println("PE signature not found, attempting repair ...")
        pesig.repair(outFile)
        haveFixed = true
      }
    }
    if (haveFixed) {
      // check if reload works
      if(isValidPE()) {
        println("File repaired and saved to " + outFile.getAbsolutePath)
      } else {
        println("Tried to repair, but still invalid PE file. Saved to " + outFile.getAbsolutePath)
      }
    } else {
      Files.delete(outFile.toPath)
      println("I didn't fix anything")
    }
  }
  
  private def isValidPE(): Boolean = {
    try {
       PELoader.loadPE(outFile)
    } catch {
      case e: Exception => return false 
    }
    true
  }

}

object PEAutoRepair {
  def apply(inFile: File, outFile: File): PEAutoRepair = {
    new PEAutoRepair(inFile, outFile)
  }
}