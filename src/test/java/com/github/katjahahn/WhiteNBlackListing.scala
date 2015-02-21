package com.github.katjahahn

import java.io.File
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.rsrc.icon.IconParser
import com.github.katjahahn.tools.Hasher
import java.security.MessageDigest
import com.github.katjahahn.parser.ScalaIOUtil.{ using }
import java.io.BufferedWriter
import java.io.FileWriter
import com.github.katjahahn.parser.ByteArrayUtil

object WhiteNBlackListing {
  
  private val delim = ":"

  def main(args: Array[String]): Unit = {
    val parentfolder = new File("/home/deque/portextestfiles/goodfiles")
    for (folder <- parentfolder.listFiles().toList.filter(_.isDirectory())) {
      whitelistLogos(folder)
    }
  }

  def whitelistLogos(folder: File): Unit = {
    val messageDigest = MessageDigest.getInstance("SHA-256")
    val outfile = new File("iconwhitelist.txt")
    var hashNrWritten = 0
    for (file <- folder.listFiles().toList) {
      val groupIcons = IconParser.extractGroupIcons(file).asScala
      groupIcons.foreach { grp =>
        val iconHashes = grp.nIDToLocations.values.map(loc => Hasher.computeHash(file,
          messageDigest, loc.from, loc.from + loc.size)).toList
        saveToWhitelist(iconHashes, outfile, file.getName(), folder.getName())
        hashNrWritten += iconHashes.size
        if(hashNrWritten % 100 == 0) {
          println("hashes written: " + hashNrWritten)
        }
      }
    }
  }

  def saveToWhitelist(hashes: List[Array[Byte]], outfile: File, filename: String,
    osVersion: String): Unit = {
    val append = true
    using(new BufferedWriter(new FileWriter(outfile, append))) { out =>
      hashes.foreach { hash =>
        val line = ByteArrayUtil.byteToHex(hash, "") + delim + filename + 
          delim + osVersion
        out.write(line)
        out.newLine()
      }
    }
  }

}