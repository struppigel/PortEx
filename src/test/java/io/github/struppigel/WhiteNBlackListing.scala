package io.github.struppigel

import io.github.struppigel.parser.ScalaIOUtil.using
import io.github.struppigel.parser.ByteArrayUtil
import io.github.struppigel.tools.Hasher
import io.github.struppigel.parser.sections.rsrc.icon.IconParser

import java.io.{BufferedWriter, File, FileWriter}
import java.security.MessageDigest
import scala.collection.JavaConverters._

object WhiteNBlackListing {

  private val delim = ":"
  private var hashNrWritten = 0

  def main(args: Array[String]): Unit = {
    val parentfolder = new File("/home/deque/portextestfiles/goodfiles")
    val outfile = new File("iconwhitelist.txt")
    if(outfile.exists()) outfile.delete()
    for (folder <- parentfolder.listFiles().toList.filter(_.isDirectory())) {
      whitelistLogos(folder, outfile)
    }
  }

  def whitelistLogos(folder: File, outfile: File): Unit = {
    val messageDigest = MessageDigest.getInstance("SHA-256")
    for (file <- folder.listFiles().toList) {
      try {
        val groupIcons = IconParser.extractGroupIcons(file).asScala
        groupIcons.foreach { grp =>
          val iconHashes = grp.nIDToLocations.values.map(loc => Hasher.computeHash(file,
            messageDigest, loc.from, loc.from + loc.size)).toList
          saveToWhitelist(iconHashes, outfile, file.getName(), folder.getName())
          hashNrWritten += iconHashes.size
          if (hashNrWritten % 100 == 0) {
            println("hashes written: " + hashNrWritten)
          }
        }
      } catch {
        case ex: Exception => ex.printStackTrace()
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