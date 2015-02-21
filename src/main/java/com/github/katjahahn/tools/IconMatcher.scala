package com.github.katjahahn.tools

import java.io.File
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.ScalaIOUtil.using
import com.github.katjahahn.parser.sections.rsrc.icon.IconParser
import java.security.MessageDigest
import java.io.BufferedReader
import java.io.FileReader
import com.github.katjahahn.parser.ByteArrayUtil

object IconMatcher { //TODO use trie

  private val iconWhitelist = "iconwhitelist.txt"

  def main(args: Array[String]): Unit = {
    val testfile = new File("/home/deque/portextestfiles/goodfiles/chmodXP/NOTEPAD.EXE")
    findMatches(testfile).foreach(println)
  }

  def findMatches(file: File): List[String] = {
    val digest = MessageDigest.getInstance("SHA-256")
    val groupList = IconParser.extractGroupIcons(file).asScala
    (for (group <- groupList) yield {
      val iconHashes = group.nIDToLocations.values.map(loc => Hasher.computeHash(file,
        digest, loc.from, loc.from + loc.size)).toList
      val matches = iconHashes.map(findMatch).flatten
      matches
    }).toList.flatten
  }

  private def findMatch(hash: Array[Byte]): Option[String] = {
    using(new BufferedReader(new FileReader(iconWhitelist))) { in =>
      var line = ""
      while ({ line = in.readLine(); line } != null) {
        val split = line.split(":")
        if (split.length == 3 && split(0) == ByteArrayUtil.byteToHex(hash, "")) {
          return Some(line)
        }
      }
      None
    }
  }

}