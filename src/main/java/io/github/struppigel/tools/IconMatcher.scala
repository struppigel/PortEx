/**
 * *****************************************************************************
 * Copyright 2016 Katja Hahn
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

package io.github.struppigel.tools

import io.github.struppigel.parser.ScalaIOUtil.using
import io.github.struppigel.parser.ByteArrayUtil
import io.github.struppigel.parser.sections.rsrc.icon.IconParser

import java.io.{BufferedReader, File, FileReader}
import java.security.MessageDigest
import scala.collection.JavaConverters._

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