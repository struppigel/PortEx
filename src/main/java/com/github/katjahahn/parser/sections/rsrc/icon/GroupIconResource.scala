/**
 * *****************************************************************************
 * Copyright 2015 Katja Hahn
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

package com.github.katjahahn.parser.sections.rsrc.icon

import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.ScalaIOUtil.{ using, hex }
import com.github.katjahahn.parser.ByteArrayUtil
import com.github.katjahahn.parser.PhysicalLocation
import java.io.File
import com.github.katjahahn.parser.sections.rsrc.Resource
import java.io.RandomAccessFile
import GroupIconResource.NID
import com.github.katjahahn.parser.PhysicalLocation
import com.github.katjahahn.parser.sections.rsrc.Level
import com.github.katjahahn.parser.sections.rsrc.ID
import org.apache.logging.log4j.LogManager

/**
 * Parsing and converting group icon resources to an IcoFile.
 */

//FIXME: PsychoXP uTorrent.exe makes problems, check if anomaly

/**
 * @param grpIconDir the group icon directory
 * @param nIDToLocations a map that saves the nID of each idEntry and the
 *        physical location of the resources bytes in the peFile that belong to it
 * @param peFile the file this resource belongs to
 */
class GroupIconResource(
  val groupIconDir: GroupIconDir,
  val nIDToLocations: Map[NID, PhysicalLocation],
  private val peFile: File) {

  val entryHeaderSize = 16

  override def toString(): String =
    s"""|GroupIconDirectory
        |------------------
        |
        |${groupIconDir.toString}
        |Icon locations
        |...............
        |${
      nIDToLocations.map(m => "id: " + m._1.toString + " location: " +
        hex(m._2.from) + "-" + hex(m._2.from + m._2.size)).mkString(NL)
    }
        |
        |""".stripMargin

  /**
   * Converts the GroupIconResource instance into an IcoFile.
   *
   * @return GroupIconResource converted into an IcoFile
   */
  def toIcoFile(): IcoFile = {
    // calculate the offset right after the ICO headers to put raw data into
    var dwImageOffset = 6L + groupIconDir.idEntries.size * entryHeaderSize
    val iconDirEntries = (for (idEntry <- groupIconDir.idEntries) yield {
      // fetch location of raw data
      val peLocation = nIDToLocations(idEntry.nID) //TODO does it exist?
      // create the IconDirEntry
      val iconDirEntry = IconDirEntry(idEntry.bWidth, idEntry.bHeight, idEntry.bColorCount,
        idEntry.bReserved, idEntry.wPlanes, idEntry.wBitCount,
        idEntry.dwBytesInRes, dwImageOffset, peLocation)
      // calculate next offset for raw data of the next icon
      dwImageOffset += idEntry.dwBytesInRes
      // yield the entry
      iconDirEntry
    }).toList

    // instantiate IconDir with the collected iconDirEntries
    val iconDir = IconDir(groupIconDir.idReserved, groupIconDir.idType,
      groupIconDir.idCount, iconDirEntries)
    // create and return the IcoFile
    new IcoFile(iconDir, peFile)
  }

}

object GroupIconResource {

  private val logger = LogManager.getLogger(GroupIconResource.getClass()
    .getName());

  type NID = Int

  private val byteSize = 1
  private val wordSize = 2
  private val dwordSize = 4
  private val qwordSize = 8
  private val entrySize = 14

  /**
   * Parses the resource bytes of the given RT_GROUP_ICON and the related RT_ICON
   * resources to create a GroupIconResource instance.
   *
   * @return GroupIconResource based on the given resource of the type RT_GROUP_ICON
   */
  def apply(grpResource: Resource, resources: List[Resource],
    file: File): GroupIconResource = {
    // fetch location of raw data
    val loc = grpResource.rawBytesLocation
    if (isValidLocation(loc, file)) {
      using(new RandomAccessFile(file, "r")) { raf =>
        // read the header values
        val idReserved = ByteArrayUtil.bytesToInt(loadBytes(loc.from, wordSize, raf))
        val idType = ByteArrayUtil.bytesToInt(loadBytes(loc.from + wordSize, wordSize, raf))
        val idCount = ByteArrayUtil.bytesToInt(loadBytes(loc.from + 2 * wordSize, wordSize, raf))
        // current offset after reading the first three values
        val idEntriesOffset = loc.from + 3 * wordSize
        // read idEntries array starting from idEntriesOffset
        val idEntries = readGroupIconDirEntries(idEntriesOffset, raf, idCount)
        // save location of RT_ICON resources in a map
        val nIDToLocs = getEntryLocs(idEntries, resources, file)
        val filteredEntries = idEntries.filter(entry => nIDToLocs.contains(entry.nID))
        // create grpIconDir
        val grpIconDir = GroupIconDir(idReserved, idType, idCount, filteredEntries)
        // create and return GroupIconResource
        new GroupIconResource(grpIconDir, nIDToLocs, file)
      }
    } else throw new IllegalArgumentException("invalid group icon location")
  }

  private def isValidLocation(loc: PhysicalLocation, file: File): Boolean = {
    loc.from >= 0 &&
      loc.size > 0 &&
      loc.from + loc.size <= file.length()
  }

  /**
   *
   * @param idEntriesOffset
   * @param raf
   * @param idCount
   * @return list of GrpIconDirEntries
   */
  private def readGroupIconDirEntries(idEntriesOffset: Long, raf: RandomAccessFile,
    idCount: Int): List[GroupIconDirEntry] = {
    (for (i <- Range(0, idCount)) yield {
      val offset = i * entrySize + idEntriesOffset
      //Check for EOF
      if (offset + 14 <= raf.length()) {
        val bWidth = loadBytes(offset, 1, raf)(0)
        val bHeight = loadBytes(offset + 1, 1, raf)(0)
        val bColorCount = loadBytes(offset + 2, 1, raf)(0)
        val bReserved = loadBytes(offset + 3, 1, raf)(0)
        val wPlanes = ByteArrayUtil.bytesToInt(loadBytes(offset + 4, 2, raf))
        val wBitCount = ByteArrayUtil.bytesToInt(loadBytes(offset + 6, 2, raf))
        val dwBytesInRes = ByteArrayUtil.bytesToLong(loadBytes(offset + 8, 4, raf))
        val nID = ByteArrayUtil.bytesToInt(loadBytes(offset + 12, 2, raf))
        Some(GroupIconDirEntry(bWidth, bHeight, bColorCount, bReserved, wPlanes,
          wBitCount, dwBytesInRes, nID))
      } else None
    }).toList.flatten
  }

  /**
   * @param nID the nID of the entry
   * @param resources list of all resources in the PE file
   * @return physical location of the raw data for resource with nID
   */
  private def getLocation(nID: NID, resources: List[Resource]): PhysicalLocation = {
    // search for resource, whose ID matches the nID
    val maybeRes = resources.find { res =>
      val nameID = res.getLevelIDs.get(Level.nameLevel)
      nameID match {
        case ID(id, _) => id == nID
        case _ => false
      }
    }
    // if found, get the location
    if (maybeRes.isDefined) {
      val icoResource = maybeRes.get
      icoResource.rawBytesLocation
    } else throw new IllegalStateException("Resource with nID " + nID + " not found")
  }

  /**
   * Creates a map that lists the NID of the RT_ICON resources and the location
   * of their raw data within the pefile.
   *
   * @param idEntries the idEntries of the current GroupIconResource
   * @param resources all resources of the pefile
   */
  private def getEntryLocs(idEntries: List[GroupIconDirEntry],
    resources: List[Resource], file: File): Map[NID, PhysicalLocation] = {
    (for (entry <- idEntries) yield {
      try {
        val loc = getLocation(entry.nID, resources)
        if (isValidLocation(loc, file)) Some((entry.nID, loc)) else None
      } catch {
        case e: IllegalStateException =>
          logger.warn(e)
          logger.warn("file: " + file.getAbsolutePath())
          None
      }
    }).toList.flatten.toMap
  }

}

/**
 * @param idReserved must be 0
 * @param idType Resource Type (must be 1 for icons)
 * @param idCount number of images
 * @param idEntries the entries for each image
 */
case class GroupIconDir(idReserved: Int, idType: Int, idCount: Int, idEntries: List[GroupIconDirEntry]) {
  override def toString(): String =
    s"""|idReserved: $idReserved
        |idType: $idType
        |idCount: $idCount
        |
        |idEntries
        |.........
        |
        |${idEntries.map(_.toString).mkString(NL)}""".stripMargin
}

/**
 * @param bWidth width of the image in pixels
 * @param bHeight height of the image in pixels
 * @param bColorCount Number of colors in image (0 if >= 8bpp)
 * @param bReserved reserved
 * @param wPlanes color planes
 * @param wBitCount
 */
case class GroupIconDirEntry(bWidth: Byte, bHeight: Byte, bColorCount: Byte,
  bReserved: Byte, wPlanes: Int, wBitCount: Int,
  dwBytesInRes: Long, nID: Int) {
  override def toString(): String =
    s"""|bWidth: ${bWidth & 0xff}
        |bHeight: ${bHeight & 0xff}
        |bColorCount: ${bColorCount & 0xff}
        |bReserved: ${bReserved & 0xff}
        |wPlanes: $wPlanes
        |wBitCount: $wBitCount
        |dwBytesInRes: $dwBytesInRes
        |nID: $nID
        |""".stripMargin
}
                           