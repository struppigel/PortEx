/*******************************************************************************
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
 ******************************************************************************/

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

class GroupIconResource(
  private val grpIconDir: GrpIconDir,
  private val nIDToLocations: Map[NID, PhysicalLocation]) {

  override def toString(): String =
    s"""|GroupIconDirectory
        |------------------
        |
        |${grpIconDir.toString}
        |Icon locations
        |...............
        |${
      nIDToLocations.map(m => "id: " + m._1.toString + " location: " +
        hex(m._2.from) + "-" + hex(m._2.from + m._2.size)).mkString(NL)
    }
        |
        |""".stripMargin

  def toIcoFile(): IcoFile = {
    val initialOffset = 6L + grpIconDir.idEntries.size * 16L
    var dwImageOffset = initialOffset
    val iconDirEntries = (for (idEntry <- grpIconDir.idEntries) yield {
      val peLocation = nIDToLocations(idEntry.nID) //TODO does it exist?
      val iconDirEntry = IconDirEntry(idEntry.bWidth, idEntry.bHeight, idEntry.bColorCount,
        idEntry.bReserved, idEntry.wPlanes, idEntry.wBitCount,
        idEntry.dwBytesInRes, dwImageOffset, peLocation)
      dwImageOffset += idEntry.dwBytesInRes
      iconDirEntry
    }).toList

    val iconDir = IconDir(grpIconDir.idReserved, grpIconDir.idType,
      grpIconDir.idCount, iconDirEntries)
    new IcoFile(iconDir)
  }

}

object GroupIconResource {

  type NID = Int

  def apply(resource: Resource, resources: List[Resource],
            file: File): GroupIconResource = {
    val loc = resource.resourceBytes
    using(new RandomAccessFile(file, "r")) { raf =>
      val idReserved = ByteArrayUtil.bytesToInt(loadBytes(loc.from, 2, raf))
      val idType = ByteArrayUtil.bytesToInt(loadBytes(loc.from + 2, 2, raf))
      val idCount = ByteArrayUtil.bytesToInt(loadBytes(loc.from + 4, 2, raf))
      val idEntriesOffset = loc.from + 6
      val idEntries = readGrpIconDirEntries(idEntriesOffset, raf, idCount)
      val grpIconDir = GrpIconDir(idReserved, idType, idCount, idEntries)
      val nIDToLocs = getEntryLocs(idEntries, resources)
      new GroupIconResource(grpIconDir, nIDToLocs)
    }
  }

  private def readGrpIconDirEntries(idEntriesOffset: Long, raf: RandomAccessFile,
                                    idCount: Int): List[GrpIconDirEntry] = {
    (for (i <- Range(0, idCount)) yield {
      val offset = i * 14 + idEntriesOffset
      val bWidth = loadBytes(offset, 1, raf)(0)
      val bHeight = loadBytes(offset + 1, 1, raf)(0)
      val bColorCount = loadBytes(offset + 2, 1, raf)(0)
      val bReserved = loadBytes(offset + 3, 1, raf)(0)
      val wPlanes = ByteArrayUtil.bytesToInt(loadBytes(offset + 4, 2, raf))
      val wBitCount = ByteArrayUtil.bytesToInt(loadBytes(offset + 6, 2, raf))
      val dwBytesInRes = ByteArrayUtil.bytesToLong(loadBytes(offset + 8, 4, raf))
      val nID = ByteArrayUtil.bytesToInt(loadBytes(offset + 12, 2, raf))
      GrpIconDirEntry(bWidth, bHeight, bColorCount, bReserved, wPlanes, wBitCount, dwBytesInRes, nID)
    }).toList
  }

  private def getLocation(nID: NID, resources: List[Resource]): PhysicalLocation = {
    val maybeRes = resources.find { res =>
      val nameID = res.getLevelIDs.get(Level.nameLevel)
      nameID match {
        case ID(id, _) => id == nID
        case _         => false
      }
    }
    if (maybeRes.isDefined) {
      val icoResource = maybeRes.get
      icoResource.resourceBytes
    } else throw new IllegalStateException("Resource with nID " + nID + " not found")
  }

  private def getEntryLocs(idEntries: List[GrpIconDirEntry],
                           resources: List[Resource]): Map[NID, PhysicalLocation] = {
    (for (entry <- idEntries) yield {
      val loc = getLocation(entry.nID, resources)
      (entry.nID, loc)
    }).toMap
  }

}

/**
 * @param idReserved must be 0
 * @param idType Resource Type (must be 1 for icons)
 * @param idCount number of images
 * @param idEntries the entries for each image
 */
case class GrpIconDir(idReserved: Int, idType: Int, idCount: Int, idEntries: List[GrpIconDirEntry]) {
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
case class GrpIconDirEntry(bWidth: Byte, bHeight: Byte, bColorCount: Byte,
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
                           