package com.github.katjahahn.parser.sections.rsrc.icon

import com.github.katjahahn.parser.PhysicalLocation

class GroupIconResource(
    private val grpIconDir: GrpIconDir,
    private val locations: List[PhysicalLocation]) {
 
}

class IcoFile(
    private val iconDir: IconDir,
    private val bytes: Array[Byte]) {
  
}

/**
 * @param idReserved must be 0
 * @param idType Resource Type (must be 1 for icons)
 * @param idCount number of images
 * @param idEntries the entries for each image
 */
case class IconDir(idReserved: Int, idType: Int, idCount: Int, idEntries: Array[IconDirEntry])

/**
 * @param bWidth width of the image in pixels
 * @param bHeight height of the image in pixels
 * @param bColorCount Number of colors in image (0 if >= 8bpp)
 * @param bReserved reserved
 * @param wPlanes color planes
 * @param wBitCount
 */
case class IconDirEntry(bWidth: Byte, bHeight: Byte, bColorCount: Byte,
                           bReserved: Byte, wPlanes: Int, wBitCount: Int,
                           dwBytesInRes: Long, dwImageOffset: Long)
                           
/**
 * @param idReserved must be 0
 * @param idType Resource Type (must be 1 for icons)
 * @param idCount number of images
 * @param idEntries the entries for each image
 */
case class GrpIconDir(idReserved: Int, idType: Int, idCount: Int, idEntries: Array[GrpIconDirEntry])

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
                           dwBytesInRes: Long, nID: Int)
                           