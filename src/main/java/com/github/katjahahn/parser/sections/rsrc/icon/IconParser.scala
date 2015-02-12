package com.github.katjahahn.parser.sections.rsrc.icon

import com.github.katjahahn.parser.sections.rsrc.Resource
import java.io.File
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.rsrc.Level
import com.github.katjahahn.parser.sections.rsrc.ID
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.ByteArrayUtil

object IconParser {
  
  private final val RT_GROUP_ICON = 14 //TODO remove data file, use enums
  
  private def extractGroupIcons(file: File): List[GroupIconResource] = {
    val loader = new SectionLoader(file)
    val rsrc = loader.loadResourceSection()
    val resources = rsrc.getResources().asScala.toList
    _extractGroupIcons(resources, file)
  }
  
  private def _extractGroupIcons(resources: List[Resource], file: File): List[GroupIconResource] =
    resources.filter(isGroupIcon).map(res => toGroupIconResource(res, file))
  
  private def isGroupIcon(resource: Resource): Boolean = {
    val ids = resource.getLevelIDs.asScala
    val resType = ids(Level.typeLevel)
    resType match {
      case ID(id, _) => id == RT_GROUP_ICON
      case _ => false
    }
  }
  
  private def toGroupIconResource(resource: Resource, file: File): GroupIconResource = {
    //TODO implement conversion
    null
  }
  
}