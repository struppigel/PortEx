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

import com.github.katjahahn.parser.sections.rsrc.Resource
import java.io.File
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.rsrc.Level
import com.github.katjahahn.parser.sections.rsrc.ID
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.ByteArrayUtil
import java.io.RandomAccessFile

object IconParser {
  
  //TODO Ticket 699224 keygen with non-standard icons
  //see: #be5f8d4433137de5828020353a951c73e0fc03ad1c48a23e915b3beea9c3e67c
  
  private final val RT_GROUP_ICON = 14 //TODO remove data file, use enums
  
  /**
   * Extract all group icons from the resource section of the file.
   * @param file the PE file
   * @return list of group icon resources
   */
  def extractGroupIcons(file: File): java.util.List[GroupIconResource] = {
    val loader = new SectionLoader(file)
    val rsrc = loader.loadResourceSection()
    val resources = rsrc.getResources().asScala.toList
    _extractGroupIcons(resources, file).asJava
  }
  
  /**
   * @param resources the list of all resources that belong the file
   * @param file the PE file to extract the icons from
   * @return list of group icon resources
   */
  private def _extractGroupIcons(resources: List[Resource], file: File): List[GroupIconResource] =
    resources.filter(isGroupIcon).map(res => GroupIconResource(res, resources, file))
  
  private def isGroupIcon(resource: Resource): Boolean = {
    val ids = resource.getLevelIDs.asScala
    val resType = ids(Level.typeLevel)
    resType match {
      case ID(id, _) => id == RT_GROUP_ICON
      case _ => false
    }
  }
}