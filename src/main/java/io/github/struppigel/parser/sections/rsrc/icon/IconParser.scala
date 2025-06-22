/**
 * *****************************************************************************
 * Copyright 2015 Karsten Hahn
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

package io.github.struppigel.parser.sections.rsrc.icon

import io.github.struppigel.parser.PEData
import io.github.struppigel.parser.sections.SectionLoader
import io.github.struppigel.parser.sections.rsrc.{ID, Level, Resource}

import java.io.File
import java.util.Optional
import scala.collection.JavaConverters._

object IconParser {

  //TODO Ticket 699224 keygen with non-standard icons
  //see: #be5f8d4433137de5828020353a951c73e0fc03ad1c48a23e915b3beea9c3e67c

  private final val RT_GROUP_ICON = 14 //TODO remove data file, use enums

  /**
   * Extract IcoFiles of the provided resources for this PE.
   * @param resources the resources to extract icons from
   * @param pedata
   * @return
   */
  def extractIcons(resources: java.util.List[Resource], pedata: PEData): java.util.List[IcoFile] =
    extractGroupIcons(resources: java.util.List[Resource], pedata.getFile).asScala.map(_.toIcoFile()).asJava

  /**
   * Extract all IcoFiles for this PE
   * @param pedata
   * @return
   */
  def extractIcons(pedata: PEData): java.util.List[IcoFile] =
    extractGroupIcons(pedata.getFile).asScala.map(_.toIcoFile()).asJava

  /**
   * Convert the resource into an IcoFile. Resource must be of type RT_GROUP_ICON
   * @param resource the resource to convert
   * @param pedata the pedata that contains the RT_GROUP_ICON
   * @return IcoFile for the resource or empty optional if not an RT_GROUP_ICON or not parseable
   */
  def resourceToIcoFile(resource : Resource, pedata: PEData): Optional[IcoFile] = {
    val loader = new SectionLoader(pedata)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent) {
      val rsrc = maybeRSRC.get
      val resources = rsrc.getResources().asScala.toList
      resourceToIcoFile(resource, resources.asJava, pedata.getFile)
    }
    Optional.empty()
  }

  /**
   * Convert the resource into an IcoFile. Resource must be of type RT_GROUP_ICON
   * @param resource the resource to convert
   * @param allResources all resources of the file or all RT_ICON resources of the file
   * @param file the PE file
   * @return IcoFile for the resource or empty optional if not an RT_GROUP_ICON or not parseable
   */
  def resourceToIcoFile(resource : Resource, allResources : java.util.List[Resource], file : File): Optional[IcoFile] = {
    if(isGroupIcon(resource)){
      val gir = GroupIconResource(resource, allResources.asScala.toList, file)
      Optional.of(gir.toIcoFile())
    }
    Optional.empty()
  }

  /**
   * Extract all group icons from the resource section of the file.
   * @param file the PE file
   * @return list of group icon resources
   */
  def extractGroupIcons(file: File): java.util.List[GroupIconResource] = {
    val loader = new SectionLoader(file)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent) {
      val rsrc = maybeRSRC.get
      val resources = rsrc.getResources().asScala.toList
      _extractGroupIcons(resources, file).asJava
    } else List.empty.asJava
  }

  /**
   * @param resources the list of all resources that belong the file
   * @param file the PE file to extract the icons from
   * @return list of group icon resources
   */
  def extractGroupIcons(resources: java.util.List[Resource], file: File): java.util.List[GroupIconResource] =
    _extractGroupIcons(resources.asScala.toList, file).asJava

  /**
   * @param resources the list of all resources that belong the file
   * @param file the PE file to extract the icons from
   * @return list of group icon resources
   */
  private def _extractGroupIcons(resources: List[Resource], file: File): List[GroupIconResource] =
    resources.filter(isGroupIcon).map(res => GroupIconResource(res, resources, file))

  def isGroupIcon(resource: Resource): Boolean = {
    val ids = resource.getLevelIDs.asScala
    val resType = ids(Level.typeLevel)
    resType match {
      case ID(id, _) => id == RT_GROUP_ICON
      case _ => false
    }
  }
}