/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn.parser.sections.rsrc

import java.awt.image.BufferedImage
import scala.collection.JavaConverters._

/**
 * Holds the most information of a resource, which is the information provided
 * by the level IDs and the bytes that make up the resource.
 * This is the return datatype for the API user.
 *
 * @param
 * @param
 */
class Resource(
  val resourceBytes: Array[Byte],
  var levelIDs: Map[Level, IDOrName]) {
  
  def getLevelIDs: java.util.Map[Level, IDOrName] = levelIDs.asJava

  def getType(): String = levelIDs(Level.typeLevel) match {
    case Name(rva, name) => name
    case id: ID => id.idString
  }

  def this(resourceBytes: Array[Byte]) = this(resourceBytes, Map.empty)

  def getResourceBytesString(): String = new java.lang.String(resourceBytes, "UTF8").trim()

  //TODO implement, probably need to do that manually
  //  def getResourceAsIcon(): BufferedImage = null 

  //  def isIcon(): Boolean = {
  //    levelIDs(new Level(1)).toString.contains("icon")
  //  }

  override def toString(): String =
    levelIDs.mkString(" || ")

}
