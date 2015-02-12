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
import com.github.katjahahn.parser.PhysicalLocation

/**
 * Holds the information about a resource, which is the information provided
 * by the level IDs and the bytes that make up the resource.
 *
 * @author Katja Hahn
 *
 * Creates a resource instance
 *
 * @param resourceBytes the bytes that make up the data of the resource
 * @param levelIDs the levelIDs of the resource
 */
class Resource(
  val resourceBytes: PhysicalLocation,
  var levelIDs: Map[Level, IDOrName]) {

  /**
   * Returns a map of all level IDs
   *
   * @return level IDs
   */
  def getLevelIDs: java.util.Map[Level, IDOrName] = levelIDs.asJava

  /**
   * Returns the type of the resource as string
   */
  def getType(): String = levelIDs(Level.typeLevel) match {
    case Name(rva, name) => name
    case id: ID => id.idString
  }

  /**
   * Creates a resource instance
   *
   * @param resourceBytes the bytes that make up the data of the resource
   */
  def this(resourceBytes: PhysicalLocation) = this(resourceBytes, Map.empty)

  //  /** TODO
  //   * Creates an UTF8 string of the resource bytes
  //   */
  //  def getResourceBytesString(): String = new java.lang.String(resourceBytes, "UTF8").trim()

  /**
   * {@inheritDoc}
   */
  override def toString(): String =
    "address: 0x" + java.lang.Long.toHexString(resourceBytes.from) + 
    ", size: 0x" + java.lang.Long.toHexString(resourceBytes.size) + ", " +
    levelIDs.mkString(", ")

}
