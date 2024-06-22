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
package com.github.struppigel.parser.sections.rsrc

import com.github.struppigel.parser.PhysicalLocation

import scala.collection.JavaConverters._

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
  val rawBytesLocation: PhysicalLocation, 
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
    case Name(_, name) => name
    case id: ID => id.idString
  }

  def getName(): String = levelIDs(Level.nameLevel) match {
    case Name(_, name) => name
    case id: ID => id.idString
  }
  /**
   * Creates a resource instance
   *
   * @param resourceBytes the bytes that make up the data of the resource
   */
  def this(rawBytesLocation: PhysicalLocation) = this(rawBytesLocation, Map.empty)

  /**
   * {@inheritDoc}
   */
  override def toString(): String =
    "offset: 0x" + java.lang.Long.toHexString(rawBytesLocation.from) +
    ", size: 0x" + java.lang.Long.toHexString(rawBytesLocation.size) + ", " +
    levelIDs.mkString(", ")

  def canEqual(other: Any) = {
    other.isInstanceOf[Resource]
  }

  override def equals(other: Any) = {
    other match {
      case that: Resource => that.canEqual(Resource.this) && rawBytesLocation == that.rawBytesLocation && levelIDsAreEqual(levelIDs, that.levelIDs)
      case _ => false
    }
  }

  private def levelIDsAreEqual(m1: Map[Level, IDOrName], m2: Map[Level, IDOrName]): Boolean = {
    val diff = (m1.keySet -- m2.keySet) ++ (m2.keySet -- m1.keySet)
    if(!diff.isEmpty) false
    else {
      for(k <- m1.keySet){
        if(!m1(k).equals(m2(k))) return false
      }
      true
    }
  }

  override def hashCode() = {
    val prime = 41
    prime * (prime + rawBytesLocation.hashCode) + levelIDs.hashCode
  }

}
