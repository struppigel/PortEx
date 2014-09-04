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
package com.github.katjahahn.parser

/**
 * Contains Location classes. Every location represents a start offset and a size.
 * A location is either physical (file offset and size) or virtual
 * (in-memory address and size).
 *
 * @author Katja Hahn
 */

/**
 * Location in virtual space.
 *
 * @param from in-memory start address
 * @param size size in bytes
 */
class VirtualLocation(from: Long, size: Long) extends Location(from, size) {
  override def merge(that: Location): Location =
    new VirtualLocation(this.from, this.size + that.size)
}

/**
 * Location in a file on disk.
 *
 * @param from file offset
 * @param size size in bytes
 */
class PhysicalLocation(from: Long, size: Long) extends Location(from, size) {
  override def merge(that: Location): Location =
    new PhysicalLocation(this.from, this.size + that.size)
}

/**
 * Abstract location.
 */
abstract class Location(val from: Long, val size: Long) extends Equals {

  /**
   * Determines whether this and that location can be merged.
   *
   * @param that that other location
   * @return true iff this location can be merged with that location
   */
  def canMerge(that: Location): Boolean =
    this.getClass() == that.getClass() &&
      this.from + this.size == that.from

  /**
   * Merges this location with that location to one location.
   *
   * @param that that other location
   * @return the merged location
   */
  def merge(that: Location): Location

  def canEqual(other: Any) = {
    other.isInstanceOf[com.github.katjahahn.parser.Location]
  }

  override def toString(): String = "Loc(" + from + ", " + (from + size) + ")"

  override def equals(other: Any) = {
    other match {
      case that: com.github.katjahahn.parser.Location => that.canEqual(Location.this) && from == that.from && size == that.size
      case _ => false
    }
  }

  override def hashCode() = {
    val prime = 41
    prime * (prime + from.hashCode) + size.hashCode
  }
}

object Location {

  /**
   * Merges subsequent locations in a list if possible.
   *
   * @param locs list of locations
   * @return list of locations with the locations merged that can be merged
   */
  def mergeContinuous[T <: Location](locs: List[T]): List[T] = {
    locs.foldLeft(List[T]()) { (list, loc) =>
      // nothing to merge in empty list
      if (list.isEmpty) List(loc)
      // check if mergeable
      else if (list.last.canMerge(loc)) {
        // merge last location from the list with present location
        // return list without last element plus merged location
        list.take(list.length - 1) :+ (list.last.merge(loc).asInstanceOf[T])
      } else list :+ loc
    }
  }
}

