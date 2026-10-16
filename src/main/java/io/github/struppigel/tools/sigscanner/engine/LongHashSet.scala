/**
 * *****************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools.sigscanner.engine

/**
 * A set of non-negative longs with open addressing, without boxing. It forgets
 * all elements when it grows beyond maxSize, so it is only suitable for
 * avoiding repeated work, not for correctness.
 *
 * @param maxSize number of elements at which the set is cleared
 */
private[sigscanner] final class LongHashSet(maxSize: Int = LongHashSet.DefaultMaxSize) {

  private var table = LongHashSet.emptyTable(64)
  private var count = 0

  def size: Int = count

  /**
   * Adds the value.
   *
   * @param value a value >= 0
   * @return true if the value was not in the set
   */
  def add(value: Long): Boolean = {
    var mask = table.length - 1
    var i = LongHashSet.mix(value).toInt & mask
    while (table(i) != LongHashSet.Empty) {
      if (table(i) == value) return false
      i = (i + 1) & mask
    }
    if (count >= maxSize) {
      clear()
      mask = table.length - 1
      i = LongHashSet.mix(value).toInt & mask
    } else if ((count + 1) * 2 > table.length) {
      grow()
      mask = table.length - 1
      i = LongHashSet.mix(value).toInt & mask
      while (table(i) != LongHashSet.Empty) i = (i + 1) & mask
    }
    table(i) = value
    count += 1
    true
  }

  def contains(value: Long): Boolean = {
    val mask = table.length - 1
    var i = LongHashSet.mix(value).toInt & mask
    while (table(i) != LongHashSet.Empty) {
      if (table(i) == value) return true
      i = (i + 1) & mask
    }
    false
  }

  /** removes all elements and keeps the capacity */
  def clear(): Unit = {
    java.util.Arrays.fill(table, LongHashSet.Empty)
    count = 0
  }

  private def grow(): Unit = {
    val old = table
    table = LongHashSet.emptyTable(old.length * 2)
    val mask = table.length - 1
    var j = 0
    while (j < old.length) {
      val v = old(j)
      if (v != LongHashSet.Empty) {
        var i = LongHashSet.mix(v).toInt & mask
        while (table(i) != LongHashSet.Empty) i = (i + 1) & mask
        table(i) = v
      }
      j += 1
    }
  }
}

private[sigscanner] object LongHashSet {

  /** keeps the table at 32 MiB at most */
  val DefaultMaxSize: Int = 1 << 21

  private val Empty = -1L

  private def emptyTable(capacity: Int): Array[Long] = {
    val t = new Array[Long](capacity)
    java.util.Arrays.fill(t, Empty)
    t
  }

  /** the finalizer of MurmurHash3, spreads close values over the table */
  private def mix(value: Long): Long = {
    var h = value
    h ^= h >>> 33
    h *= 0xff51afd7ed558ccdL
    h ^= h >>> 33
    h *= 0xc4ceb9fe1a85ec53L
    h ^ (h >>> 33)
  }
}
