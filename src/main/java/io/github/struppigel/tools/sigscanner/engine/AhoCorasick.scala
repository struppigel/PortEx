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
 * Aho-Corasick automaton that finds all occurrences of a set of byte strings
 * in one pass.
 * <p>
 * States are numbered in breadth first order. The first denseLimit states,
 * which are the ones near the root where a search spends most of its time,
 * have a dense transition table with the failure transitions resolved. Small
 * automata are dense completely. The children of the other states are sorted
 * arrays that are searched with binary search, missing children follow the
 * failure links until a dense state answers.
 * <p>
 * The automaton is immutable. A scan keeps its state in an Int, so that
 * inputs can be fed in chunks.
 *
 * @param keys the byte strings, their index is reported on matches
 * @param denseLimit number of states with a dense transition table
 */
private[sigscanner] final class AhoCorasick(keys: IndexedSeq[Array[Byte]], denseLimit: Int = AhoCorasick.DenseLimit) {

  require(keys.forall(_.nonEmpty), "empty key")

  /** number of states, the root is state 0 */
  val stateCount: Int = AhoCorasick.trieSize(keys)

  // byte of the edge into each state
  private val label = new Array[Byte](stateCount)
  // the children of state s are the states childStart(s) until childStart(s + 1), sorted by label
  private val childStart = new Array[Int](stateCount + 1)
  private val fail = new Array[Int](stateCount)
  // the keys that end in state s, including those of its failure chain, are outKeys(outStart(s) until outStart(s + 1))
  private val outStart = new Array[Int](stateCount + 1)
  private var outKeys: Array[Int] = _

  locally {
    // trie with children as sorted linked lists, numbered in insertion order
    val maxStates = stateCount
    val tLabel = new Array[Int](maxStates)
    val firstChild = Array.fill(maxStates)(-1)
    val nextSibling = Array.fill(maxStates)(-1)
    // keys that end in a state as linked lists over key indices, the last added key first
    val ownFirst = Array.fill(maxStates)(-1)
    val ownNext = Array.fill(keys.length)(-1)
    var states = 1

    def child(state: Int, b: Int): Int = {
      var c = firstChild(state)
      while (c >= 0 && tLabel(c) < b) c = nextSibling(c)
      if (c >= 0 && tLabel(c) == b) c else -1
    }

    def addChild(state: Int, b: Int): Int = {
      val s = states
      states += 1
      tLabel(s) = b
      var prev = -1
      var c = firstChild(state)
      while (c >= 0 && tLabel(c) < b) {
        prev = c
        c = nextSibling(c)
      }
      nextSibling(s) = c
      if (prev < 0) firstChild(state) = s else nextSibling(prev) = s
      s
    }

    var k = 0
    while (k < keys.length) {
      val key = keys(k)
      var state = 0
      var i = 0
      while (i < key.length) {
        val b = key(i) & 0xFF
        val c = child(state, b)
        state = if (c >= 0) c else addChild(state, b)
        i += 1
      }
      ownNext(k) = ownFirst(state)
      ownFirst(state) = k
      k += 1
    }

    // breadth first numbering: the children of a state get consecutive numbers in label order
    val order = new Array[Int](stateCount) // new number -> trie state, the root stays 0
    var tail = 1
    var head = 0
    while (head < tail) {
      val s = order(head)
      childStart(head) = tail
      var c = firstChild(s)
      while (c >= 0) {
        order(tail) = c
        tail += 1
        c = nextSibling(c)
      }
      head += 1
    }
    childStart(stateCount) = tail
    var n = 0
    while (n < stateCount) {
      label(n) = tLabel(order(n)).toByte
      n += 1
    }

    // failure links in breadth first order, the failure state is computed before its users
    n = 0
    while (n < stateCount) {
      var c = childStart(n)
      while (c < childStart(n + 1)) {
        val b = label(c) & 0xFF
        if (n == 0) fail(c) = 0
        else {
          var f = fail(n)
          var target = sortedChild(f, b)
          while (target < 0 && f != 0) {
            f = fail(f)
            target = sortedChild(f, b)
          }
          fail(c) = if (target >= 0 && target != c) target else 0
        }
        c += 1
      }
      n += 1
    }

    // outputs: the own keys of a state, then those of its failure state
    n = 0
    var total = 0
    val counts = new Array[Int](stateCount)
    while (n < stateCount) {
      var own = 0
      var key = ownFirst(order(n))
      while (key >= 0) {
        own += 1
        key = ownNext(key)
      }
      counts(n) = own + (if (n == 0) 0 else counts(fail(n)))
      outStart(n) = total
      total += counts(n)
      n += 1
    }
    outStart(stateCount) = total
    outKeys = new Array[Int](total)
    n = 0
    while (n < stateCount) {
      var pos = outStart(n)
      var key = ownFirst(order(n))
      while (key >= 0) {
        outKeys(pos) = key
        pos += 1
        key = ownNext(key)
      }
      if (n != 0) {
        val f = fail(n)
        System.arraycopy(outKeys, outStart(f), outKeys, pos, counts(f))
      }
      n += 1
    }
  }

  /** number of states with a dense transition table */
  private val denseCount: Int = math.max(0, math.min(stateCount, denseLimit))

  val isDense: Boolean = denseCount == stateCount

  /** dense transition table of the first states: delta(state * 256 + byte) */
  private val delta: Array[Int] = {
    val d = new Array[Int](denseCount * 256)
    var s = 0
    while (s < denseCount) {
      val row = s * 256
      // inherit the transitions of the failure state, whose row is complete already
      if (s != 0) System.arraycopy(d, fail(s) * 256, d, row, 256)
      var c = childStart(s)
      while (c < childStart(s + 1)) {
        d(row + (label(c) & 0xFF)) = c
        c += 1
      }
      s += 1
    }
    d
  }

  /** the child of the state for the byte, -1 if there is none */
  private def sortedChild(state: Int, b: Int): Int = {
    var lo = childStart(state)
    var hi = childStart(state + 1) - 1
    while (lo <= hi) {
      val mid = (lo + hi) >>> 1
      val l = label(mid) & 0xFF
      if (l < b) lo = mid + 1
      else if (l > b) hi = mid - 1
      else return mid
    }
    -1
  }

  /** the state after reading the byte */
  def next(state: Int, b: Int): Int = {
    var s = state
    while (true) {
      if (s < denseCount) return delta(s * 256 + b)
      val c = sortedChild(s, b)
      if (c >= 0) return c
      if (s == 0) return 0
      s = fail(s)
    }
    0
  }

  /**
   * Feeds bytes to the automaton.
   *
   * @param state the state after the previous bytes, 0 at the start
   * @param bytes the input
   * @param from index of the first byte
   * @param until index after the last byte
   * @param onMatch called with the key index and the index of the last byte of the occurrence
   * @return the state after the bytes
   */
  def feed(state: Int, bytes: Array[Byte], from: Int, until: Int)(onMatch: (Int, Int) => Unit): Int = {
    val d = delta
    val dense = denseCount
    val starts = outStart
    val out = outKeys
    var s = state
    var i = from
    while (i < until) {
      val b = bytes(i) & 0xFF
      s = if (s < dense) d(s * 256 + b) else next(s, b)
      var k = starts(s)
      val end = starts(s + 1)
      while (k < end) {
        onMatch(out(k), i)
        k += 1
      }
      i += 1
    }
    s
  }
}

private[sigscanner] object AhoCorasick {
  /** states with a dense transition table, 4096 states take 4 MiB */
  val DenseLimit: Int = 4096

  /** number of states of the trie of the keys */
  private def trieSize(keys: IndexedSeq[Array[Byte]]): Int = {
    // counts the distinct prefixes, sorting keeps shared prefixes adjacent
    val sorted = keys.sortWith((a, b) => compare(a, b) < 0)
    var count = 1
    var prev: Array[Byte] = Array.emptyByteArray
    for (key <- sorted) {
      var common = 0
      while (common < prev.length && common < key.length && prev(common) == key(common)) common += 1
      count += key.length - common
      prev = key
    }
    count
  }

  private def compare(a: Array[Byte], b: Array[Byte]): Int = {
    var i = 0
    while (i < a.length && i < b.length) {
      val c = (a(i) & 0xFF) - (b(i) & 0xFF)
      if (c != 0) return c
      i += 1
    }
    a.length - b.length
  }
}
