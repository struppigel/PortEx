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
 * in one pass. Small automata use a dense transition table, large ones the
 * trie with failure links.
 * <p>
 * The automaton is immutable. A scan keeps its state in an Int, so that
 * inputs can be fed in chunks.
 *
 * @param keys the byte strings, their index is reported on matches
 * @param denseLimit maximum number of states for the dense table
 */
private[sigscanner] final class AhoCorasick(keys: IndexedSeq[Array[Byte]], denseLimit: Int = AhoCorasick.DenseLimit) {

  require(keys.forall(_.nonEmpty), "empty key")

  // the trie is built with plain arrays: children of a state form a list sorted by byte
  private val maxStates = keys.map(_.length).sum + 1
  private val label = new Array[Int](maxStates)
  private val firstChild = Array.fill(maxStates)(-1)
  private val nextSibling = Array.fill(maxStates)(-1)
  private var states = 1

  private def child(state: Int, b: Int): Int = {
    var c = firstChild(state)
    while (c >= 0 && label(c) < b) c = nextSibling(c)
    if (c >= 0 && label(c) == b) c else -1
  }

  private def addChild(state: Int, b: Int): Int = {
    val s = states
    states += 1
    label(s) = b
    // insert sorted
    var prev = -1
    var c = firstChild(state)
    while (c >= 0 && label(c) < b) {
      prev = c
      c = nextSibling(c)
    }
    nextSibling(s) = c
    if (prev < 0) firstChild(state) = s else nextSibling(prev) = s
    s
  }

  // keys that end in a state, as linked lists over key indices
  private val ownFirst = Array.fill(maxStates)(-1)
  private val ownNext = Array.fill(keys.length)(-1)

  locally {
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
  }

  val stateCount: Int = states

  /** length of each key */
  val keyLengths: Array[Int] = keys.map(_.length).toArray

  private val fail = new Array[Int](stateCount)

  /** breadth first order of the states, failure states come before their users */
  private val order: Array[Int] = {
    val queue = new Array[Int](stateCount)
    var head = 0
    var tail = 1
    queue(0) = 0
    while (head < tail) {
      val s = queue(head)
      head += 1
      var c = firstChild(s)
      while (c >= 0) {
        queue(tail) = c
        tail += 1
        c = nextSibling(c)
      }
    }
    queue
  }

  /** keys that end in a state, including those of the failure chain */
  private val outputs: Array[Array[Int]] = {
    val out = new Array[Array[Int]](stateCount)
    out(0) = Array.emptyIntArray
    // failure links: for each state in breadth first order, compute the links of its children
    var i = 0
    while (i < stateCount) {
      val s = order(i)
      var c = firstChild(s)
      while (c >= 0) {
        val b = label(c)
        if (s == 0) fail(c) = 0
        else {
          var f = fail(s)
          var target = child(f, b)
          while (target < 0 && f != 0) {
            f = fail(f)
            target = child(f, b)
          }
          fail(c) = if (target >= 0 && target != c) target else 0
        }
        c = nextSibling(c)
      }
      i += 1
    }
    // outputs in breadth first order, the failure state's outputs are complete before they are used
    i = 1
    while (i < stateCount) {
      val s = order(i)
      var own = 0
      var k = ownFirst(s)
      while (k >= 0) {
        own += 1
        k = ownNext(k)
      }
      val inherited = out(fail(s))
      val merged = new Array[Int](own + inherited.length)
      var n = 0
      k = ownFirst(s)
      while (k >= 0) {
        merged(n) = k
        n += 1
        k = ownNext(k)
      }
      System.arraycopy(inherited, 0, merged, n, inherited.length)
      out(s) = merged
      i += 1
    }
    out
  }

  val isDense: Boolean = stateCount <= denseLimit

  /** dense transition table: delta(state * 256 + byte) */
  private val delta: Array[Int] = if (!isDense) null else {
    val d = new Array[Int](stateCount * 256)
    var i = 0
    while (i < stateCount) {
      val s = order(i)
      val row = s * 256
      // inherit the transitions of the failure state, whose row is complete already
      if (s != 0) System.arraycopy(d, fail(s) * 256, d, row, 256)
      var c = firstChild(s)
      while (c >= 0) {
        d(row + label(c)) = c
        c = nextSibling(c)
      }
      i += 1
    }
    d
  }

  /** the state after reading the byte */
  def next(state: Int, b: Int): Int = {
    if (isDense) delta(state * 256 + b)
    else {
      var s = state
      while (true) {
        val c = child(s, b)
        if (c >= 0) return c
        if (s == 0) return 0
        s = fail(s)
      }
      0
    }
  }

  /** keys that end in the state */
  def outputsOf(state: Int): Array[Int] = outputs(state)

  /** true if keys end in the state */
  def hasOutput(state: Int): Boolean = outputs(state).length > 0

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
    var s = state
    var i = from
    if (isDense) {
      val d = delta
      while (i < until) {
        s = d(s * 256 + (bytes(i) & 0xFF))
        if (outputs(s).length > 0) {
          val out = outputs(s)
          var k = 0
          while (k < out.length) {
            onMatch(out(k), i)
            k += 1
          }
        }
        i += 1
      }
    } else {
      while (i < until) {
        s = next(s, bytes(i) & 0xFF)
        if (outputs(s).length > 0) {
          val out = outputs(s)
          var k = 0
          while (k < out.length) {
            onMatch(out(k), i)
            k += 1
          }
        }
        i += 1
      }
    }
    s
  }
}

private[sigscanner] object AhoCorasick {
  /** 4096 states take 4 MiB as dense table */
  val DenseLimit: Int = 4096
}
