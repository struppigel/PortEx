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
package io.github.struppigel.tools.sigscanner.pattern

/**
 * Matches compiled patterns. Not thread-safe, use one matcher per scan.
 *
 * @param source the bytes to match against
 * @param mapper address mapping for follow tokens
 * @param stepBudget maximum number of matcher steps per match attempt, bounds
 *                   the backtracking of pathological patterns
 */
private[sigscanner] final class PatternMatcher(
    val source: ByteSource,
    val mapper: AddressMapper,
    val stepBudget: Int = PatternMatcher.DefaultStepBudget) {

  private var steps = 0
  private var requiredEnd = -1L
  private var segmentEnd = -1L

  /** true if the last match attempt was aborted because of the step budget */
  var budgetExceeded = false

  /**
   * End of the first contiguous part of the last match, which is the whole
   * match for patterns without follow tokens.
   */
  def lastSegmentEnd: Long = segmentEnd

  /**
   * Matches the pattern at start.
   *
   * @param limit the bytes before the first follow token must be below limit
   * @param mustEndAt the match must end exactly here, -1 for no restriction
   * @return the end of the match (exclusive) or -1
   */
  def matchAt(pattern: CompiledPattern, start: Long, limit: Long, mustEndAt: Long = -1): Long = {
    budgetExceeded = false
    segmentEnd = -1
    val lim = math.min(limit, source.size)
    if (start < 0 || start >= lim) return -1
    if (pattern.isFlat) {
      val end = matchFlat(pattern.flatValues, pattern.flatMasks, start, lim)
      if (end < 0 || (mustEndAt >= 0 && end != mustEndAt)) return -1
      segmentEnd = end
      end
    } else {
      steps = 0
      requiredEnd = mustEndAt
      val end = run(pattern.program, start, lim)
      if (end >= 0 && segmentEnd < 0) segmentEnd = end
      end
    }
  }

  private def matchFlat(values: Array[Byte], masks: Array[Byte], start: Long, limit: Long): Long = {
    val n = values.length
    if (start + n > limit) return -1
    if (matchBytes(values, masks, start)) start + n else -1
  }

  /** checks the masked bytes at pos, the caller ensures they are within the source */
  private def matchBytes(values: Array[Byte], masks: Array[Byte], pos: Long): Boolean = {
    val n = values.length
    val buf = source.buffer
    val bufStart = source.bufferStart
    if (pos >= bufStart && pos + n <= bufStart + source.bufferLength) {
      var i = (pos - bufStart).toInt
      var k = 0
      while (k < n) {
        if ((buf(i) & masks(k)) != values(k)) return false
        i += 1
        k += 1
      }
      true
    } else {
      var k = 0
      while (k < n) {
        val b = source.byteAt(pos + k)
        if (b < 0 || (b & masks(k)) != (values(k) & 0xFF)) return false
        k += 1
      }
      true
    }
  }

  /** @return end of the match or -1 */
  private def run(node: MNode, pos: Long, limit: Long): Long = {
    steps += 1
    if (steps > stepBudget) {
      budgetExceeded = true
      return -1
    }
    node match {
      case null =>
        if (requiredEnd >= 0 && pos != requiredEnd) -1 else pos
      case b: MBytes =>
        if (pos + b.length > limit || !matchBytes(b.values, b.masks, pos)) -1
        else run(b.next, pos + b.length, limit)
      case c: MClass =>
        if (pos >= limit) -1
        else {
          val v = source.byteAt(pos)
          if (v < 0 || !c.cls.contains(v)) -1 else run(c.next, pos + 1, limit)
        }
      case j: MJump =>
        val maxSkip = if (j.max == PJump.Unbounded) PatternParser.MaxSpan else j.max
        val last = math.min(pos + maxSkip, limit)
        var p = pos + j.min
        // skip positions where the next literal byte cannot match
        val literal = j.next match {
          case b: MBytes if b.masks(0) == 0xFF.toByte => b.values(0) & 0xFF
          case _ => -1
        }
        while (p <= last) {
          if (literal < 0 || source.byteAt(p) == literal) {
            val r = run(j.next, p, limit)
            if (r >= 0) return r
            if (budgetExceeded) return -1
          }
          p += 1
        }
        -1
      case a: MAlt =>
        var i = 0
        while (i < a.branches.length) {
          val r = run(a.branches(i), pos, limit)
          if (r >= 0) return r
          if (budgetExceeded) return -1
          i += 1
        }
        -1
      case f: MFollow =>
        if (pos + f.size > limit) return -1
        val target = followTarget(f, pos)
        if (target < 0 || target >= source.size) -1
        else {
          val r = run(f.next, target, source.size)
          // unwinding sets the field end of the first follow token last
          if (r >= 0) segmentEnd = pos + f.size
          r
        }
    }
  }

  /** file offset the follow token at pos refers to, or -1 */
  private def followTarget(f: MFollow, pos: Long): Long = {
    var value = 0L
    var k = 0
    while (k < f.size) {
      val b = source.byteAt(pos + k)
      if (b < 0) return -1
      value |= b.toLong << (8 * k)
      k += 1
    }
    if (f.absolute) {
      mapper.rvaToOffset(value - mapper.imageBase)
    } else {
      // sign extension of the displacement
      val shift = 64 - 8 * f.size
      val displacement = (value << shift) >> shift
      val rva = mapper.offsetToRva(pos)
      if (rva < 0) -1 else mapper.rvaToOffset(rva + f.size + displacement)
    }
  }
}

private[sigscanner] object PatternMatcher {
  val DefaultStepBudget: Int = 1000000
}
