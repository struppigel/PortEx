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
 * A compiled byte pattern of a signature, e.g. "60 BE ?? ?? ?? ?? 8D BE".
 * See docs/SIGNATURES.md for the syntax.
 * <p>
 * Instances are immutable and thread-safe.
 */
final class Pattern private (val source: String, private[sigscanner] val nodes: Vector[PNode]) {

  private[sigscanner] val compiled: CompiledPattern = PatternCompiler.compile(nodes)

  /** the pattern as written in the signature */
  def getSource: String = source

  /** minimum number of bytes of a match (up to the first follow token) */
  def getMinLength: Int = compiled.minLength

  /** maximum number of bytes of a match (up to the first follow token), -1 if unbounded */
  def getMaxLength: Int = compiled.maxLength

  /** true if the pattern contains follow tokens like $$$$$$$$ */
  def hasFollowTokens: Boolean = compiled.hasFollow

  /**
   * Matches the pattern at the start of the bytes. Follow tokens treat
   * addresses as array indices.
   */
  def matches(bytes: Array[Byte]): Boolean = matchAt(bytes, 0) >= 0

  /**
   * Matches the pattern at the given index of the bytes. Follow tokens treat
   * addresses as array indices.
   *
   * @return the index after the match or -1 if it does not match
   */
  def matchAt(bytes: Array[Byte], index: Int): Int = {
    val matcher = new PatternMatcher(new ArrayByteSource(bytes), AddressMapper.Identity)
    matcher.matchAt(compiled, index, bytes.length).toInt
  }

  /**
   * Searches the bytes for the first match.
   *
   * @return the index where the first match starts or -1
   */
  def find(bytes: Array[Byte]): Int = {
    val matcher = new PatternMatcher(new ArrayByteSource(bytes), AddressMapper.Identity)
    var i = 0
    while (i < bytes.length) {
      if (matcher.matchAt(compiled, i, bytes.length) >= 0) return i
      i += 1
    }
    -1
  }

  override def toString: String = source

  override def equals(other: Any): Boolean = other match {
    case p: Pattern => p.nodes == nodes
    case _ => false
  }

  override def hashCode(): Int = nodes.hashCode()
}

object Pattern {

  /**
   * Parses and compiles a pattern.
   *
   * @throws PatternSyntaxException if the pattern is malformed
   */
  def parse(source: String): Pattern = new Pattern(source.trim, PatternParser.parse(source.trim))
}
