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
 * Thrown if a signature pattern is malformed.
 *
 * @param reason description of the problem
 * @param column 1-based column within the pattern string where the problem was found
 */
class PatternSyntaxException(val reason: String, val column: Int)
  extends IllegalArgumentException(s"column $column: $reason") {

  def getReason: String = reason

  def getColumn: Int = column
}
