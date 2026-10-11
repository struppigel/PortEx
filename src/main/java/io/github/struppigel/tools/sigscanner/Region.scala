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
package io.github.struppigel.tools.sigscanner

/**
 * A range of file bytes that a scan location resolved to, e.g. one section.
 *
 * @param kind the location kind
 * @param label describes the region, e.g. "section(.text)"
 * @param start file offset where the region starts
 * @param end file offset where the region ends (exclusive)
 */
final case class Region(kind: LocationKind, label: String, start: Long, end: Long) {

  def getKind: LocationKind = kind

  def getLabel: String = label

  def getStart: Long = start

  def getEnd: Long = end

  def size: Long = end - start

  override def toString: String = s"$label [0x${start.toHexString}-0x${end.toHexString})"
}
