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

import java.util.Optional
import scala.collection.JavaConverters._

/**
 * Where one clause of a signature matched.
 *
 * @param clause the matched clause
 * @param location the location of the clause that matched
 * @param region the region of the location that contains the match
 * @param offset file offset where the match starts
 * @param length number of matched bytes up to the first follow token
 */
final class ClauseMatch(val clause: Clause, val location: LocationSpec, val region: Region, val offset: Long, val length: Int) {

  def getClause: Clause = clause

  def getLocation: LocationSpec = location

  def getRegion: Region = region

  def getOffset: Long = offset

  def getLength: Int = length

  /** offset relative to the start of the region */
  def getRelativeOffset: Long = offset - region.start

  override def toString: String =
    s"${region.label}+0x${getRelativeOffset.toHexString} (file offset 0x${offset.toHexString}, $length bytes)"
}

/**
 * A matched signature. The location of the match is the location of its first
 * clause. Signatures that only have conditions have no location, their
 * location kind is METADATA.
 *
 * @param signature the matched signature
 * @param clauseMatches one match for each clause of the signature
 */
final class SignatureMatch(val signature: Signature, val clauseMatches: IndexedSeq[ClauseMatch]) {

  private def primary: Option[ClauseMatch] = clauseMatches.headOption

  def getSignature: Signature = signature

  def getName: String = signature.name

  /** location kind of the first clause, METADATA for signatures without pattern */
  def getLocationKind: LocationKind = primary.map(_.region.kind).getOrElse(LocationKind.METADATA)

  /** label of the matched region, e.g. "section(.text)" */
  def getLocationLabel: String = primary.map(_.region.label).getOrElse("metadata")

  /** false for signatures without pattern */
  def hasOffset: Boolean = primary.isDefined

  /** file offset where the match starts, -1 if the signature has no pattern */
  def getOffset: Long = primary.map(_.offset).getOrElse(-1L)

  /** offset relative to the matched region, -1 if the signature has no pattern */
  def getRelativeOffset: Long = primary.map(_.getRelativeOffset).getOrElse(-1L)

  /** number of matched bytes of the first clause up to its first follow token */
  def getLength: Int = primary.map(_.length).getOrElse(0)

  def getRegion: Optional[Region] = Optional.ofNullable(primary.map(_.region).orNull)

  /** start of the matched region, -1 if the signature has no pattern */
  def getRegionStart: Long = primary.map(_.region.start).getOrElse(-1L)

  /** end of the matched region, -1 if the signature has no pattern */
  def getRegionEnd: Long = primary.map(_.region.end).getOrElse(-1L)

  def getClauseMatches: java.util.List[ClauseMatch] = clauseMatches.asJava

  override def toString: String = primary match {
    case Some(m) => s"${signature.name} at $m"
    case None => s"${signature.name} (metadata)"
  }
}

/**
 * Options of the signature scanner.
 *
 * @param chunkSize number of bytes read at once when searching
 * @param maxMatchesPerSignature matches of a signature beyond this number are dropped
 * @param stepBudget maximum backtracking steps of a single match attempt
 */
final case class ScanOptions(
    chunkSize: Int = 1 << 20,
    maxMatchesPerSignature: Int = 10000,
    stepBudget: Int = 1000000)

object ScanOptions {
  val Default: ScanOptions = ScanOptions()
}
