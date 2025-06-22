/**
 * *****************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
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
package io.github.struppigel.parser.sections.edata

import com.google.common.base.Optional

/**
 * Represents one entry of the export section.
 * <p>
 * Is created by the export section instance and used for easy access to the
 * export information without knowing the details of the internal structure.
 *
 * @author Karsten Hahn
 *
 * Creates an instance of an export entry with ordinal
 * and relative virtual address
 *
 * @param symbolRVA the relative virtual address that points to the function
 * @param ordinal the ordinal of the functions
 * @param forwarder name of the forwarder string, only present if symbolRVA is
 *        a forwarder address
 */
class ExportEntry(
  val symbolRVA: Long,
  val ordinal: Int,
  val forwarder: Option[String]) extends Equals {

  def this(symbolRVA: Long, ordinal: Int) =
    this(symbolRVA, ordinal, None)

  /**
   * Returns whether the export entry is a forwarder entry
   * @return true iff forwarder entry
   */
  def forwarded: Boolean = forwarder match { case Some(s) => true; case None => false }

  /**
   * Returns the forwarder string or empty string if this is no forwarder entry.
   */
  private def forwarderString(): String = forwarder match {
    case None => ""
    case Some(str) => "forwarded from " + str
  }

  /**
   * {@inheritDoc}
   */
  override def toString(): String =
    s"-ordinal entry-, ${ordinal}, ${symbolRVA} (0x${java.lang.Long.toHexString(symbolRVA)}) ${forwarderString}"

  //for java
  //TODO write converter for option to optional!
  /**
   * Returns some forwarder String or None if present entry is no forwarder.
   */
  def maybeGetForwarder(): Optional[String] =
    forwarder match {
      case None => Optional.absent()
      case Some(str) => Optional.of(str)
    }

  def canEqual(other: Any) = {
    other.isInstanceOf[ExportEntry]
  }

  /**
   * {@inheritDoc}
   */
  override def equals(other: Any) = {
    other match {
      case that: ExportEntry => that.canEqual(ExportEntry.this) && symbolRVA == that.symbolRVA && ordinal == that.ordinal
      case _ => false
    }
  }

  /**
   * {@inheritDoc}
   */
  override def hashCode() = {
    val prime = 41
    prime * (prime + symbolRVA.hashCode) + ordinal.hashCode
  }

}

/**
 * Creates an instance of an export entry with the name, ordinal
 * and relative virtual address
 *
 * @param symbolRVA the relative virtual address that points to the function
 * @param name the name of the function
 * @param ordinal the ordinal of the function
 * @param forwarder name of the forwarder string, only present if symbolRVA is
 *        a forwarder address
 */
class ExportNameEntry(
  symbolRVA: Long,
  val name: String,
  ordinal: Int,
  forwarder: Option[String]) extends ExportEntry(symbolRVA, ordinal, forwarder) {

  def this(symbolRVA: Long, name: String, ordinal: Int) =
    this(symbolRVA, name, ordinal, None)

  private def forwarderString(): String = forwarder match {
    case None => ""
    case Some(str) => "forwarded from " + str
  }

  /**
   * {@inheritDoc}
   */
  override def toString(): String =
    s"${name}, ${ordinal}, ${symbolRVA} (0x${java.lang.Long.toHexString(symbolRVA)}) ${forwarderString}"

  override def canEqual(other: Any) = {
    other.isInstanceOf[ExportNameEntry]
  }

  override def equals(other: Any) = {
    other match {
      case that: ExportNameEntry => that.canEqual(ExportNameEntry.this) && symbolRVA == that.symbolRVA && name == that.name && ordinal == that.ordinal
      case _ => false
    }
  }

  /**
   * {@inheritDoc}
   */
  override def hashCode() = {
    val prime = 41
    prime * (prime * (prime + symbolRVA.hashCode) + name.hashCode) + ordinal.hashCode
  }

}
