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

import io.github.struppigel.tools.sigscanner.pattern.Pattern

import java.util.Optional
import scala.collection.JavaConverters._
import scala.collection.immutable.ListMap

/**
 * A pattern and the locations where it is matched. All clauses of a signature
 * must match.
 *
 * @param number 1 for 'pattern', N for 'pattern.N'
 * @param pattern the byte pattern
 * @param locations where the pattern is matched, one match in any location suffices
 */
final class Clause(val number: Int, val pattern: Pattern, val locations: IndexedSeq[LocationSpec]) {

  def getNumber: Int = number

  def getPattern: Pattern = pattern

  def getLocations: java.util.List[LocationSpec] = locations.asJava

  override def equals(other: Any): Boolean = other match {
    case c: Clause => c.number == number && c.pattern == pattern && c.locations == locations
    case _ => false
  }

  override def hashCode(): Int = (number, pattern, locations).hashCode()
}

/**
 * One value of a condition, e.g. "!dotnet" or "/^UPX/i".
 *
 * @param negated true if the value starts with '!'
 * @param text the value without negation, quotes or regex delimiters
 * @param regex the compiled regex if the value is a /regex/, otherwise null
 */
final class ConditionValue(val negated: Boolean, val text: String, val regex: java.util.regex.Pattern) {

  def isRegex: Boolean = regex != null

  /** compares the string with this value, ignoring negation */
  def matches(s: String, ignoreCase: Boolean): Boolean =
    if (regex != null) regex.matcher(s).find()
    else if (ignoreCase) text.equalsIgnoreCase(s)
    else text == s

  override def equals(other: Any): Boolean = other match {
    case v: ConditionValue => v.negated == negated && v.text == text && v.isRegex == isRegex &&
      (!isRegex || v.regex.flags == regex.flags)
    case _ => false
  }

  override def hashCode(): Int = (negated, text, isRegex).hashCode()
}

/**
 * A declarative condition of a signature, e.g. "import = kernel32.dll!VirtualAlloc".
 * All values must hold.
 *
 * @param key the condition key, e.g. "import" or "version_info"
 * @param argument the part after the key for "version_info.ProductName", otherwise null
 * @param values the values, all must hold
 * @param source the value as written in the database
 */
final class Condition(val key: String, val argument: String, val values: IndexedSeq[ConditionValue], val source: String) {

  def getKey: String = key

  def getArgument: Optional[String] = Optional.ofNullable(argument)

  def getSource: String = source

  /** the key as written in the database */
  def fullKey: String = if (argument == null) key else key + "." + argument

  override def equals(other: Any): Boolean = other match {
    case c: Condition => c.key == key && c.argument == argument && c.values == values
    case _ => false
  }

  override def hashCode(): Int = (key, argument, values).hashCode()

  override def toString: String = s"$fullKey = $source"
}

object Condition {

  /** flags of the 'requires' condition */
  val RequiresFlags: Set[String] = Set("dotnet", "native", "pe32", "pe32+", "dll", "driver", "console", "gui",
    "overlay", "signed", "rich", "tls", "x86", "x64")

  /** supported condition keys, version_info always has an argument */
  val Keys: Set[String] = Set("requires", "section", "import", "export", "resource", "version_info",
    "dotnet_string", "dotnet_us", "dotnet_type")

  /** condition keys that are reserved for future versions */
  val ReservedKeys: Set[String] = Set("linker_version", "rich_version", "entropy", "imphash", "priority")
}

/**
 * A signature: named clauses and conditions that must all hold, plus metadata.
 *
 * @param name the name of the signature
 * @param clauses patterns and their locations, empty for signatures that only have conditions
 * @param conditions declarative conditions
 * @param metadata metadata keys and values in database order
 * @param source file name and line number of the entry
 */
final class Signature(
    val name: String,
    val clauses: IndexedSeq[Clause],
    val conditions: IndexedSeq[Condition],
    val metadata: ListMap[String, String],
    val source: String) {

  def getName: String = name

  def getClauses: java.util.List[Clause] = clauses.asJava

  def getConditions: java.util.List[Condition] = conditions.asJava

  def getMetadata: java.util.Map[String, String] = metadata.asJava

  def getSource: String = source

  def hasPattern: Boolean = clauses.nonEmpty

  /** the comma separated values of the metadata key 'type' */
  def getTypes: java.util.List[String] =
    metadata.get("type").toList.flatMap(_.split(",").map(_.trim).filter(_.nonEmpty)).asJava

  def getVersion: Optional[String] = Optional.ofNullable(metadata.getOrElse("version", null))

  def getDescription: Optional[String] = Optional.ofNullable(metadata.getOrElse("description", null))

  /** true if name, clauses, conditions and metadata are equal, the source is ignored */
  def sameAs(other: Signature): Boolean =
    other.name == name && other.clauses == clauses && other.conditions == conditions && other.metadata == metadata

  override def toString: String = s"[$name] ($source)"
}
