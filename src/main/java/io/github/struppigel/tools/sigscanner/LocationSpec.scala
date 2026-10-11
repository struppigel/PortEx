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

import io.github.struppigel.parser.optheader.DataDirectoryKey

import scala.collection.mutable.ListBuffer

/**
 * Thrown for malformed values of signature database entries.
 *
 * @param reason description of the problem
 * @param column 1-based column within the value
 */
class SpecSyntaxException(val reason: String, val column: Int)
  extends IllegalArgumentException(s"column $column: $reason")

/**
 * Case insensitive or sensitive glob with '*' as wildcard for any number of
 * characters.
 */
private[sigscanner] final case class Glob(pattern: String, caseSensitive: Boolean) {
  private val regex = {
    val quoted = pattern.split("\\*", -1).map(java.util.regex.Pattern.quote).mkString(".*")
    java.util.regex.Pattern.compile(quoted,
      if (caseSensitive) java.util.regex.Pattern.DOTALL
      else java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.UNICODE_CASE | java.util.regex.Pattern.DOTALL)
  }

  def isLiteral: Boolean = !pattern.contains('*')

  def matches(s: String): Boolean = regex.matcher(s).matches()

  override def toString: String = pattern
}

/** selects some of the regions of a location kind, e.g. sections by name */
sealed trait Selector

case object AllSelector extends Selector

final case class SectionNameSelector(name: Glob) extends Selector

/** 0-based index, negative values count from the last section */
final case class SectionIndexSelector(index: Int) extends Selector

case object ExecutableSectionSelector extends Selector

case object CodeSectionSelector extends Selector

case object EntryPointSectionSelector extends Selector

/** type, name and language of resources, each may be a glob */
final case class ResourceSelector(resourceType: Glob, name: Option[Glob], language: Option[Glob]) extends Selector

final case class ExportSelector(name: Glob) extends Selector

final case class DataDirectorySelector(key: DataDirectoryKey) extends Selector

final case class StreamSelector(name: String) extends Selector

/** how a pattern is applied to a region */
sealed trait Mode

/**
 * at = loc + offset: the match starts at region start + offset, or for EOF at
 * end of file - offset
 */
final case class Anchored(offset: Long) extends Mode

/** at = eof: the match must end at the end of the file */
case object EndAnchored extends Mode

/**
 * in = loc[from-until]: the match starts at region start + [from, until),
 * until is -1 for the region end. For EOF the match starts within the last
 * 'from' bytes.
 */
final case class Search(from: Long, until: Long) extends Mode

/**
 * A scan location of a signature clause, e.g. "section(.rdata)[0-0x1500]".
 *
 * @param kind the location kind
 * @param selector selects regions of the kind
 * @param mode anchored at or search in the regions
 * @param source the location as written in the database
 */
final class LocationSpec(val kind: LocationKind, val selector: Selector, val mode: Mode, val source: String) {

  def getKind: LocationKind = kind

  def getSource: String = source

  def isAnchored: Boolean = mode != EndAnchored && !mode.isInstanceOf[Search]

  override def toString: String = source

  override def equals(other: Any): Boolean = other match {
    case o: LocationSpec => o.kind == kind && o.selector == selector && o.mode == mode
    case _ => false
  }

  override def hashCode(): Int = (kind, selector, mode).hashCode()
}

object LocationSpec {

  /** search window of 'in = eof' */
  val DefaultEofWindow: Long = 0x10000

  /**
   * Parses the comma separated locations of an 'at' or 'in' value.
   *
   * @param value the value of the key
   * @param search true for 'in', false for 'at'
   * @throws SpecSyntaxException if the value is malformed
   */
  def parseList(value: String, search: Boolean): List[LocationSpec] = {
    // databases repeat the same few locations, e.g. 'at = entrypoint', and the specs are immutable
    val cache = if (search) searchCache else anchorCache
    val cached = cache.get(value)
    if (cached != null) return cached
    val parsed = parseListUncached(value, search)
    if (cache.size < MaxCached) cache.put(value, parsed)
    parsed
  }

  private val MaxCached = 4096
  private val anchorCache = new java.util.concurrent.ConcurrentHashMap[String, List[LocationSpec]]()
  private val searchCache = new java.util.concurrent.ConcurrentHashMap[String, List[LocationSpec]]()

  private def parseListUncached(value: String, search: Boolean): List[LocationSpec] = {
    val items = splitTopLevel(value)
    if (items.forall(_._1.trim.isEmpty)) throw new SpecSyntaxException("expected at least one location", 1)
    items.map { case (item, offset) =>
      if (item.trim.isEmpty) throw new SpecSyntaxException("empty location", offset + 1)
      new ItemParser(item, offset, search).parse()
    }
  }

  /** splits at commas that are not within parentheses, brackets or quotes */
  private[sigscanner] def splitTopLevel(value: String): List[(String, Int)] = {
    val result = ListBuffer[(String, Int)]()
    var depth = 0
    var quote: Char = 0
    var start = 0
    for (i <- value.indices) {
      val c = value.charAt(i)
      if (quote != 0) {
        if (c == quote) quote = 0
      } else c match {
        case '"' | '\'' => quote = c
        case '(' | '[' => depth += 1
        case ')' | ']' => depth -= 1
        case ',' if depth == 0 =>
          result += ((value.substring(start, i), start))
          start = i + 1
        case _ =>
      }
    }
    result += ((value.substring(start), start))
    result.toList
  }

  private class ItemParser(item: String, offset: Int, search: Boolean) {
    private var i = 0

    private def error(msg: String, at: Int = i): Nothing = throw new SpecSyntaxException(msg, offset + at + 1)

    private def peek: Char = if (i < item.length) item.charAt(i) else '\u0000'

    private def skipWhitespace(): Unit = while (i < item.length && Character.isWhitespace(peek)) i += 1

    def parse(): LocationSpec = {
      skipWhitespace()
      val keywordStart = i
      while (i < item.length && (Character.isLetter(peek) || peek == '_')) i += 1
      val keyword = item.substring(keywordStart, i)
      if (keyword.isEmpty) error("expected a location keyword")
      val (kind, aliasSelector) = keyword match {
        case "manifest" => (LocationKind.RESOURCE, Some(ResourceSelector(Glob("RT_MANIFEST", caseSensitive = false), None, None)))
        case _ =>
          val k = LocationKind.byKeyword(keyword)
          if (!k.isPresent) error(s"unknown location '$keyword'", keywordStart)
          (k.get, None)
      }
      skipWhitespace()
      val selector = if (peek == '(') {
        if (aliasSelector.isDefined) error(s"'$keyword' takes no argument")
        val argStart = i + 1
        val close = findClosingParen()
        val arg = item.substring(argStart, close).trim
        i = close + 1
        parseSelector(kind, arg, argStart)
      } else aliasSelector.getOrElse(defaultSelector(kind, keywordStart))
      skipWhitespace()
      val mode = if (search) parseSearch(kind) else parseAnchor(kind)
      skipWhitespace()
      if (i < item.length) error(s"unexpected '${item.substring(i).trim}'")
      new LocationSpec(kind, selector, mode, item.trim)
    }

    private def findClosingParen(): Int = {
      var quote: Char = 0
      var j = i + 1
      while (j < item.length) {
        val c = item.charAt(j)
        if (quote != 0) {
          if (c == quote) quote = 0
        } else if (c == '"') quote = c
        else if (c == ')') return j
        j += 1
      }
      error("missing ')'")
    }

    private def defaultSelector(kind: LocationKind, at: Int): Selector = kind match {
      case LocationKind.DATA_DIRECTORY => error("datadir needs a data directory name, e.g. datadir(IMPORT_TABLE)", at)
      case LocationKind.DOTNET_STREAM => error("dotnet_stream needs a stream name, e.g. dotnet_stream(#US)", at)
      case _ => AllSelector
    }

    private def unquote(arg: String, at: Int): String =
      if (arg.length >= 2 && arg.startsWith("\"") && arg.endsWith("\"")) arg.substring(1, arg.length - 1)
      else if (arg.startsWith("\"")) error("unterminated quote", at)
      else arg

    private def parseSelector(kind: LocationKind, arg: String, at: Int): Selector = {
      if (arg.isEmpty) error("empty argument", at)
      kind match {
        case LocationKind.SECTION => arg match {
          case "executable" => ExecutableSectionSelector
          case "code" => CodeSectionSelector
          case "entrypoint" => EntryPointSectionSelector
          case _ if arg.startsWith("#") =>
            try SectionIndexSelector(arg.substring(1).trim.toInt)
            catch { case _: NumberFormatException => error(s"invalid section index '$arg'", at) }
          case _ => SectionNameSelector(Glob(unquote(arg, at), caseSensitive = true))
        }
        case LocationKind.RESOURCE =>
          val parts = unquote(arg, at).split("/", -1).map(_.trim)
          if (parts.length > 3 || parts.exists(_.isEmpty)) error("expected resource(<type>[/<name>[/<language>]])", at)
          ResourceSelector(Glob(parts(0), caseSensitive = false),
            parts.lift(1).map(Glob(_, caseSensitive = false)), parts.lift(2).map(Glob(_, caseSensitive = false)))
        case LocationKind.EXPORT => ExportSelector(Glob(unquote(arg, at), caseSensitive = true))
        case LocationKind.DATA_DIRECTORY =>
          DataDirectoryKey.values().find(_.name.equalsIgnoreCase(arg)) match {
            case Some(key) => DataDirectorySelector(key)
            case None => error(s"unknown data directory '$arg', expected one of " +
              DataDirectoryKey.values().map(_.name).mkString(", "), at)
          }
        case LocationKind.DOTNET_STREAM => StreamSelector(unquote(arg, at))
        case _ => error(s"'${kind.keyword}' takes no argument", at - 1)
      }
    }

    private def parseNumber(): Long = {
      val start = i
      val hex = item.startsWith("0x", i) || item.startsWith("0X", i)
      if (hex) i += 2
      val digitsStart = i
      while (i < item.length && (if (hex) Character.digit(peek, 16) >= 0 else Character.isDigit(peek))) i += 1
      if (i == digitsStart) error("expected a number", start)
      try java.lang.Long.parseLong(item.substring(digitsStart, i), if (hex) 16 else 10)
      catch { case _: NumberFormatException => error("number too large", start) }
    }

    private def parseAnchor(kind: LocationKind): Mode = {
      if (peek == '[') error("a search window [..] is only allowed with 'in', use 'at = loc + offset' for anchors")
      if (peek == '+' || peek == '-') {
        val sign = peek
        val signPos = i
        i += 1
        skipWhitespace()
        val n = parseNumber()
        if (kind == LocationKind.EOF) {
          if (sign == '+') error("offsets after eof point outside of the file, use 'eof - N'", signPos)
          Anchored(n)
        } else {
          if (sign == '-') error("negative offsets are only allowed for eof", signPos)
          Anchored(n)
        }
      } else if (kind == LocationKind.EOF) EndAnchored
      else Anchored(0)
    }

    private def parseSearch(kind: LocationKind): Mode = {
      if (peek == '+' || peek == '-') error("offsets are only allowed with 'at', use 'in = loc[start-end]' for windows")
      if (peek != '[') {
        return if (kind == LocationKind.EOF) Search(DefaultEofWindow, -1) else Search(0, -1)
      }
      val open = i
      i += 1
      skipWhitespace()
      val from = if (peek == '-') -1L else parseNumber()
      skipWhitespace()
      val mode = if (peek == '-') {
        if (kind == LocationKind.EOF) error("eof only takes a window size, e.g. in = eof[0x1000]")
        i += 1
        skipWhitespace()
        if (peek == ']') {
          if (from < 0) error("a window needs at least one bound", open)
          Search(from, -1)
        } else {
          val until = parseNumber()
          val start = math.max(from, 0)
          if (until <= start) error(s"window end must be greater than its start", open)
          Search(start, until)
        }
      } else {
        if (from <= 0) error("window size must be greater than 0", open)
        if (kind == LocationKind.EOF) Search(from, -1) else Search(0, from)
      }
      skipWhitespace()
      if (peek != ']') error("expected ']'")
      i += 1
      mode
    }
  }
}
