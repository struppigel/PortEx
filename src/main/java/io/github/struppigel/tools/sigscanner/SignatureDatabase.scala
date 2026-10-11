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

import io.github.struppigel.tools.sigscanner.pattern.{Pattern, PatternSyntaxException}
import org.apache.logging.log4j.LogManager

import java.io.{File, InputStream}
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import scala.annotation.varargs
import scala.collection.JavaConverters._
import scala.collection.immutable.ListMap
import scala.collection.mutable
import scala.collection.mutable.{ArrayBuffer, ListBuffer}

/**
 * Thrown if a signature database is malformed.
 *
 * @param source name of the database
 * @param line 1-based line number
 * @param column 1-based column, 0 if unknown
 * @param reason description of the problem
 */
class SignatureDatabaseException(val source: String, val line: Int, val column: Int, val reason: String)
  extends RuntimeException(s"$source:$line${if (column > 0) ":" + column else ""}: $reason")

/**
 * An immutable list of signatures. See docs/SIGNATURES.md for the file format.
 *
 * @param signatures the signatures in database order
 * @param warnings problems found while loading, e.g. skipped entries
 */
final class SignatureDatabase(val signatures: IndexedSeq[Signature], val warnings: IndexedSeq[String]) {

  def getSignatures: java.util.List[Signature] = signatures.asJava

  def getWarnings: java.util.List[String] = warnings.asJava

  def size: Int = signatures.size

  override def toString: String = s"SignatureDatabase(${signatures.size} signatures)"
}

object SignatureDatabase {

  private val logger = LogManager.getLogger(SignatureDatabase.getClass.getName)

  /** metadata keys, additionally all keys starting with x- are metadata */
  val MetadataKeys: Set[String] = Set("type", "version", "options", "lang", "author", "url", "description", "extensions")

  val empty: SignatureDatabase = new SignatureDatabase(IndexedSeq.empty, IndexedSeq.empty)

  /**
   * Loads a database file. Malformed entries cause an exception.
   */
  def load(file: File): SignatureDatabase = load(file, lenient = false)

  /**
   * Loads a database file.
   *
   * @param lenient if true, malformed entries are skipped and reported as warnings
   */
  def load(file: File, lenient: Boolean): SignatureDatabase =
    parse(new String(Files.readAllBytes(file.toPath), StandardCharsets.UTF_8), file.getName, lenient)

  /**
   * Loads a database from the class path, malformed entries cause an exception.
   *
   * @param path absolute resource path, e.g. "/data/signatures/packers.sig"
   */
  def loadResource(path: String): SignatureDatabase = {
    val in: InputStream = getClass.getResourceAsStream(path)
    if (in == null) throw new IllegalArgumentException("signature database not found: " + path)
    try {
      val out = new java.io.ByteArrayOutputStream(1 << 16)
      val buffer = new Array[Byte](1 << 16)
      var read = in.read(buffer)
      while (read >= 0) {
        out.write(buffer, 0, read)
        read = in.read(buffer)
      }
      parse(new String(out.toByteArray, StandardCharsets.UTF_8), path.substring(path.lastIndexOf('/') + 1), lenient = false)
    } finally in.close()
  }

  /** merges databases in the given order */
  @varargs def merge(databases: SignatureDatabase*): SignatureDatabase = {
    val signatures = Vector.newBuilder[Signature]
    val warnings = Vector.newBuilder[String]
    for (db <- databases) {
      signatures ++= db.signatures
      warnings ++= db.warnings
    }
    new SignatureDatabase(signatures.result(), warnings.result())
  }

  /** builds a database from signatures */
  def of(signatures: Seq[Signature]): SignatureDatabase = new SignatureDatabase(signatures.toIndexedSeq, IndexedSeq.empty)

  /** builds a database from signatures */
  def of(signatures: java.util.List[Signature]): SignatureDatabase = of(signatures.asScala.toList)

  /**
   * Parses the text of a signature database, malformed entries cause an exception.
   *
   * @param text the content of the database
   * @param sourceName name of the database used in messages, e.g. the file name
   */
  def parse(text: String, sourceName: String): SignatureDatabase = parse(text, sourceName, lenient = false)

  /**
   * Parses the text of a signature database.
   *
   * @param text the content of the database
   * @param sourceName name of the database used in messages, e.g. the file name
   * @param lenient if true, malformed entries are skipped and reported as warnings
   */
  def parse(text: String, sourceName: String, lenient: Boolean): SignatureDatabase = {
    // written with plain loops, because the bundled databases are parsed while a fresh JVM is still slow
    val content = if (text.startsWith("﻿")) text.substring(1) else text
    val signatures = ArrayBuffer[Signature]()
    val warnings = ArrayBuffer[String]()
    // signatures by name to find exact duplicates
    val byName = new java.util.HashMap[String, List[Signature]]()
    var entry: EntryBuilder = null

    def finish(): Unit = if (entry != null) {
      val e = entry
      entry = null
      try {
        val sig = e.build()
        var sameName = byName.get(sig.name)
        if (sameName == null) sameName = Nil
        var duplicate = false
        var rest = sameName
        while (!duplicate && rest.nonEmpty) {
          duplicate = rest.head.sameAs(sig)
          rest = rest.tail
        }
        if (!duplicate) {
          signatures += sig
          byName.put(sig.name, sig :: sameName)
        } else warnings += s"$sourceName:${e.line}: duplicate of an earlier signature [${e.name}], skipped"
      } catch {
        case ex: SignatureDatabaseException if lenient =>
          warnings += ex.getMessage + ", signature skipped"
      }
    }

    var lineStart = 0
    var lineNr = 0
    while (lineStart <= content.length) {
      var lineEnd = lineStart
      while (lineEnd < content.length && content.charAt(lineEnd) != '\n' && content.charAt(lineEnd) != '\r') lineEnd += 1
      val rawLine = content.substring(lineStart, lineEnd)
      lineStart = if (lineEnd + 1 < content.length && content.charAt(lineEnd) == '\r' && content.charAt(lineEnd + 1) == '\n')
        lineEnd + 2 else lineEnd + 1
      lineNr += 1
      val line = rawLine.trim
      if (line.isEmpty || line.startsWith(";") || line.startsWith("#")) {
        // blank line or comment
      } else if (line.startsWith("[")) {
        finish()
        val close = line.lastIndexOf(']')
        if (close <= 0) {
          val ex = new SignatureDatabaseException(sourceName, lineNr, rawLine.indexOf('[') + 1, "missing ']' after signature name")
          if (!lenient) throw ex
          warnings += ex.getMessage + ", signature skipped"
          entry = new EntryBuilder("", sourceName, lineNr, skip = true)
        } else {
          val name = line.substring(1, close).trim
          if (close != line.length - 1 || name.isEmpty) {
            val ex = new SignatureDatabaseException(sourceName, lineNr, 0,
              if (name.isEmpty) "empty signature name" else "unexpected text after ']'")
            if (!lenient) throw ex
            warnings += ex.getMessage + ", signature skipped"
            entry = new EntryBuilder(name, sourceName, lineNr, skip = true)
          } else entry = new EntryBuilder(name, sourceName, lineNr, skip = false)
        }
      } else {
        val eq = rawLine.indexOf('=')
        if (entry == null || eq < 0) {
          val ex = new SignatureDatabaseException(sourceName, lineNr, 1,
            if (entry == null) "expected a signature name in brackets, e.g. [UPX]" else "expected 'key = value'")
          if (!lenient) throw ex
          warnings += ex.getMessage + ", line ignored"
          if (entry != null) entry.skip = true
        } else {
          val key = rawLine.substring(0, eq).trim
          var valueStart = eq + 1
          while (valueStart < rawLine.length && Character.isWhitespace(rawLine.charAt(valueStart))) valueStart += 1
          val value = rawLine.substring(valueStart).trim
          entry.add(key, value, lineNr, rawLine.indexOf(key) + 1, valueStart + 1)
        }
      }
    }
    finish()
    if (warnings.nonEmpty) warnings.foreach(w => logger.debug(w))
    new SignatureDatabase(signatures.toIndexedSeq, warnings.toIndexedSeq)
  }

  private case class Entry(key: String, value: String, line: Int, keyColumn: Int, valueColumn: Int)

  /**
   * Splits keys like "pattern.2" or "version_info.ProductName" into the lower
   * case base key and the argument after the first dot, null if there is none.
   */
  private def validKeyChar(c: Char, first: Boolean): Boolean =
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (!first && ((c >= '0' && c <= '9') || c == '-'))

  /**
   * Splits keys like "pattern.2" or "version_info.ProductName" into the lower
   * case base key and the argument after the first dot, null if there is none.
   */
  private def splitKey(key: String): (String, String) = {
    val dot = key.indexOf('.')
    val base = if (dot < 0) key else key.substring(0, dot)
    val argument = if (dot < 0) null else key.substring(dot + 1)
    var valid = base.nonEmpty && validKeyChar(base.charAt(0), first = true) && (argument == null || argument.nonEmpty)
    var i = 1
    while (valid && i < base.length) {
      valid = validKeyChar(base.charAt(i), first = false)
      i += 1
    }
    if (valid) (base.toLowerCase, argument) else null
  }

  private val NoConditions: IndexedSeq[Condition] = Vector.empty

  /** collects the key value pairs of one signature and validates them */
  private class EntryBuilder(val name: String, source: String, val line: Int, var skip: Boolean) {
    private val entries = new ArrayBuffer[Entry](4)

    def add(key: String, value: String, lineNr: Int, keyColumn: Int, valueColumn: Int): Unit =
      entries += Entry(key, value, lineNr, keyColumn, valueColumn)

    private def error(e: Entry, column: Int, msg: String): Nothing =
      throw new SignatureDatabaseException(source, e.line, column, msg)

    private def error(msg: String): Nothing = throw new SignatureDatabaseException(source, line, 0, msg)

    private def clauseNumber(e: Entry, base: String, argument: String): Int = {
      if (argument == null) 1
      else {
        val n = try argument.toInt catch { case _: NumberFormatException => error(e, e.keyColumn, s"invalid clause number in '${e.key}'") }
        if (n < 2) error(e, e.keyColumn, s"clause numbers start at 2, use '$base' for the first clause")
        n
      }
    }

    def build(): Signature = {
      if (skip) throw new SignatureDatabaseException(source, line, 0, s"malformed signature [$name]")
      // clause number, pattern and entry; usually there is only one clause
      val patterns = new ArrayBuffer[(Int, Pattern, Entry)](1)
      // clause number and location, in database order
      val locations = new ArrayBuffer[(Int, LocationSpec)](2)
      var conditions: ArrayBuffer[Condition] = null
      var metadata: ArrayBuffer[(String, String)] = null

      var idx = 0
      while (idx < entries.length) {
        val e = entries(idx)
        idx += 1
        val split = splitKey(e.key)
        if (split == null) error(e, e.keyColumn, s"invalid key '${e.key}'")
        val base = split._1
        val argument = split._2
        if (e.value.isEmpty) error(e, e.valueColumn, s"empty value for '${e.key}'")
        if (base == "pattern") {
          val n = clauseNumber(e, base, argument)
          var p = 0
          while (p < patterns.length) {
            if (patterns(p)._1 == n) error(e, e.keyColumn, s"duplicate '${e.key}'")
            p += 1
          }
          val pattern = try Pattern.parse(e.value) catch {
            case ex: PatternSyntaxException => error(e, e.valueColumn + ex.column - 1, ex.reason)
          }
          patterns += ((n, pattern, e))
        } else if (base == "at" || base == "in") {
          val n = clauseNumber(e, base, argument)
          var specs = try LocationSpec.parseList(e.value, search = base == "in") catch {
            case ex: SpecSyntaxException => error(e, e.valueColumn + ex.column - 1, ex.reason)
          }
          while (specs.nonEmpty) {
            locations += ((n, specs.head))
            specs = specs.tail
          }
        } else if (Condition.Keys.contains(base)) {
          if (base == "version_info" && argument == null)
            error(e, e.keyColumn, "version_info needs a key, e.g. version_info.ProductName")
          if (base != "version_info" && argument != null) error(e, e.keyColumn, s"invalid key '${e.key}'")
          if (conditions == null) conditions = new ArrayBuffer[Condition](2)
          conditions += (try ConditionParser.parse(base, argument, e.value) catch {
            case ex: SpecSyntaxException => error(e, e.valueColumn + ex.column - 1, ex.reason)
          })
        } else if (Condition.ReservedKeys.contains(base)) {
          error(e, e.keyColumn, s"condition '${e.key}' is not supported by this version")
        } else if (MetadataKeys.contains(base) && argument == null) {
          if (metadata == null) metadata = new ArrayBuffer[(String, String)](2)
          var m = 0
          while (m < metadata.length) {
            if (metadata(m)._1 == base) error(e, e.keyColumn, s"duplicate '${e.key}'")
            m += 1
          }
          metadata += ((base, e.value))
        } else if (base.startsWith("x-")) {
          if (metadata == null) metadata = new ArrayBuffer[(String, String)](2)
          metadata += ((e.key, e.value))
        } else {
          // unknown keys might be conditions of a newer version, ignoring them could cause false positives
          error(e, e.keyColumn, s"unknown key '${e.key}'")
        }
      }

      // locations of clauses without pattern
      var l = 0
      var orphan = Int.MaxValue
      while (l < locations.length) {
        val n = locations(l)._1
        var p = 0
        var found = false
        while (!found && p < patterns.length) {
          found = patterns(p)._1 == n
          p += 1
        }
        if (!found) orphan = math.min(orphan, n)
        l += 1
      }
      if (orphan != Int.MaxValue)
        error(s"'${if (orphan == 1) "at/in" else s"at.$orphan/in.$orphan"}' without '${if (orphan == 1) "pattern" else s"pattern.$orphan"}'")
      val sortedPatterns = if (patterns.length <= 1) patterns else patterns.sortBy(_._1)
      if (sortedPatterns.nonEmpty && sortedPatterns(0)._1 != 1) error("'pattern' is missing, numbered clauses start at pattern.2")
      val clauses = new Array[Clause](sortedPatterns.length)
      var c = 0
      while (c < sortedPatterns.length) {
        val (n, pattern, e) = sortedPatterns(c)
        val specs = Vector.newBuilder[LocationSpec]
        var endAnchored = false
        var any = false
        var i = 0
        while (i < locations.length) {
          if (locations(i)._1 == n) {
            val spec = locations(i)._2
            specs += spec
            any = true
            endAnchored |= spec.mode == EndAnchored
          }
          i += 1
        }
        if (!any) error(e, e.keyColumn,
          s"'${e.key}' has no location, add 'at${if (n == 1) "" else "." + n} = ...' or 'in${if (n == 1) "" else "." + n} = ...'")
        if (endAnchored && pattern.hasFollowTokens) error(e, e.valueColumn, "'at = eof' can not be used with follow tokens")
        clauses(c) = new Clause(n, pattern, specs.result())
        c += 1
      }
      if (clauses.isEmpty && conditions == null) error(s"signature [$name] needs a pattern or a condition")
      new Signature(name, clauses.toVector, if (conditions == null) NoConditions else conditions.toVector,
        if (metadata == null) ListMap.empty else ListMap(metadata: _*), s"$source:$line")
    }
  }
}

/**
 * Parses condition values: comma separated, each optionally negated with '!',
 * as plain text, "quoted text" or /regex/flags.
 */
private[sigscanner] object ConditionParser {

  def parse(key: String, argument: String, value: String): Condition = {
    val values = parseValues(value)
    key match {
      case "requires" =>
        for ((v, col) <- values) {
          if (v.isRegex) throw new SpecSyntaxException("requires does not take regular expressions", col)
          if (!Condition.RequiresFlags.contains(v.text))
            throw new SpecSyntaxException(s"unknown requirement '${v.text}', expected one of " +
              Condition.RequiresFlags.toList.sorted.mkString(", "), col)
        }
      case "import" =>
        for ((v, col) <- values if !v.isRegex) {
          val parts = v.text.split("!", -1)
          if (parts.length > 2 || parts.exists(_.trim.isEmpty))
            throw new SpecSyntaxException("expected 'dll' or 'dll!function'", col)
        }
      case "resource" =>
        for ((v, col) <- values) {
          if (v.isRegex) throw new SpecSyntaxException("resource takes <type>[/<name>[/<language>]], not a regular expression", col)
          val parts = v.text.split("/", -1)
          if (parts.length > 3 || parts.exists(_.trim.isEmpty))
            throw new SpecSyntaxException("expected <type>[/<name>[/<language>]]", col)
        }
      case _ =>
    }
    new Condition(key, argument, values.map(_._1).toIndexedSeq, value)
  }

  /** @return the values with their 1-based columns */
  def parseValues(value: String): List[(ConditionValue, Int)] = {
    val result = ListBuffer[(ConditionValue, Int)]()
    var i = 0
    def skipWs(): Unit = while (i < value.length && Character.isWhitespace(value.charAt(i))) i += 1
    while (i <= value.length) {
      skipWs()
      val start = i
      if (i >= value.length) throw new SpecSyntaxException("expected a value", i + 1)
      val negated = value.charAt(i) == '!'
      if (negated) {
        i += 1
        skipWs()
      }
      if (i >= value.length) throw new SpecSyntaxException("expected a value after '!'", i + 1)
      val v = value.charAt(i) match {
        case '"' =>
          val sb = new StringBuilder
          i += 1
          while (i < value.length && value.charAt(i) != '"') {
            if (value.charAt(i) == '\\' && i + 1 < value.length) i += 1
            sb += value.charAt(i)
            i += 1
          }
          if (i >= value.length) throw new SpecSyntaxException("unterminated quote", start + 1)
          i += 1
          new ConditionValue(negated, sb.toString, null)
        case '/' =>
          val sb = new StringBuilder
          i += 1
          while (i < value.length && value.charAt(i) != '/') {
            if (value.charAt(i) == '\\' && i + 1 < value.length && value.charAt(i + 1) == '/') i += 1
            else if (value.charAt(i) == '\\' && i + 1 < value.length) { sb += '\\'; i += 1 }
            sb += value.charAt(i)
            i += 1
          }
          if (i >= value.length) throw new SpecSyntaxException("unterminated regular expression", start + 1)
          i += 1
          val flagsStart = i
          while (i < value.length && Character.isLetter(value.charAt(i))) i += 1
          var flags = 0
          for (f <- value.substring(flagsStart, i)) f match {
            case 'i' => flags |= java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.UNICODE_CASE
            case 's' => flags |= java.util.regex.Pattern.DOTALL
            case 'm' => flags |= java.util.regex.Pattern.MULTILINE
            case other => throw new SpecSyntaxException(s"unknown regular expression flag '$other'", flagsStart + 1)
          }
          val regex = try java.util.regex.Pattern.compile(sb.toString, flags) catch {
            case ex: java.util.regex.PatternSyntaxException =>
              throw new SpecSyntaxException("invalid regular expression: " + ex.getDescription, start + 1)
          }
          new ConditionValue(negated, sb.toString, regex)
        case _ =>
          val textStart = i
          while (i < value.length && value.charAt(i) != ',') i += 1
          new ConditionValue(negated, value.substring(textStart, i).trim, null)
      }
      result += ((v, start + 1))
      skipWs()
      if (i < value.length) {
        if (value.charAt(i) != ',') throw new SpecSyntaxException("expected ',' between values", i + 1)
        i += 1
      } else i = value.length + 1
    }
    result.toList
  }
}
