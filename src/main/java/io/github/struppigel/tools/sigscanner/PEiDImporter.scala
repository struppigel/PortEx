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

import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.{CharacterCodingException, Charset, CodingErrorAction, StandardCharsets}
import java.nio.file.Files
import scala.collection.immutable.ListMap
import scala.collection.mutable.{ArrayBuffer, ListBuffer}

/**
 * Options for importing PEiD databases.
 *
 * @param base location keyword for signatures that are not ep_only, e.g. "file" or "overlay"
 * @param anchoredBase if true, signatures that are not ep_only match at the
 *                     start of the base location, otherwise anywhere within it
 * @param leadingWildcardsAsOffset if true, leading ?? of anchored patterns are
 *                                 removed and added to the anchor offset
 */
final case class PEiDImportOptions(
    base: String = "file",
    anchoredBase: Boolean = false,
    leadingWildcardsAsOffset: Boolean = false) {

  def withBase(base: String): PEiDImportOptions = copy(base = base)

  def withAnchoredBase(anchored: Boolean): PEiDImportOptions = copy(anchoredBase = anchored)

  def withLeadingWildcardsAsOffset(enabled: Boolean): PEiDImportOptions = copy(leadingWildcardsAsOffset = enabled)
}

object PEiDImportOptions {
  /** ep_only signatures at the entry point, all others anywhere in the file */
  val Default: PEiDImportOptions = PEiDImportOptions()
}

/**
 * Converts PEiD signature databases (e.g. userdb.txt) to signatures.
 * <p>
 * Supported keys: signature, ep_only, at_offset and until_offset (hex),
 * section_start_only, is_dot_net and in_section. Quoted ASCII strings in
 * signatures are supported as in PortEx 5. Malformed entries are skipped and
 * reported as warnings of the database.
 */
object PEiDImporter {

  /** imports a PEiD database file with default options */
  def load(file: File): SignatureDatabase = load(file, PEiDImportOptions.Default)

  /** imports a PEiD database file */
  def load(file: File, options: PEiDImportOptions): SignatureDatabase =
    parse(decode(Files.readAllBytes(file.toPath)), file.getName, options)

  /**
   * Decodes each line as UTF-8, or as windows-1252 if it is not valid UTF-8.
   */
  def decode(bytes: Array[Byte]): String = {
    val lines = ListBuffer[String]()
    var start = 0
    for (i <- 0 to bytes.length) {
      if (i == bytes.length || bytes(i) == '\n') {
        lines += decodeLine(java.util.Arrays.copyOfRange(bytes, start, i))
        start = i + 1
      }
    }
    lines.mkString("\n")
  }

  private def decodeLine(line: Array[Byte]): String = {
    val decoder = StandardCharsets.UTF_8.newDecoder()
      .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
    try decoder.decode(ByteBuffer.wrap(line)).toString
    catch {
      case _: CharacterCodingException => new String(line, Charset.forName("windows-1252"))
    }
  }

  private val Entities = Map("&gt;" -> ">", "&lt;" -> "<", "&amp;" -> "&", "&quot;" -> "\"", "&apos;" -> "'")

  /** decodes HTML entities like &amp;gt; and &amp;#62; */
  def decodeEntities(s: String): String = {
    val decimal = "&#(\\d{1,7});".r
    val hex = "&#[xX]([0-9a-fA-F]{1,6});".r
    var result = hex.replaceAllIn(s, m => java.util.regex.Matcher.quoteReplacement(new String(Character.toChars(Integer.parseInt(m.group(1), 16)))))
    result = decimal.replaceAllIn(result, m => java.util.regex.Matcher.quoteReplacement(new String(Character.toChars(m.group(1).toInt))))
    Entities.foldLeft(result) { case (acc, (entity, ch)) => acc.replace(entity, ch) }
  }

  /** a raw entry of a PEiD database */
  final case class PEiDEntry(name: String, line: Int, values: ListMap[String, String])

  /** reads the entries without converting them */
  def parseEntries(text: String): (List[PEiDEntry], List[String]) = {
    val entries = ListBuffer[PEiDEntry]()
    val warnings = ListBuffer[String]()
    var name: String = null
    var nameLine = 0
    var values = ListMap[String, String]()
    def finish(): Unit = if (name != null) entries += PEiDEntry(name, nameLine, values)
    for ((raw, idx) <- text.split("\r\n|\n|\r", -1).zipWithIndex) {
      val line = raw.trim
      if (line.isEmpty || line.startsWith(";")) {
        // comment
      } else if (line.startsWith("[")) {
        finish()
        val close = line.lastIndexOf(']')
        name = decodeEntities(if (close > 0) line.substring(1, close) else line.substring(1)).trim
        nameLine = idx + 1
        values = ListMap()
      } else if (name != null && line.contains("=")) {
        val eq = line.indexOf('=')
        values += (line.substring(0, eq).trim.toLowerCase -> line.substring(eq + 1).trim)
      } else warnings += s"line ${idx + 1}: ignored '$line'"
    }
    finish()
    (entries.toList, warnings.toList)
  }

  /** imports PEiD database text */
  def parse(text: String, sourceName: String, options: PEiDImportOptions): SignatureDatabase = {
    val (entries, lineWarnings) = parseEntries(text)
    val signatures = ArrayBuffer[Signature]()
    val warnings = ArrayBuffer[String]() ++ lineWarnings.map(w => s"$sourceName: $w")
    for (entry <- entries) {
      try signatures += toSignature(entry, sourceName, options)
      catch {
        case e: IllegalArgumentException => warnings += s"$sourceName:${entry.line}: ${e.getMessage}, signature [${entry.name}] skipped"
        case e: SignatureDatabaseException => warnings += s"$sourceName:${entry.line}: ${e.reason}, signature [${entry.name}] skipped"
      }
    }
    val seen = scala.collection.mutable.HashSet[String]()
    val unique = signatures.filter { s =>
      val isNew = seen.add(SignatureDatabaseWriter.canonical(s))
      if (!isNew) warnings += s"${s.source}: duplicate of an earlier signature [${s.name}], skipped"
      isNew
    }
    new SignatureDatabase(unique.toIndexedSeq, warnings.toIndexedSeq)
  }

  private def hexValue(s: String, key: String): Long =
    try java.lang.Long.parseLong(s.replace(" ", "").stripPrefix("0x").stripPrefix("0X"), 16)
    catch { case _: NumberFormatException => throw new IllegalArgumentException(s"invalid hex number for $key: '$s'") }

  /** converts one PEiD entry to a signature */
  def toSignature(entry: PEiDEntry, sourceName: String, options: PEiDImportOptions): Signature = {
    val v = entry.values
    val signature = v.getOrElse("signature", throw new IllegalArgumentException("missing 'signature'"))
    var tokens = convertPattern(signature)
    val epOnly = v.get("ep_only").exists(_.equalsIgnoreCase("true"))
    val sectionStart = v.get("section_start_only").exists(_.equalsIgnoreCase("true"))
    val inEPSection = v.get("in_section").exists(_.trim == "1")
    val atOffset = v.get("at_offset").map(hexValue(_, "at_offset")).getOrElse(0L)
    val untilOffset = v.get("until_offset").map(hexValue(_, "until_offset"))

    def anchored(location: String): (String, String) = {
      var offset = atOffset
      if (options.leadingWildcardsAsOffset) {
        val leading = tokens.takeWhile(_ == "??").size
        if (leading > 0 && leading < tokens.size) {
          tokens = tokens.drop(leading)
          offset += leading
        }
      }
      ("at", if (offset == 0) location else s"$location + 0x${offset.toHexString.toUpperCase}")
    }

    val (key, location) =
      if (epOnly) anchored("entrypoint")
      else if (sectionStart) anchored("section")
      else if (inEPSection) ("in", "section(entrypoint)")
      else untilOffset match {
        case Some(until) => ("in", s"${options.base}[0x${atOffset.toHexString.toUpperCase}-0x${until.toHexString.toUpperCase}]")
        case None if options.anchoredBase || atOffset != 0 => anchored(options.base)
        case None => ("in", options.base)
      }
    val lines = ListBuffer(s"[${entry.name}]", s"pattern = ${tokens.mkString(" ")}", s"$key = $location")
    v.get("is_dot_net").foreach(d => lines += s"requires = ${if (d.equalsIgnoreCase("true")) "" else "!"}dotnet")
    val db = SignatureDatabase.parse(lines.mkString("\n"), sourceName)
    val sig = db.signatures.head
    new Signature(sig.name, sig.clauses, sig.conditions, sig.metadata, s"$sourceName:${entry.line}")
  }

  /**
   * Converts a PEiD signature to pattern tokens. Outside of quotes only hex
   * digits and '?' are significant, as in PortEx 5. Quoted strings stay strings
   * if they are printable ASCII, otherwise they become hex bytes.
   */
  def convertPattern(signature: String): List[String] = {
    val tokens = ListBuffer[String]()
    val hex = new StringBuilder
    def flushHex(): Unit = {
      if (hex.length % 2 != 0) throw new IllegalArgumentException(s"odd number of hex digits in '$signature'")
      hex.toString.grouped(2).foreach(t => tokens += t.toUpperCase)
      hex.clear()
    }
    var i = 0
    while (i < signature.length) {
      val c = signature.charAt(i)
      if (c == '\'') {
        flushHex()
        val close = signature.indexOf('\'', i + 1)
        if (close < 0) throw new IllegalArgumentException(s"unterminated quote in '$signature'")
        val text = signature.substring(i + 1, close)
        if (text.nonEmpty) {
          if (text.forall(ch => ch >= 0x20 && ch <= 0x7E && ch != '\\' && ch != '\'')) tokens += s"'$text'"
          else text.foreach(ch => tokens += "%02X".format(ch & 0xFF))
        }
        i = close + 1
      } else {
        if (Character.digit(c, 16) >= 0 || c == '?') hex += c
        i += 1
      }
    }
    flushHex()
    if (tokens.isEmpty) throw new IllegalArgumentException(s"empty signature")
    tokens.toList
  }
}
