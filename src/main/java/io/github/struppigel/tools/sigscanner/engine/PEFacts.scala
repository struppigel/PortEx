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
package io.github.struppigel.tools.sigscanner.engine

import io.github.struppigel.parser.coffheader.{FileCharacteristic, MachineType}
import io.github.struppigel.parser.optheader.OptionalHeader.MagicNumber
import io.github.struppigel.parser.optheader.{DataDirectoryKey, Subsystem}
import io.github.struppigel.parser.sections.clr.{CLRStringField, CLRTableKey, CLRTableType, UserStringsHeap}
import io.github.struppigel.parser.sections.edata.ExportNameEntry
import io.github.struppigel.parser.{AnalysisInterruptedException, PEData}
import io.github.struppigel.tools.Overlay
import io.github.struppigel.tools.sigscanner._
import io.github.struppigel.tools.sigscanner.pattern.ByteSource
import org.apache.logging.log4j.LogManager

import java.nio.charset.StandardCharsets
import scala.collection.JavaConverters._
import scala.util.control.NonFatal

/**
 * Evaluates the conditions of signatures. Every fact is parsed on first use
 * and cached. Facts that can not be parsed count as absent. For files that are
 * not PE files all facts are absent.
 */
private[sigscanner] final class PEFacts(pe: PEData, resolver: RegionResolver, source: ByteSource) {

  import PEFacts.logger

  private def safely[T](what: String, default: T)(compute: => T): T =
    if (pe == null) default
    else try compute catch {
      case e: AnalysisInterruptedException => throw e
      // the parsers use assertions for malformed structures
      case NonFatal(e) =>
        logger.warn(s"could not read $what of ${resolver.name}: $e")
        default
    }

  private def dataDirectoryPresent(key: DataDirectoryKey): Boolean = safely("data directory", false) {
    val entry = pe.getOptionalHeader.maybeGetDataDirEntry(key)
    entry.isPresent && entry.get.getVirtualAddress != 0 && entry.get.getDirectorySize != 0
  }

  private lazy val isDotNet: Boolean = resolver.hasClrDirectory && safely("CLR section", false)(pe.isDotNet)

  private lazy val magic = safely[MagicNumber]("magic number", null)(pe.getOptionalHeader.getMagicNumber)

  private lazy val subsystem = safely[Subsystem]("subsystem", null)(pe.getOptionalHeader.getSubsystem)

  private lazy val machine = safely[MachineType]("machine type", null)(pe.getCOFFFileHeader.getMachineType)

  private lazy val isDll = safely("characteristics", false)(
    pe.getCOFFFileHeader.getCharacteristics.asScala.contains(FileCharacteristic.IMAGE_FILE_DLL))

  private lazy val hasOverlay = safely("overlay", false)(new Overlay(pe).exists())

  private lazy val hasRich = safely("rich header", false)(pe.maybeGetRichHeader().isPresent)

  def flag(name: String): Boolean = name match {
    case "dotnet" => isDotNet
    case "native" => pe != null && !isDotNet
    case "pe32" => magic == MagicNumber.PE32
    case "pe32+" => magic == MagicNumber.PE32_PLUS
    case "dll" => isDll
    case "driver" => subsystem == Subsystem.IMAGE_SUBSYSTEM_NATIVE
    case "console" => subsystem == Subsystem.IMAGE_SUBSYSTEM_WINDOWS_CUI
    case "gui" => subsystem == Subsystem.IMAGE_SUBSYSTEM_WINDOWS_GUI
    case "overlay" => hasOverlay
    case "signed" => dataDirectoryPresent(DataDirectoryKey.CERTIFICATE_TABLE)
    case "rich" => hasRich
    case "tls" => dataDirectoryPresent(DataDirectoryKey.TLS_TABLE)
    case "x86" => machine == MachineType.I386
    case "x64" => machine == MachineType.AMD64
    case other => throw new IllegalArgumentException("unknown requirement " + other)
  }

  private lazy val sectionNames: IndexedSeq[String] = safely("section names", IndexedSeq.empty[String])(
    pe.getSectionTable.getSectionHeaders.asScala.map(_.getName).toIndexedSeq)

  /** lower case DLL names and lower case DLL names with function names, "dll!function" */
  private lazy val imports: (Set[String], Set[String]) = safely("imports", (Set.empty[String], Set.empty[String])) {
    val dlls = pe.loadImports().asScala ++ pe.loadDelayLoadImports().asScala
    val names = dlls.map(_.getName.toLowerCase).toSet
    val functions = dlls.flatMap(d => d.getNameImports.asScala.map(i => d.getName.toLowerCase + "!" + i.getName)).toSet
    (names, functions)
  }

  private lazy val exports: Set[String] = safely("exports", Set.empty[String])(
    pe.loadExports().asScala.collect { case e: ExportNameEntry => e.name }.toSet)

  private lazy val versionStrings: Map[String, String] = safely("version info", Map.empty[String, String]) {
    val info = pe.loadVersionInfo()
    if (!info.isPresent) Map.empty
    else info.get.getVersionStrings.asScala.map { case (k, v) => k.toLowerCase -> v.replaceAll("\u0000+$", "") }.toMap
  }

  private def streamBytes(name: String): Array[Byte] =
    resolver.streamRegion(name).map(r => source.slice(r.start, r.end)).getOrElse(Array.emptyByteArray)

  private lazy val dotnetStrings: Set[String] = safely("#Strings", Set.empty[String]) {
    if (!isDotNet) Set.empty
    else new String(streamBytes("#Strings"), StandardCharsets.UTF_8).split("\u0000").filter(_.nonEmpty).toSet
  }

  private lazy val dotnetUserStrings: Set[String] = safely("#US", Set.empty[String]) {
    if (!isDotNet) Set.empty else UserStringsHeap(streamBytes("#US")).strings.toSet
  }

  private lazy val dotnetTypes: Set[String] = safely("TypeDef table", Set.empty[String]) {
    if (!isDotNet) Set.empty
    else {
      val stream = pe.loadClrSection().get.getMetadataRoot.maybeGetOptimizedStream
      if (!stream.isPresent) Set.empty
      else stream.get.getCLRTable(CLRTableType.TYPEDEF) match {
        case Some(table) =>
          def str(entry: io.github.struppigel.parser.sections.clr.CLRTableEntry, key: CLRTableKey): String =
            entry.get(key) match {
              // index 0 is the empty string
              case Some(f: CLRStringField) if f.getValue != 0 => try f.getString catch { case NonFatal(_) => "" }
              case _ => ""
            }
          table.entries.map { e =>
            val ns = str(e, CLRTableKey.TYPEDEF_TYPE_NAMESPACE)
            val name = str(e, CLRTableKey.TYPEDEF_TYPE_NAME)
            if (ns.isEmpty) name else ns + "." + name
          }.filter(_.nonEmpty).toSet
        case None => Set.empty
      }
    }
  }

  private def anyMatches(values: Iterable[String], v: ConditionValue, ignoreCase: Boolean): Boolean =
    values.exists(v.matches(_, ignoreCase))

  private def importMatches(v: ConditionValue): Boolean = {
    val (dlls, functions) = imports
    if (v.isRegex) dlls.exists(v.matches(_, ignoreCase = false)) || functions.exists(v.matches(_, ignoreCase = false))
    else {
      val bang = v.text.indexOf('!')
      if (bang < 0) dlls.contains(v.text.trim.toLowerCase)
      else functions.contains(v.text.substring(0, bang).trim.toLowerCase + "!" + v.text.substring(bang + 1).trim)
    }
  }

  private def resourceMatches(v: ConditionValue): Boolean = {
    val parts = v.text.split("/", -1).map(_.trim)
    resolver.hasResource(ResourceSelector(Glob(parts(0), caseSensitive = false),
      parts.lift(1).map(Glob(_, caseSensitive = false)), parts.lift(2).map(Glob(_, caseSensitive = false))))
  }

  /** true if all values of the condition hold */
  def holds(c: Condition): Boolean = c.values.forall { v =>
    val present = c.key match {
      case "requires" => flag(v.text)
      case "section" => anyMatches(sectionNames, v, ignoreCase = false)
      case "import" => importMatches(v)
      case "export" => anyMatches(exports, v, ignoreCase = false)
      case "resource" => resourceMatches(v)
      case "version_info" => versionStrings.get(c.argument.toLowerCase).exists(v.matches(_, ignoreCase = false))
      case "dotnet_string" => if (v.isRegex) anyMatches(dotnetStrings, v, ignoreCase = false) else dotnetStrings.contains(v.text)
      case "dotnet_us" => if (v.isRegex) anyMatches(dotnetUserStrings, v, ignoreCase = false) else dotnetUserStrings.contains(v.text)
      case "dotnet_type" => if (v.isRegex) anyMatches(dotnetTypes, v, ignoreCase = false) else dotnetTypes.contains(v.text)
      case other => throw new IllegalArgumentException("unknown condition " + other)
    }
    present != v.negated
  }

  /**
   * True if the condition can not hold because the file is no .NET file. Used
   * to skip signatures without parsing anything.
   */
  def excludedCheaply(c: Condition): Boolean = PEFacts.isCheapExclusion(c) && !resolver.hasClrDirectory
}

private[sigscanner] object PEFacts {

  private val logger = LogManager.getLogger(classOf[PEFacts].getName)

  /** true for 'requires = dotnet', which needs only a look at the data directory to be excluded */
  def isCheapExclusion(c: Condition): Boolean =
    c.key == "requires" && c.values.exists(v => !v.negated && v.text == "dotnet")

  /** relative cost of evaluating a condition, cheaper conditions are evaluated first */
  def cost(c: Condition): Int = c.key match {
    case "requires" => if (c.values.exists(v => v.text == "dotnet" || v.text == "native")) 3 else 0
    case "section" => 1
    case "import" | "export" => 2
    case "resource" | "version_info" => 3
    case _ => 4
  }
}
