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

import io.github.struppigel.parser.optheader.{DataDirectoryKey, StandardFieldEntryKey, WindowsEntryKey}
import io.github.struppigel.parser.sections.clr.CLIHeaderKey
import io.github.struppigel.parser.sections.debug.DebugDirectoryKey
import io.github.struppigel.parser.sections.edata.ExportNameEntry
import io.github.struppigel.parser.sections.rsrc.{ID, Level, Name}
import io.github.struppigel.parser.sections.{SectionCharacteristic, SectionHeaderKey, SectionLoader}
import io.github.struppigel.parser.{AnalysisInterruptedException, PEData}
import io.github.struppigel.tools.Overlay
import io.github.struppigel.tools.sigscanner._
import io.github.struppigel.tools.sigscanner.pattern.AddressMapper
import org.apache.logging.log4j.LogManager

import java.io.File
import scala.collection.JavaConverters._
import scala.collection.mutable
import scala.util.control.NonFatal

/**
 * Resolves scan locations to file regions. Each location kind is resolved
 * lazily on first use, so that e.g. scanning the entry point never parses
 * resources. Failures while resolving one kind are logged and yield no
 * regions for that kind only.
 *
 * @param fileLength size of the scanned data
 * @param name name of the scanned file for log messages
 * @param pe the parsed PE file, null for files that are not PE files
 */
private[sigscanner] final class RegionResolver(val fileLength: Long, val name: String, val pe: PEData) {

  import RegionResolver.logger



  /** location kinds that were resolved so far, for tests */
  val resolvedKinds: mutable.Set[LocationKind] = mutable.LinkedHashSet[LocationKind]()

  private lazy val loader: SectionLoader = new SectionLoader(pe)

  /** maps addresses for follow tokens */
  lazy val addressMapper: AddressMapper =
    if (pe == null) AddressMapper.Identity else new PEAddressMapper(pe, loader, fileLength)

  private case class SectionInfo(region: Region, name: String, index: Int, executable: Boolean,
    code: Boolean, containsEntryPoint: Boolean)

  private case class ResourceInfo(region: Region, types: List[String], names: List[String], languages: List[String])

  private case class ExportInfo(region: Region, name: String)

  private val cache = mutable.Map[LocationKind, IndexedSeq[_]]()

  /**
   * All regions of the location, ignoring its mode. EOF and FILE resolve to
   * the whole file, the mode determines which part is scanned.
   */
  def resolve(spec: LocationSpec): IndexedSeq[Region] = {
    if (pe == null && spec.kind.isPEOnly) return IndexedSeq.empty
    (spec.kind, spec.selector) match {
      case (LocationKind.SECTION, selector) =>
        val sections = cached(LocationKind.SECTION)(resolveSections())
        val selected = selector match {
          case AllSelector => sections
          case SectionNameSelector(glob) => sections.filter(s => glob.matches(s.name))
          case SectionIndexSelector(i) =>
            val idx = if (i < 0) sections.size + i else i
            sections.filter(_.index == idx)
          case ExecutableSectionSelector => sections.filter(_.executable)
          case CodeSectionSelector => sections.filter(_.code)
          case EntryPointSectionSelector => sections.filter(_.containsEntryPoint)
          case other => throw new IllegalArgumentException("invalid section selector " + other)
        }
        selected.map(_.region).filter(_.size > 0)
      case (LocationKind.RESOURCE, selector) =>
        val resources = cached(LocationKind.RESOURCE)(resolveResources())
        selector match {
          case AllSelector => resources.map(_.region)
          case ResourceSelector(t, n, l) =>
            resources.filter { r =>
              r.types.exists(t.matches) && n.forall(g => r.names.exists(g.matches)) &&
                l.forall(g => r.languages.exists(g.matches))
            }.map(_.region)
          case other => throw new IllegalArgumentException("invalid resource selector " + other)
        }
      case (LocationKind.EXPORT, selector) =>
        val exports = cached(LocationKind.EXPORT)(resolveExports())
        selector match {
          case ExportSelector(glob) => exports.filter(e => glob.matches(e.name)).map(_.region)
          case _ => exports.map(_.region)
        }
      case (LocationKind.DATA_DIRECTORY, DataDirectorySelector(key)) =>
        cached(LocationKind.DATA_DIRECTORY)(resolveDataDirectories()).filter(_._1 == key).map(_._2)
      case (LocationKind.DOTNET_STREAM, StreamSelector(name)) =>
        cached(LocationKind.DOTNET_STREAM)(resolveStreams()).filter(_._1 == name).map(_._2)
      case (kind, _) => cached(kind)(resolveSimple(kind))
    }
  }

  /** true if a resource matches the selector, used by the resource condition */
  def hasResource(selector: ResourceSelector): Boolean =
    pe != null && cached(LocationKind.RESOURCE)(resolveResources()).exists { r =>
      r.types.exists(selector.resourceType.matches) && selector.name.forall(g => r.names.exists(g.matches)) &&
        selector.language.forall(g => r.languages.exists(g.matches))
    }

  /** the region of a .NET metadata stream */
  def streamRegion(name: String): Option[Region] =
    if (pe == null) None
    else cached(LocationKind.DOTNET_STREAM)(resolveStreams()).find(_._1 == name).map(_._2)

  /** true if the PE file has a CLR runtime header data directory, cheaper than loading the CLR section */
  def hasClrDirectory: Boolean = pe != null && dataDirectory(DataDirectoryKey.CLR_RUNTIME_HEADER).isDefined

  private def cached[T](kind: LocationKind)(compute: => IndexedSeq[T]): IndexedSeq[T] =
    cache.getOrElseUpdate(kind, {
      resolvedKinds += kind
      try compute
      catch {
        case e: AnalysisInterruptedException => throw e
        case NonFatal(e) =>
          logger.warn(s"could not resolve location ${kind.keyword} of $name: $e")
          IndexedSeq.empty
      }
    }).asInstanceOf[IndexedSeq[T]]

  /** a region clipped to the file, None if it is empty */
  private def region(kind: LocationKind, label: String, start: Long, end: Long): Option[Region] = {
    val s = math.max(0L, start)
    val e = math.min(fileLength, end)
    if (s < e) Some(Region(kind, label, s, e)) else None
  }

  private lazy val overlay: Option[Long] = {
    val o = new Overlay(pe)
    if (o.exists()) Some(o.getOffset) else None
  }

  private def resolveSimple(kind: LocationKind): IndexedSeq[Region] = (kind match {
    case LocationKind.FILE => region(kind, "file", 0, fileLength)
    case LocationKind.EOF => region(kind, "eof", 0, fileLength)
    case LocationKind.IMAGE => region(kind, "image", 0, overlay.getOrElse(fileLength))
    case LocationKind.OVERLAY => overlay.flatMap(region(kind, "overlay", _, fileLength))
    case LocationKind.MSDOS_HEADER => region(kind, "msdos_header", 0, 0x40)
    case LocationKind.MSDOS_STUB => region(kind, "msdos_stub", 0x40, pe.getPESignature.getOffset)
    case LocationKind.RICH_HEADER =>
      val rich = pe.maybeGetRichHeader()
      if (rich.isPresent) {
        val loc = rich.get.getPhysicalLocation()
        region(kind, "rich_header", loc.from, loc.from + loc.size)
      } else None
    case LocationKind.HEADERS =>
      region(kind, "headers", 0, pe.getOptionalHeader.get(WindowsEntryKey.SIZE_OF_HEADERS))
    case LocationKind.ENTRY_POINT => entryPoint.flatMap { case (offset, end) => region(kind, "entrypoint", offset, end) }
    case LocationKind.CERTIFICATE =>
      dataDirectory(DataDirectoryKey.CERTIFICATE_TABLE).flatMap { case (va, size) =>
        // the address of the certificate table is a file offset
        region(kind, "certificate", va, va + size)
      }
    case LocationKind.DEBUG_DATA => None
    case LocationKind.DOTNET => metadata.flatMap { case (_, offset, size) => region(kind, "dotnet", offset, offset + size) }
    case LocationKind.METADATA => None
    case other => throw new IllegalArgumentException("not a simple location: " + other)
  }).toIndexedSeq ++ (if (kind == LocationKind.DEBUG_DATA) resolveDebugData() else Nil)

  /** file offset of the entry point and end of its section, None if there is no entry point */
  lazy val entryPoint: Option[(Long, Long)] = {
    if (pe == null) None
    else {
      val rva = pe.getOptionalHeader.get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT)
      if (rva == 0) None
      else {
        val maybeOffset = loader.maybeGetFileOffset(rva)
        if (!maybeOffset.isPresent) None
        else {
          val offset: Long = maybeOffset.get
          Some((offset, endOfContainingSection(rva, offset)))
        }
      }
    }
  }

  /** end of the raw data of the section that contains the address, or end of file */
  private def endOfContainingSection(rva: Long, offset: Long): Long = {
    val header = loader.maybeGetSectionHeaderByRVA(rva)
    if (header.isPresent) {
      val start = header.get.getAlignedPointerToRaw(pe.getOptionalHeader.isLowAlignmentMode)
      val end = start + loader.getReadSize(header.get)
      if (offset >= start && offset < end) end else fileLength
    } else fileLength
  }

  private def resolveSections(): IndexedSeq[SectionInfo] = {
    val lowAlign = pe.getOptionalHeader.isLowAlignmentMode
    val epRva = pe.getOptionalHeader.get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT)
    val epSection = if (epRva == 0) None else {
      val h = loader.maybeGetSectionHeaderByRVA(epRva)
      if (h.isPresent) Some(h.get.getNumber) else None
    }
    pe.getSectionTable.getSectionHeaders.asScala.zipWithIndex.flatMap { case (header, index) =>
      val name = header.getName
      val start = header.getAlignedPointerToRaw(lowAlign)
      val end = start + loader.getReadSize(header)
      val characteristics = header.getCharacteristics.asScala
      val label = if (name.isEmpty) s"section(#$index)" else s"section($name)"
      Some(SectionInfo(
        region(LocationKind.SECTION, label, start, end).getOrElse(Region(LocationKind.SECTION, label, start, start)),
        name, index,
        characteristics.contains(SectionCharacteristic.IMAGE_SCN_MEM_EXECUTE),
        characteristics.contains(SectionCharacteristic.IMAGE_SCN_CNT_CODE),
        epSection.contains(header.getNumber)))
    }.toIndexedSeq
  }

  private def resolveResources(): IndexedSeq[ResourceInfo] = {
    pe.loadResources().asScala.flatMap { resource =>
      val loc = resource.rawBytesLocation
      val ids = resource.levelIDs
      def idStrings(level: Level, symbolic: Boolean): List[String] = ids.get(level) match {
        case Some(id: ID) => if (symbolic) List(id.idString, id.id.toString).distinct else List(id.id.toString)
        case Some(Name(_, name)) => List(name)
        case _ => Nil
      }
      val types = idStrings(Level.typeLevel(), symbolic = true)
      val names = idStrings(Level.nameLevel(), symbolic = false)
      val languages = idStrings(Level.languageLevel(), symbolic = false)
      val label = "resource(" + (types.headOption.toList ++ names.headOption ++ languages.headOption).mkString("/") + ")"
      if (loc.from <= 0 || loc.size <= 0) None
      else region(LocationKind.RESOURCE, label, loc.from, loc.from + loc.size).map(ResourceInfo(_, types, names, languages))
    }.toIndexedSeq
  }

  private def resolveExports(): IndexedSeq[ExportInfo] = {
    pe.loadExports().asScala.filterNot(_.forwarded).flatMap { e =>
      val name = e match {
        case n: ExportNameEntry => n.name
        case _ => "#" + e.ordinal
      }
      val maybeOffset = loader.maybeGetFileOffset(e.symbolRVA)
      if (!maybeOffset.isPresent || e.symbolRVA == 0) None
      else {
        val offset: Long = maybeOffset.get
        region(LocationKind.EXPORT, s"export($name)", offset, endOfContainingSection(e.symbolRVA, offset)).map(ExportInfo(_, name))
      }
    }.toIndexedSeq
  }

  /** virtual address and size of a data directory entry, None if it is empty */
  private def dataDirectory(key: DataDirectoryKey): Option[(Long, Long)] = {
    val entry = pe.getOptionalHeader.maybeGetDataDirEntry(key)
    if (entry.isPresent && entry.get.getVirtualAddress != 0 && entry.get.getDirectorySize != 0)
      Some((entry.get.getVirtualAddress, entry.get.getDirectorySize))
    else None
  }

  private def resolveDataDirectories(): IndexedSeq[(DataDirectoryKey, Region)] = {
    DataDirectoryKey.values().toIndexedSeq.flatMap { key =>
      dataDirectory(key).flatMap { case (va, size) =>
        val offset = if (key == DataDirectoryKey.CERTIFICATE_TABLE) Some(va) else {
          val o = loader.maybeGetFileOffset(va)
          if (o.isPresent) Some(o.get.longValue) else None
        }
        offset.flatMap(o => region(LocationKind.DATA_DIRECTORY, s"datadir(${key.name})", o, o + size)).map((key, _))
      }
    }
  }

  private def resolveDebugData(): IndexedSeq[Region] = {
    val debug = loader.maybeLoadDebugSection()
    if (!debug.isPresent) IndexedSeq.empty
    else debug.get.getEntries.asScala.flatMap { entry =>
      val offset: Long = entry.get(DebugDirectoryKey.POINTER_TO_RAW_DATA)
      val size: Long = entry.get(DebugDirectoryKey.SIZE_OF_DATA)
      if (offset == 0 || size == 0) None
      else region(LocationKind.DEBUG_DATA, s"debug_data(${entry.getDebugType})", offset, offset + size)
    }.toIndexedSeq
  }

  /** RVA, file offset and size of the .NET metadata */
  private lazy val metadata: Option[(Long, Long, Long)] = {
    if (pe == null || dataDirectory(DataDirectoryKey.CLR_RUNTIME_HEADER).isEmpty) None
    else {
      val clr = pe.loadClrSection()
      if (!clr.isPresent) None
      else {
        val header = clr.get.getCliHeaderEntries
        val rva = header.get(CLIHeaderKey.META_DATA_RVA).getValue
        val size = header.get(CLIHeaderKey.META_DATA_SIZE).getValue
        val offset = loader.maybeGetFileOffset(rva)
        if (offset.isPresent && size > 0) Some((rva, offset.get.longValue, size)) else None
      }
    }
  }

  private def resolveStreams(): IndexedSeq[(String, Region)] = {
    metadata.toIndexedSeq.flatMap { case (rva, _, _) =>
      pe.loadClrSection().get.getMetadataRoot.getStreamHeaders.asScala.flatMap { stream =>
        val offset = loader.maybeGetFileOffset(rva + stream.offset)
        if (!offset.isPresent || stream.size <= 0) None
        else {
          val o: Long = offset.get
          region(LocationKind.DOTNET_STREAM, s"dotnet_stream(${stream.name})", o, o + stream.size).map((stream.name, _))
        }
      }
    }
  }
}

private[sigscanner] object RegionResolver {
  private val logger = LogManager.getLogger(classOf[RegionResolver].getName)
}

/**
 * Maps addresses of a PE file the same way the SectionLoader does.
 * <p>
 * The results are cached, because the lookups of the SectionLoader are not
 * cheap and the follow tokens of many signatures map the same addresses, e.g.
 * the target of a call at the entry point.
 */
private[sigscanner] final class PEAddressMapper(pe: PEData, loader: SectionLoader, fileLength: Long) extends AddressMapper {

  override val imageBase: Long = pe.getOptionalHeader.get(WindowsEntryKey.IMAGE_BASE)

  private val rvas = mutable.LongMap.empty[Long]
  private val offsets = mutable.LongMap.empty[Long]

  private def cached(cache: mutable.LongMap[Long], key: Long)(compute: => Long): Long =
    cache.getOrElse(key, {
      // searches with follow tokens may map an address per position, so the caches are bounded
      if (cache.size >= PEAddressMapper.MaxCached) cache.clear()
      val value = compute
      cache.update(key, value)
      value
    })

  override def offsetToRva(offset: Long): Long = cached(rvas, offset)(computeOffsetToRva(offset))

  override def rvaToOffset(rva: Long): Long = cached(offsets, rva)(computeRvaToOffset(rva))

  private def computeOffsetToRva(offset: Long): Long = {
    if (offset < 0 || offset >= fileLength) return -1
    val header = loader.maybeGetSectionHeaderByOffset(offset)
    if (header.isPresent) {
      val h = header.get
      offset + h.get(SectionHeaderKey.VIRTUAL_ADDRESS) - h.get(SectionHeaderKey.POINTER_TO_RAW_DATA)
    } else offset
  }

  private def computeRvaToOffset(rva: Long): Long = {
    if (rva < 0) return -1
    val offset = loader.maybeGetFileOffset(rva)
    if (offset.isPresent && offset.get < fileLength) offset.get else -1
  }
}

private[sigscanner] object PEAddressMapper {
  val MaxCached = 4096
}
