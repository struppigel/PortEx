/**
 * *****************************************************************************
 * Copyright 2022 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */
package io.github.struppigel.tools.anomalies

import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.parser.ScalaIOUtil.filteredString
import io.github.struppigel.parser.StandardField
import io.github.struppigel.parser.PhysicalLocation
import io.github.struppigel.parser.sections.SectionCharacteristic
import io.github.struppigel.parser.coffheader.FileCharacteristic
import io.github.struppigel.parser.optheader.DataDirectoryKey
import io.github.struppigel.parser.sections.SectionLoader
import io.github.struppigel.parser.sections.clr.{CLIHeaderKey, CLRBlobField, CLRCodedIndexField, CLRSection, CLRStringField, CLRTableEntry, CLRTableKey, CLRTableType, MetadataRootKey, OptimizedStreamKey}

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

/**
 * Scans the .NET related structures for anomalies
 */
trait ClrScanning extends AnomalyScanner {
  abstract override def scanReport(): String =
    "Applied CLR Anomaly Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val clr = new SectionLoader(data).maybeLoadCLRSection()
    val anomalyList = ListBuffer[Anomaly]()
    if (clr.isPresent) {
      anomalyList ++= checkStreamHeaders(clr.get)
      anomalyList ++= checkStringsHeap(clr.get)
      anomalyList ++= checkVersionStringNotReadable(clr.get)
      anomalyList ++= checkCliHeader(clr.get)
      anomalyList ++= checkMetadataRootFields(clr.get)
      anomalyList ++= checkTablesStreamHeader(clr.get)
      anomalyList ++= checkDataDirectories()
      anomalyList ++= checkStreamSizesNamesAndHeapStarts(clr.get)
      anomalyList ++= checkImports(clr.get)
      anomalyList ++= checkMethodHeaders(clr.get)
      anomalyList ++= checkHeaderSection(clr.get)
      anomalyList ++= checkTables(clr.get)
    }
    super.scan ::: anomalyList.toList
  }

  /**
   * [ERROR] rules of ECMA-335 II.22 that can be checked on the tables alone, evidence in the Javadoc of the subtypes.
   * Fields of rows are reported once per kind of table, for the first row, with the count in the description.
   */
  private def checkTables(clr: CLRSection): List[Anomaly] = {
    val maybeStream = clr.getMetadataRoot.maybeGetOptimizedStream
    if (!maybeStream.isPresent) return Nil
    val stream = maybeStream.get
    def table(tableType: CLRTableType): List[CLRTableEntry] =
      stream.getCLRTable(tableType).map(_.entries).getOrElse(Nil)
    def stringEntry(entry: CLRTableEntry, key: CLRTableKey): Option[Array[Byte]] = entry.get(key) match {
      case Some(f: CLRStringField) => f.strIdx.stringsHeap.flatMap(_.rawAt(f.strIdx.getIndex))
      case _ => None
    }
    def stringIndex(entry: CLRTableEntry, key: CLRTableKey): Long = entry.get(key).map(_.getValue).getOrElse(0L)
    def anomalyFor(entry: CLRTableEntry, key: CLRTableKey, description: String, subtype: AnomalySubType): List[Anomaly] =
      entry.get(key).map(_.toStandardField()).map { f =>
        if (subtype.getSuperType == AnomalyType.STRUCTURE)
          StructureAnomaly(PEStructureKey.CLR_SECTION, description, subtype,
            List(new PhysicalLocation(f.getOffset, f.getSize)))
        else FieldAnomaly(f, description, subtype)
      }.toList

    // row counts
    val valid = stream.entries(OptimizedStreamKey.VALID).getValue
    val sizes = stream.getTableIndicesToSizesMap()
    def rowCountLocation(tableIndex: Int): List[PhysicalLocation] =
      if (sizes.contains(tableIndex))
        List(new PhysicalLocation(stream.getRawOffset + 24 + 4L * java.lang.Long.bitCount(valid & ((1L << tableIndex) - 1)), 4))
      else List(new PhysicalLocation(stream.getRawOffset + 8, 8))
    val moduleRows = sizes.getOrElse(CLRTableType.MODULE.getIndex, 0)
    val moduleCount = if (moduleRows != 1)
      List(StructureAnomaly(PEStructureKey.CLR_SECTION, s"The Module table has $moduleRows rows, it must have exactly one",
        AnomalySubType.CLR_MODULE_ROW_COUNT, rowCountLocation(CLRTableType.MODULE.getIndex))) else Nil
    val assemblyRows = sizes.getOrElse(CLRTableType.ASSEMBLY.getIndex, 0)
    val assemblyCount = if (assemblyRows > 1)
      List(StructureAnomaly(PEStructureKey.CLR_SECTION, s"The Assembly table has $assemblyRows rows, it can have at most one",
        AnomalySubType.CLR_MULTIPLE_ASSEMBLY_ROWS, rowCountLocation(CLRTableType.ASSEMBLY.getIndex))) else Nil

    // empty names
    def emptyNames(tableType: CLRTableType, key: CLRTableKey, tableName: String, nullAllowed: Boolean): List[Anomaly] = {
      val rows = table(tableType).filter { e =>
        stringEntry(e, key).exists(_.isEmpty) && !(nullAllowed && stringIndex(e, key) == 0)
      }
      rows.headOption.toList.flatMap(first => anomalyFor(first, key,
        s"${rows.size} rows of the $tableName table have an empty name or namespace", AnomalySubType.CLR_EMPTY_NAME))
    }
    val emptyNameAnomalies =
      emptyNames(CLRTableType.MODULE, CLRTableKey.MODULE_NAME, "Module", nullAllowed = false) :::
        emptyNames(CLRTableType.ASSEMBLY, CLRTableKey.ASSEMBLY_NAME, "Assembly", nullAllowed = false) :::
        emptyNames(CLRTableType.TYPEDEF, CLRTableKey.TYPEDEF_TYPE_NAME, "TypeDef", nullAllowed = false) :::
        emptyNames(CLRTableType.TYPEDEF, CLRTableKey.TYPEDEF_TYPE_NAMESPACE, "TypeDef", nullAllowed = true) :::
        emptyNames(CLRTableType.METHODDEF, CLRTableKey.METHOD_NAME, "MethodDef", nullAllowed = false) :::
        emptyNames(CLRTableType.FIELD, CLRTableKey.FIELD_NAME, "Field", nullAllowed = false)

    // Module row
    val moduleAnomalies = table(CLRTableType.MODULE).headOption.toList.flatMap { module =>
      val nullMvid = if (stringIndex(module, CLRTableKey.MODULE_MVID) == 0)
        anomalyFor(module, CLRTableKey.MODULE_MVID, "The Mvid of the Module row is null", AnomalySubType.CLR_NULL_MVID)
      else Nil
      val reserved = List(CLRTableKey.MODULE_GENERATION, CLRTableKey.MODULE_ENCID, CLRTableKey.MODULE_ENCBASEID)
        .filter(stringIndex(module, _) != 0)
        .flatMap(key => anomalyFor(module, key, s"The reserved column $key of the Module row must be zero",
          AnomalySubType.CLR_MODULE_RESERVED_SET))
      nullMvid ::: reserved
    }

    // duplicate TypeDef rows, nested types (visibility above Public) are not compared
    val typeDefs = table(CLRTableType.TYPEDEF)
    val notNested = typeDefs.filter(e => (stringIndex(e, CLRTableKey.TYPEDEF_FLAGS) & 0x7) < 2)
    val duplicates = notNested.groupBy(e => (
      stringEntry(e, CLRTableKey.TYPEDEF_TYPE_NAMESPACE).map(_.toSeq),
      stringEntry(e, CLRTableKey.TYPEDEF_TYPE_NAME).map(_.toSeq)))
      .filter { case ((ns, name), rows) => ns.isDefined && name.isDefined && rows.size > 1 }.values.toList
    val duplicateAnomalies = duplicates.sortBy(_.head.row).headOption.toList.flatMap { rows =>
      anomalyFor(rows.head, CLRTableKey.TYPEDEF_TYPE_NAME,
        s"${duplicates.map(_.size).sum} TypeDef rows are duplicates, e.g. ${rows.size} rows with the name of row ${rows.head.row}",
        AnomalySubType.CLR_DUPLICATE_TYPEDEF)
    }

    // inheritance loops through TypeDef rows
    val extendsRow: Map[Int, Int] = typeDefs.flatMap { e =>
      e.get(CLRTableKey.TYPEDEF_EXTENDS) match {
        case Some(c: CLRCodedIndexField)
          if c.codedTokenIndex.getReferencedTableType.equals(java.util.Optional.of(CLRTableType.TYPEDEF)) =>
          Some(e.row -> c.codedTokenIndex.getIndex)
        case _ => None
      }
    }.toMap
    val state = scala.collection.mutable.Map[Int, Int]() // 1 on the current path, 2 ends, 3 leads into a loop
    for (start <- typeDefs.map(_.row) if !state.contains(start)) {
      val path = ListBuffer[Int]()
      var current: Option[Int] = Some(start)
      var result = 2
      while (current.isDefined) {
        val row = current.get
        state.get(row) match {
          case Some(1) => result = 3; current = None
          case Some(known) => result = known; current = None
          case None => state(row) = 1; path += row; current = extendsRow.get(row)
        }
      }
      path.foreach(state(_) = result)
    }
    val loopRows = typeDefs.filter(e => state.get(e.row).contains(3))
    val loopAnomalies = loopRows.headOption.toList.flatMap(first => anomalyFor(first, CLRTableKey.TYPEDEF_EXTENDS,
      s"${loopRows.size} TypeDef rows extend a loop of types, starting with row ${first.row}",
      AnomalySubType.CLR_INHERITANCE_LOOP))

    moduleCount ::: assemblyCount ::: emptyNameAnomalies ::: moduleAnomalies ::: duplicateAnomalies ::: loopAnomalies :::
      checkTypeDefRules(typeDefs, sizes, table(CLRTableType.METHODDEF), stringEntry, stringIndex, anomalyFor)
  }

  /**
   * TypeDef list indices and Extends, MethodDef flags and duplicate methods (II.22.37, II.22.26). Method rows have
   * the type whose MethodList run contains them as owner.
   */
  private def checkTypeDefRules(typeDefs: List[CLRTableEntry], sizes: Map[Int, Int], methods: List[CLRTableEntry],
                                stringEntry: (CLRTableEntry, CLRTableKey) => Option[Array[Byte]],
                                value: (CLRTableEntry, CLRTableKey) => Long,
                                anomalyFor: (CLRTableEntry, CLRTableKey, String, AnomalySubType) => List[Anomaly]): List[Anomaly] = {
    def rows(tableType: CLRTableType): Long = sizes.getOrElse(tableType.getIndex, 0).toLong
    def firstOf(entries: List[CLRTableEntry], key: CLRTableKey, text: String, subtype: AnomalySubType): List[Anomaly] =
      entries.headOption.toList.flatMap(first => anomalyFor(first, key, s"${entries.size} rows: $text", subtype))

    // FieldList and MethodList, valid is 1 up to the row count + 1, 0 is null
    val badFieldList = typeDefs.filter(e => value(e, CLRTableKey.TYPEDEF_FIELDLIST) > rows(CLRTableType.FIELD) + 1)
    val badMethodList = typeDefs.filter(e => value(e, CLRTableKey.TYPEDEF_METHODLIST) > rows(CLRTableType.METHODDEF) + 1)
    val listAnomalies =
      firstOf(badFieldList, CLRTableKey.TYPEDEF_FIELDLIST, "the field list points behind the Field table",
        AnomalySubType.CLR_INVALID_LIST_INDEX) :::
        firstOf(badMethodList, CLRTableKey.TYPEDEF_METHODLIST, "the method list points behind the MethodDef table",
          AnomalySubType.CLR_INVALID_LIST_INDEX)

    // Extends: TypeDefOrRef coded index, 2 bits tag
    val referencedRows = Map(0L -> rows(CLRTableType.TYPEDEF), 1L -> rows(CLRTableType.TYPEREF), 2L -> rows(CLRTableType.TYPESPEC))
    def isSystemObject(e: CLRTableEntry): Boolean =
      stringEntry(e, CLRTableKey.TYPEDEF_TYPE_NAME).exists(n => new String(n, "UTF-8") == "Object") &&
        stringEntry(e, CLRTableKey.TYPEDEF_TYPE_NAMESPACE).exists(n => new String(n, "UTF-8") == "System")
    val badExtends = typeDefs.filter { e =>
      val flags = value(e, CLRTableKey.TYPEDEF_FLAGS)
      val token = value(e, CLRTableKey.TYPEDEF_EXTENDS)
      val index = token >> 2
      val interface = (flags & 0x20) != 0
      val missingBase = !interface && index == 0 && e.row != 1 && !isSystemObject(e)
      val interfaceWithBase = interface && index != 0
      val behindTable = index != 0 && referencedRows.get(token & 3).forall(index > _)
      missingBase || interfaceWithBase || behindTable
    }
    val extendsAnomalies = firstOf(badExtends, CLRTableKey.TYPEDEF_EXTENDS,
      "the Extends column does not follow the rules for classes and interfaces", AnomalySubType.CLR_INVALID_EXTENDS)

    // MethodDef flags, II.23.1.10
    def invalidFlags(f: Long): Boolean = {
      val access = f & 0x7
      val static = (f & 0x10) != 0; val fin = (f & 0x20) != 0; val virtual = (f & 0x40) != 0
      val newSlot = (f & 0x100) != 0; val strict = (f & 0x200) != 0; val abstr = (f & 0x400) != 0
      val special = (f & 0x800) != 0; val rtSpecial = (f & 0x1000) != 0; val pinvoke = (f & 0x2000) != 0
      access == 7 || (static && (fin || virtual || newSlot)) || (fin && abstr) || (abstr && pinvoke) ||
        (access == 0 && (special || rtSpecial)) || (abstr && !virtual) || (rtSpecial && !special) ||
        ((fin || newSlot || strict) && !virtual) || (pinvoke && virtual)
    }
    val badFlags = methods.filter(e => invalidFlags(value(e, CLRTableKey.METHOD_FLAGS)))
    val flagAnomalies = firstOf(badFlags, CLRTableKey.METHOD_FLAGS, "the method flags are contradictory",
      AnomalySubType.CLR_INVALID_METHOD_FLAGS)

    // duplicate methods of the same owner
    // the loop is bound by the rows that were read, the row count of a malformed header can be huge
    val methodRows = methods.size
    val owners = scala.collection.mutable.Map[Int, Int]()
    for ((type_, i) <- typeDefs.zipWithIndex) {
      val start = value(type_, CLRTableKey.TYPEDEF_METHODLIST).toInt
      val end = if (i + 1 < typeDefs.size) math.min(methodRows + 1L, value(typeDefs(i + 1), CLRTableKey.TYPEDEF_METHODLIST)).toInt
      else methodRows + 1
      for (row <- math.max(1, start) until end) owners.getOrElseUpdate(row, type_.row)
    }
    def signature(e: CLRTableEntry): Option[Seq[Byte]] = e.get(CLRTableKey.METHOD_SIGNATURE) match {
      case Some(f: CLRBlobField) if f.blobIdx.getValue.isPresent => Some(f.blobIdx.getValue.get.toSeq)
      case _ => None
    }
    val duplicates = methods.filter(e => (value(e, CLRTableKey.METHOD_FLAGS) & 0x7) != 0 && owners.contains(e.row))
      .groupBy(e => (owners(e.row), stringEntry(e, CLRTableKey.METHOD_NAME).map(_.toSeq), signature(e)))
      .filter { case ((_, name, sig), group) => name.isDefined && sig.isDefined && group.size > 1 }.values.toList
    val duplicateAnomalies = duplicates.sortBy(_.head.row).headOption.toList.flatMap { group =>
      anomalyFor(group.head, CLRTableKey.METHOD_NAME,
        s"${duplicates.map(_.size).sum} MethodDef rows are duplicates of a method of the same type, e.g. ${group.size} like row ${group.head.row}",
        AnomalySubType.CLR_DUPLICATE_METHOD)
    }

    listAnomalies ::: extendsAnomalies ::: flagAnomalies ::: duplicateAnomalies
  }

  private def checkHeaderSection(clr: CLRSection): List[Anomaly] = {
    val entry = data.getOptionalHeader.maybeGetDataDirEntry(DataDirectoryKey.CLR_RUNTIME_HEADER)
    if (!entry.isPresent) return Nil
    val section = new SectionLoader(data).maybeGetSectionHeaderByRVA(entry.get.getVirtualAddress)
    if (!section.isPresent || !section.get.getCharacteristics.contains(SectionCharacteristic.IMAGE_SCN_MEM_WRITE)) return Nil
    val start = clr.cliHeader(CLIHeaderKey.CB).getOffset
    List(StructureAnomaly(PEStructureKey.CLR_SECTION,
      s"The CLI header is in the writeable section ${section.get.getName}, it should be in a read-only section",
      AnomalySubType.CLR_HEADER_IN_WRITEABLE_SECTION, List(new PhysicalLocation(start, cliHeaderSize))))
  }

  /**
   * First byte of the body of every IL method (II.25.4). Methods with native code, as in mixed mode images, are
   * skipped. One anomaly per subtype, for the first method that has it, the description gives the count.
   */
  private def checkMethodHeaders(clr: CLRSection): List[Anomaly] = {
    val stream = clr.getMetadataRoot.maybeGetOptimizedStream
    if (!stream.isPresent) return Nil
    val table = stream.get.getCLRTable(CLRTableType.METHODDEF)
    if (table.isEmpty) return Nil
    val loader = new SectionLoader(data)
    val raf = scala.util.Try(new java.io.RandomAccessFile(data.getFile, "r")).toOption
    if (raf.isEmpty) return Nil
    try {
      val invalid, unusualSize, misaligned = ListBuffer[CLRTableEntry]()
      for (entry <- table.get.entries) {
        val rva = entry.get(CLRTableKey.METHOD_RVA).map(_.getValue).getOrElse(0L)
        val implFlags = entry.get(CLRTableKey.METHOD_IMPLFLAGS).map(_.getValue).getOrElse(0L)
        val isManagedIl = (implFlags & 0x3) == 0 && (implFlags & 0x4) == 0
        val offset = if (rva != 0 && isManagedIl) loader.maybeGetFileOffset(rva) else java.util.Optional.empty[java.lang.Long]()
        if (offset.isPresent) {
          raf.get.seek(offset.get)
          val first = raf.get.read()
          val second = raf.get.read()
          if (first >= 0 && second >= 0) {
            (first & 0x3) match {
              case 3 =>
                if (((first | (second << 8)) >> 12) != 3) unusualSize += entry
                if (rva % 4 != 0) misaligned += entry
              case 2 =>
              case _ => invalid += entry
            }
          }
        }
      }
      def report(entries: ListBuffer[CLRTableEntry], subtype: AnomalySubType, text: String): List[Anomaly] =
        entries.headOption.flatMap(_.get(CLRTableKey.METHOD_RVA)).map(f =>
          FieldAnomaly(f.toStandardField(), s"$text, ${entries.size} methods are affected", subtype)).toList
      report(invalid, AnomalySubType.CLR_INVALID_METHOD_HEADER, "A method header is neither tiny nor fat") :::
        report(unusualSize, AnomalySubType.CLR_INVALID_FAT_HEADER_SIZE, "The size of a fat method header is not 3") :::
        report(misaligned, AnomalySubType.CLR_MISALIGNED_FAT_HEADER, "A fat method header is not 4-byte aligned")
    } finally raf.get.close()
  }

  /**
   * Import table of a pure .NET image (II.25.3.1). Images that are not IL only, mixed mode and ReadyToRun,
   * import more than mscoree.dll and are not checked. Only the first descriptor is checked for its content.
   */
  private def checkImports(clr: CLRSection): List[Anomaly] = {
    val ilOnly = clr.cliHeader.get(CLIHeaderKey.FLAGS).exists(f => (f.getValue & 0x1) != 0)
    if (!ilOnly) return Nil
    val maybeImports = new SectionLoader(data).maybeLoadImportSection()
    if (!maybeImports.isPresent) return Nil
    val imports = maybeImports.get.getImports.asScala.toList
    if (imports.isEmpty) return Nil
    val first = imports.head
    val isDll = data.getCOFFFileHeader.hasCharacteristic(FileCharacteristic.IMAGE_FILE_DLL)
    val expectedSymbol = if (isDll) "_CorDllMain" else "_CorExeMain"
    val multiple = if (imports.size > 1)
      List(ImportAnomaly(imports, s"There are ${imports.size} imported DLLs, a .NET image has only mscoree.dll",
        AnomalySubType.CLR_MULTIPLE_IMPORT_DESCRIPTORS, PEStructureKey.IMPORT_SECTION)) else Nil
    val dll = if (!first.getName.equalsIgnoreCase("mscoree.dll"))
      List(ImportAnomaly(List(first), s"The imported DLL is ${first.getName}, a .NET image imports mscoree.dll",
        AnomalySubType.CLR_INVALID_IMPORT_DLL, PEStructureKey.IMPORT_DLL)) else Nil
    val nameImports = first.getNameImports.asScala.toList
    val symbols = if (first.getOrdinalImports.size > 0 || nameImports.exists(_.getName != expectedSymbol))
      List(ImportAnomaly(List(first), s"A .NET image has to import $expectedSymbol by name from ${first.getName}",
        AnomalySubType.CLR_INVALID_IMPORT_SYMBOL, PEStructureKey.IMPORT_DLL)) else Nil
    val hints = if (nameImports.exists(_.getHint != 0))
      List(ImportAnomaly(List(first), s"The hint of the import from ${first.getName} is not 0",
        AnomalySubType.CLR_NONZERO_IMPORT_HINT, PEStructureKey.IMPORT_DLL)) else Nil
    multiple ::: dll ::: symbols ::: hints
  }

  private val knownStreamNames = Set("#~", "#-", "#Strings", "#US", "#Blob", "#GUID")
  private val heapsStartingWithEmptyEntry = Set("#Strings", "#US", "#Blob")

  private def firstByteOf(file: java.io.File, offset: Long): Option[Int] =
    scala.util.Try {
      val raf = new java.io.RandomAccessFile(file, "r")
      try { raf.seek(offset); raf.read() } finally raf.close()
    }.toOption.filter(_ >= 0)

  private def checkStreamSizesNamesAndHeapStarts(clr: CLRSection): List[Anomaly] = {
    val root = clr.metadataRoot
    root.streamHeaders.flatMap { header =>
      val notAligned = if (header.size % 4 != 0)
        List(ClrStreamAnomaly(root, header, s"The size of stream ${header.name} is not a multiple of 4",
          AnomalySubType.CLR_STREAM_SIZE_NOT_ALIGNED)) else Nil
      val unusualName = if (!knownStreamNames.contains(header.name))
        List(ClrStreamAnomaly(root, header, s"The stream name ${header.name} is not one of the defined names",
          AnomalySubType.CLR_UNUSUAL_STREAM_NAME)) else Nil
      val firstEntry = if (heapsStartingWithEmptyEntry.contains(header.name) && header.size > 0 &&
        firstByteOf(data.getFile, root.getBSJBOffset + header.offset).exists(_ != 0))
        List(ClrStreamAnomaly(root, header, s"The first entry of heap ${header.name} is not empty",
          AnomalySubType.CLR_HEAP_FIRST_ENTRY_NOT_EMPTY)) else Nil
      notAligned ::: unusualName ::: firstEntry
    }
  }

  /**
   * Data directories that ECMA-335 II.25.2.3.3 specifies as always 0. Resource, certificate and debug are left out,
   * nearly all shipped assemblies have them, architecture, global ptr and reserved are reported elsewhere.
   */
  private def checkDataDirectories(): List[Anomaly] = {
    def check(key: DataDirectoryKey, subtype: AnomalySubType): List[Anomaly] = {
      val entry = data.getOptionalHeader.maybeGetDataDirEntry(key)
      if (entry.isPresent && (entry.get.getVirtualAddress != 0 || entry.get.getDirectorySize != 0))
        List(DataDirAnomaly(entry.get, s"The data directory $key of a .NET image must be 0", subtype))
      else Nil
    }
    List(DataDirectoryKey.EXPORT_TABLE, DataDirectoryKey.EXCEPTION_TABLE, DataDirectoryKey.TLS_TABLE,
      DataDirectoryKey.LOAD_CONFIG_TABLE).flatMap(check(_, AnomalySubType.CLR_UNUSUAL_DATA_DIR)) :::
      List(DataDirectoryKey.BOUND_IMPORT, DataDirectoryKey.DELAY_IMPORT_DESCRIPTOR)
        .flatMap(check(_, AnomalySubType.CLR_UNEXPECTED_DATA_DIR))
  }

  // size of the CLI header in ECMA-335 II.25.3.3
  private val cliHeaderSize = 0x48
  // ILONLY, 32BITREQUIRED, IL_LIBRARY, STRONGNAMESIGNED, NATIVE_ENTRYPOINT, TRACKDEBUGDATA, 32BITPREFERRED
  private val definedCliFlags = 0x3001FL

  /**
   * Fields of the CLI header, the evidence for each type is in the Javadoc of the subtypes.
   * ManagedNativeHeader is not checked, ReadyToRun images set it.
   */
  private def checkCliHeader(clr: CLRSection): List[Anomaly] = {
    val header = clr.cliHeader
    def check(key: CLIHeaderKey, subtype: AnomalySubType, description: String)
             (isAnomalous: Long => Boolean): List[Anomaly] =
      header.get(key).filter(f => isAnomalous(f.getValue)).map(f => FieldAnomaly(f, description, subtype)).toList
    def hasFlag(flag: Long)(flags: Long): Boolean = (flags & flag) != 0
    val sizeField = header.get(CLIHeaderKey.CB)
    val sizeAnomalies = sizeField.toList.flatMap { f =>
      if (f.getValue < cliHeaderSize)
        List(FieldAnomaly(f, s"The CLI header size is ${f.getValue}, the header has $cliHeaderSize bytes",
          AnomalySubType.CLR_TOO_SMALL_HEADER_SIZE))
      else if (f.getValue > cliHeaderSize)
        List(FieldAnomaly(f, s"The CLI header size is ${f.getValue}, the header has $cliHeaderSize bytes",
          AnomalySubType.CLR_UNUSUAL_HEADER_SIZE))
      else Nil
    }
    val zeroFields = List(CLIHeaderKey.CODE_MANAGER_TABLE, CLIHeaderKey.EXPORT_ADDRESS_TABLE_JUMPS).flatMap(key =>
      check(key, AnomalySubType.CLR_NONZERO_HEADER_FIELD,
        s"The CLI header field $key must always be 0")(_ != 0))
    sizeAnomalies :::
      check(CLIHeaderKey.MAJOR_RUNTIME_VERSION, AnomalySubType.CLR_INVALID_RUNTIME_MAJOR_VERSION,
        "The major runtime version is not 2")(_ != 2) :::
      check(CLIHeaderKey.MINOR_RUNTIME_VERSION, AnomalySubType.CLR_UNUSUAL_RUNTIME_MINOR_VERSION,
        "The minor runtime version is neither 0 nor 5")(v => v != 0 && v != 5) :::
      check(CLIHeaderKey.FLAGS, AnomalySubType.CLR_UNUSUAL_ILONLY_CLEARED,
        "The IL only flag of the CLI header is cleared")(!hasFlag(0x1)(_)) :::
      check(CLIHeaderKey.FLAGS, AnomalySubType.CLR_UNUSUAL_NATIVE_ENTRYPOINT,
        "The native entry point flag of the CLI header is set")(hasFlag(0x10)) :::
      check(CLIHeaderKey.FLAGS, AnomalySubType.CLR_TRACKDEBUGDATA_SET,
        "The track debug data flag of the CLI header should be 0")(hasFlag(0x10000)) :::
      check(CLIHeaderKey.FLAGS, AnomalySubType.CLR_UNDEFINED_FLAGS,
        "The CLI header flags have bits set that are not defined")(f => (f & ~definedCliFlags) != 0) :::
      zeroFields
  }

  private def checkMetadataRootFields(clr: CLRSection): List[Anomaly] = {
    val entries = clr.getMetadataRoot.getMetaDataEntries
    def field(key: MetadataRootKey): Option[StandardField] = Option(entries.get(key))
    def check(key: MetadataRootKey, subtype: AnomalySubType, description: String)
             (isAnomalous: Long => Boolean): List[Anomaly] =
      field(key).filter(f => isAnomalous(f.getValue)).map(f => FieldAnomaly(f, description, subtype)).toList
    check(MetadataRootKey.MAJOR_VERSION, AnomalySubType.METADATA_ROOT_INVALID_VERSION,
      "The major version of the metadata root is not 1")(_ != 1) :::
      check(MetadataRootKey.MINOR_VERSION, AnomalySubType.METADATA_ROOT_INVALID_VERSION,
        "The minor version of the metadata root is not 1")(_ != 1) :::
      check(MetadataRootKey.RESERVED, AnomalySubType.METADATA_ROOT_RESERVED_SET,
        "The reserved field of the metadata root is not 0")(_ != 0) :::
      check(MetadataRootKey.FLAGS, AnomalySubType.METADATA_ROOT_RESERVED_SET,
        "The flags of the metadata root are reserved and must be 0")(_ != 0)
  }

  private def checkTablesStreamHeader(clr: CLRSection): List[Anomaly] = {
    val stream = clr.getMetadataRoot.maybeGetOptimizedStream
    if (!stream.isPresent) return Nil
    val entries = stream.get.entries
    def check(key: OptimizedStreamKey, subtype: AnomalySubType, description: String)
             (isAnomalous: Long => Boolean): List[Anomaly] =
      entries.get(key).filter(f => isAnomalous(f.getValue)).map(f => FieldAnomaly(f, description, subtype)).toList
    check(OptimizedStreamKey.MAJOR_VERSION, AnomalySubType.TABLES_STREAM_INVALID_VERSION,
      "The major version of the #~ stream is not 2")(_ != 2) :::
      check(OptimizedStreamKey.MINOR_VERSION, AnomalySubType.TABLES_STREAM_INVALID_VERSION,
        "The minor version of the #~ stream is not 0")(_ != 0) :::
      check(OptimizedStreamKey.RESERVED, AnomalySubType.TABLES_STREAM_RESERVED_SET,
        "The first reserved field of the #~ stream is not 0")(_ != 0) :::
      check(OptimizedStreamKey.RESERVED_ONE, AnomalySubType.TABLES_STREAM_RESERVED_SET,
        "The second reserved field of the #~ stream is not 1")(_ != 1) :::
      check(OptimizedStreamKey.HEAP_SIZES, AnomalySubType.TABLES_STREAM_UNDEFINED_HEAP_SIZES,
        "The heap sizes of the #~ stream have bits set other than 0x01, 0x02 and 0x04")(v => (v & ~0x7L) != 0) :::
      check(OptimizedStreamKey.VALID, AnomalySubType.TABLES_STREAM_NON_EXISTENT_TABLES,
        "The valid bit vector of the #~ stream has bits above 0x2c set, there are no such tables")(v => (v >>> 0x2D) != 0)
  }

  /**
   * Anomaly scanning the stream headers of the metadata root directory
   * @param clr the CLR section object
   * @return List of anomalies in stream headers
   */
  private def checkStreamHeaders(clr : CLRSection): List[Anomaly] = {
    val metadataRoot = clr.metadataRoot
    val names = metadataRoot.streamHeaders.map(_.name)
    // check stream names for duplicates
    val duplicates = names.diff(names.distinct).distinct
    val dupAnomalies = for(name <- duplicates) yield
      ClrStreamAnomaly(metadataRoot,
        metadataRoot.streamHeaders.find(_.name == name).get,
        "There are several streams named '" + name + "', there should only be one",
        AnomalySubType.DUPLICATED_STREAMS)
    // check for non-zero terminated streams
    val nonTermsAnomalies = {
      for (header <- metadataRoot.nonZeroTerminatedHeaders) yield
        ClrStreamAnomaly(metadataRoot,
          header, s"The name of the stream header ${header.name} is not zero terminated",
          AnomalySubType.NON_ZERO_TERMINATED_STREAM_NAME
        )
    }
    dupAnomalies ::: nonTermsAnomalies
  }

  private def checkVersionStringNotReadable(clr: CLRSection): List[Anomaly] =
    if(clr.getMetadataRoot.versionStringNotReadable) {
      List(
        new ClrMetadaRootAnomaly(clr.getMetadataRoot,
          "Version string in Metadata Root is not readable",
          AnomalySubType.METADATA_ROOT_VERSION_STRING_BROKEN
        ))
    } else Nil

  /**
   * Anomalies in the #Strings heap
   * @param clr CLR section object
   * @return list of anomalies in #Strings heap
   */
  private def checkStringsHeap(clr : CLRSection): List[Anomaly] = {
    val metadataRoot = clr.metadataRoot
    val streamHeader = metadataRoot.streamHeaders.find(_.name == "#Strings")
    val stringsHeap = metadataRoot.maybeGetStringsHeap
    if(!stringsHeap.isPresent || !streamHeader.isDefined) return Nil
    val heap= stringsHeap.get()
    val filteredStrings = heap.getArray().filter(filteredString(_).length > 0)
    // one less because first string is always empty
    val unreadableCount = heap.getArray().length - filteredStrings.length - 1
    if(unreadableCount > 0) {
      return List(new ClrStreamAnomaly(
        metadataRoot, streamHeader.get,
        "There is a total of " + unreadableCount + " unreadable strings in #Strings, this is a common obfuscation",
        AnomalySubType.UNREADABLE_CHARS_IN_STRINGS_HEAP
      ))
    }
    Nil
  }
}
