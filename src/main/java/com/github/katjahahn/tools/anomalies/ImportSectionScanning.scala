package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.idata.ImportSection
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.sections.idata.ImportDLL
import scala.collection.immutable.HashMap

trait ImportSectionScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied Import Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val maybeIdata = new SectionLoader(data).maybeLoadImportSection()
    if (maybeIdata.isPresent()) {
      val idata = maybeIdata.get
      val anomalyList = ListBuffer[Anomaly]()
      anomalyList ++= checkFractionatedImports(idata)
      anomalyList ++= checkKernel32Imports(idata)
      anomalyList ++= checkVirtualImports(idata)
      anomalyList ++= checkProcessInjectionImports(idata)
      super.scan ::: anomalyList.toList
    } else super.scan ::: Nil
  }
  
  private def checkProcessInjectionImports(idata: ImportSection): List[Anomaly] = {
    val imports = idata.getImports.asScala
    val anomalyList = ListBuffer[Anomaly]()
    val injectionMap = HashMap( //TODO complete this list, test this list!
      "Process32First" -> "is used to obtain handle to victim process",
      "Process32Next" -> "is used to obtain handle to victim process",
      "CreateToolhelp32snapshot" -> "is used to obtain handle to victim process",
      "CreateRemoteThread" -> "is used to open and execute a thread in the victim process",
      "NtUnmapViewOfSection" -> "is used to remove code segment from memory",
      "LoadLibraryA" -> "maps module into the address space of the calling process",
      "LoadLibrary" -> "maps module into the address space of the calling process",
      "GlobalAddAtom" -> "used for AtomBombing injection",
      "GlobalGetAtomName" -> "used for AtomBombing injection",
      "QueueUserApc" -> "adds APC object to queue",
      "NtQueueApcThread" -> "adds APC object to queue",
      "CreateProcess" -> "creates a process",
      "OpenProcess" -> "opens a process (check if PROCESS_ALL_ACCESS is set)",
      "VirtualAllocEx" -> "allocates memory",
      "WriteProcessMemory" -> "writes to memory",
      "Thread32First" -> "obtains thread ID of target process",
      "Thread32Next" -> "obtains thread ID of target process",
      "SetWindowsHookEx" -> "injects DLL into process by hooking a Windows message",
      "VirtualAllocEx" -> "is used for cave injection",
      "SuspendThread" -> "may suspend a thread as preparation to write to memory",
      "ResumeThread" -> "may resume thread after injection",
      "GetThreadContext" -> "may be used to extract the EIP of the thread",
      "SetThreadContext" -> "may be used to change EIP to continue execution in injected code"
    )
    for(imp <- imports) {
      val nameImps = imp.getNameImports().asScala
      for(nameImp <- nameImps) {
        val name = nameImp.getName
        if(injectionMap.contains(name)) {
          val description = "Import function typical for code injection: " + name + " " + injectionMap(name)
          anomalyList += ImportAnomaly(List(imp), description, 
              AnomalySubType.PROCESS_INJECTION_IMPORT, PEStructureKey.IMPORT_SECTION)
        }
      }
    }
    anomalyList.toList
  }
    
  private def checkVirtualImports(idata: ImportSection): List[Anomaly] = {
    val fileSize = data.getFile.length
    def isVirtual(imp: ImportDLL): Boolean = {
      val locs = imp.getLocations().asScala
      locs.exists(loc => loc.from + loc.size > fileSize)
    }
    val imports = idata.getImports.asScala
    val anomalyList = ListBuffer[Anomaly]()
    for(imp <- imports) {
      if(isVirtual(imp)) {
        val description = s"Import DLL has virtual imports: ${imp.getName()}"
        anomalyList += ImportAnomaly(List(imp), description,
          AnomalySubType.VIRTUAL_IMPORTS, PEStructureKey.IMPORT_SECTION)
      }
    }
    anomalyList.toList
  }

  private def checkFractionatedImports(idata: ImportSection): List[Anomaly] = {
    val locs = idata.getPhysicalLocations.asScala
    val anomalyList = ListBuffer[Anomaly]()
    val loader = new SectionLoader(data)
    val idataHeader = loader.maybeGetSectionHeaderByOffset(idata.getOffset())
    if (idataHeader.isPresent) {

      def isWithinIData(loc: Location): Boolean = {
        val start = idataHeader.get().getAlignedPointerToRaw
        val end = start + loader.getReadSize(idataHeader.get)
        val locEnd = loc.from + loc.size
        //ignores falty locations (indicated by -1 or larger than file size)
        //FIXME find the cause of -1 entries!
        (loc.from >= data.getFile.length) || (loc.from == -1) || (loc.from >= start && locEnd <= end)
      }
      val fractions = locs.filter(!isWithinIData(_)).toList
      if (!fractions.isEmpty) {
        val affectedImports = idata.getImports.asScala.filter(i =>
          i.getLocations.asScala.exists(!isWithinIData(_))).toList
        val description = s"Imports are fractionated! Affected import DLLs: ${affectedImports.map(_.getName()).mkString(", ")}"
        anomalyList += ImportAnomaly(affectedImports, description,
          AnomalySubType.FRACTIONATED_DATADIR, PEStructureKey.IMPORT_SECTION)

      }
    }
    anomalyList.toList
  }

  //TODO test
  private def checkKernel32Imports(idata: ImportSection): List[Anomaly] = {
    val imports = idata.getImports.asScala.filter(i =>
      i.getName().equalsIgnoreCase("kernel32.dll") &&
        i.getOrdinalImports().size() > 0).toList
    val anomalyList = ListBuffer[Anomaly]()
    if (!imports.isEmpty) {
      val description = "Imports from Kernel32.dll by ordinal, namely: " + imports.mkString(", ")
      anomalyList += new ImportAnomaly(imports, description, AnomalySubType.KERNEL32_BY_ORDINAL_IMPORTS,
        PEStructureKey.IMPORT_DLL)
    }
    anomalyList.toList
  }

}