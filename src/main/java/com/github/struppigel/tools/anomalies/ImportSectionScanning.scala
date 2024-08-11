package com.github.struppigel.tools.anomalies

import com.github.struppigel.parser.IOUtil._
import com.github.struppigel.parser.Location
import com.github.struppigel.parser.sections.SectionLoader
import com.github.struppigel.parser.sections.idata.{ImportDLL, ImportSection}

import scala.collection.JavaConverters._
import scala.collection.immutable.HashMap
import scala.collection.mutable.ListBuffer

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
    val injectionMap = HashMap(
      // Misc
      "RtlDecompressBuffer" -> "might decode data for injection or unpacking",
      "CryptStringToBinary" -> "might decode data for injection or unpacking",
      "CryptEncrypt" -> "might decode data for injection or unpacking",
      "UnmapViewOfSection" -> "may be used to carve out a process",
      "MapViewOfSection" -> "may add a section to put the unpacked data inside",
      "LoadLibrary" -> "maps module into the address space of the calling process or dynamically resolves imports",
      "GetProcAddress" -> "dynamically resolves imports",
      "SetWindowsHook" -> "injects DLL into process by hooking a Windows message",
      "WriteProcessMemory" -> "writes to memory",
      "QueryInformationProcess" -> "may get image base offset address from PEB",

      // Run or get victim process
      "CreateProcess" -> "creates a process (check if SUSPENDED flag is used)",
      "OpenProcess" -> "opens a process (check if PROCESS_ALL_ACCESS is set)",
      "WinExec" -> "runs the specified application",
      "Process32First" -> "used to iterate processes",
      "Process32Next" -> "used to iterate processes",
      "CreateToolhelp32Snapshot" -> "used to iterate processes",

      // Thread hijacking, threads in general
      "Thread32First" -> "thread hijacking, obtains thread ID of target process",
      "Thread32Next" -> "thread hijacking, obtains thread ID of target process",
      "SuspendThread" -> "may suspend a thread as preparation to write to memory",
      "ResumeThread" -> "may resume thread after injection",
      "GetThreadContext" -> "may be used to extract the EIP/RIP of the thread",
      "SetThreadContext" -> "may be used to change EIP/RIP to continue execution in injected code",
      "CreateRemoteThread" -> "is used to open and execute a thread in the victim process",
      "CreateThread" -> "is used to open and execute a thread in the victim process",
      "RtlCreateUserThread" -> "is used to open and execute a thread in the victim process",

      // Fibers
      "ConvertThreadToFiber" -> "can be used to execute shellcode via fibers",
      "CreateFiber" -> "can be used to execute shellcode via fibers",
      "SwitchToFiber" -> "can be used to execute shellcode via fibers",

      // Thread pool
      "CreateThreadpoolWait" -> "can be used to execute shellcode",
      "SetThreadpoolWait" -> "can be used to execute shellcode",

      // Thread description
      "GetThreadDescription" -> "can be used to inject shellcode",
      "SetThreadDescription" -> "can be used to inject shellcode",

      // Resources
      "FindResource" -> "used to find and load data from resources",
      "LoadResource" -> "used to find and load data from resources",
      "SizeofResource" -> "used to find and load data from resources",

      // Atom Bombing
      "GlobalAddAtom" -> "used for AtomBombing injection",
      "GlobalGetAtomName" -> "used for AtomBombing injection",
      "QueueUserApc" -> "adds APC object to queue",
      "QueueApcThread" -> "adds APC object to queue",

      // Memory Allocations
      "VirtualAlloc" -> "allocates memory",
      "AllocateVirtualMemory" -> "allocates memory",
      "ProtectVirtualMemory" -> "may set PAGE_EXECUTE for memory region",
      "VirtualProtect" -> "may set PAGE_EXECUTE for memory region",

      // Process Doppelgänging
      "CreateTransaction" -> "might be used for Process Doppelgänging",
      "CommitTransaction" -> "might be used for Process Doppelgänging",
      "RollbackTransaction" -> "might be used for Process Doppelgänging",
      "CreateFileTransacted" -> "might be used for Process Doppelgänging",
      "MoveFileTransacted" -> "might be used for Process Doppelgänging",
      "DeleteFileTransacted" -> "might be used for Process Doppelgänging",
      "CreateDirectoryTransacted" -> "might be used for Process Doppelgänging",
      "RemoveDirectoryTransacted" -> "might be used for Process Doppelgänging",

      // .NET injection, https://blog.xpnsec.com/hiding-your-dotnet-etw/
      "CLRCreateInstance" -> "might be used to unpack managed code",
      "ExecuteInDefaultAppDomain" -> "might be used to unpack managed code",

    )
    for(imp <- imports) {
      val nameImps = imp.getNameImports().asScala
      for(nameImp <- nameImps) {
        val name = nameImp.getName
        val strippedName = {
          var stripped = name
          if(name.endsWith("A") || name.endsWith("W")) {
            stripped = name.substring(0,name.length() - 1)
          }
          if(name.endsWith("Ex")){
            stripped = name.substring(0,name.length() - 2)
          }
          if(name.startsWith("Nt") || name.startsWith("Zw")) {
            stripped = name.substring(2)
          }
          stripped
        }
        if(injectionMap.contains(strippedName)) {
          val description = "Import function typical for injection/unpacking: " + name + " " + injectionMap(strippedName)
          anomalyList += ImportAnomaly(List(imp), description, 
              AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT, PEStructureKey.IMPORT_SECTION)
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
        val start = idataHeader.get().getAlignedPointerToRaw(data.getOptionalHeader.isLowAlignmentMode)
        val end = start + loader.getReadSize(idataHeader.get)
        val locEnd = loc.from + loc.size
        //ignores faulty locations (indicated by -1 or larger than file size)
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