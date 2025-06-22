package io.github.struppigel.tools.anomalies;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalySubTypeWithDescription;

public class ImportSectionScanningTest {
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }
    @Test
    public void checkPinvokeAnomalies(){
        PEData pe = pedata.get("pinvoke");
        assertHasAnomalySubTypeWithDescription(pe, AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT, "VirtualProtect");
        assertHasAnomalySubTypeWithDescription(pe, AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT, "CallWindowProcA");
    }

    @Test
    public void checkProcessInjectionImports(){
        PEData pe = pedata.get("Lab17-02dll");
        AnomalySubType subType = AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT;
        assertHasAnomalySubTypeWithDescription(pe, subType, "Process32Next");
        assertHasAnomalySubTypeWithDescription(pe, subType, "Process32First");
        assertHasAnomalySubTypeWithDescription(pe, subType, "CreateToolhelp32Snapshot");
        assertHasAnomalySubTypeWithDescription(pe, subType, "CreateRemoteThread");
        assertHasAnomalySubTypeWithDescription(pe, subType, "SuspendThread");
        assertHasAnomalySubTypeWithDescription(pe, subType, "Thread32First");
        assertHasAnomalySubTypeWithDescription(pe, subType, "ResumeThread");
        assertHasAnomalySubTypeWithDescription(pe, subType, "LoadLibraryW");
        assertHasAnomalySubTypeWithDescription(pe, subType, "LoadLibraryA");
        assertHasAnomalySubTypeWithDescription(pe, subType, "WriteProcessMemory");
        assertHasAnomalySubTypeWithDescription(pe, subType, "VirtualAllocEx");
        assertHasAnomalySubTypeWithDescription(pe, subType, "CreateProcessA");
        assertHasAnomalySubTypeWithDescription(pe, subType, "GetProcAddress");
        assertHasAnomalySubTypeWithDescription(pe, subType, "CreateThread");
        assertHasAnomalySubTypeWithDescription(pe, subType, "WinExec");
        assertHasAnomalySubTypeWithDescription(pe, subType, "Thread32Next");
        assertHasAnomalySubTypeWithDescription(pe, subType, "OpenProcess");

        pe = pedata.get("proc_doppel32.exe");
        assertHasAnomalySubTypeWithDescription(pe, subType, "CreateFileTransactedW ");
        assertHasAnomalySubTypeWithDescription(pe, subType, "VirtualAllocEx");
        assertHasAnomalySubTypeWithDescription(pe, subType, "GetProcAddress");
        assertHasAnomalySubTypeWithDescription(pe, subType, "LoadLibraryA");
        assertHasAnomalySubTypeWithDescription(pe, subType, "WriteProcessMemory");
        assertHasAnomalySubTypeWithDescription(pe, subType, "CreateProcessW");
        assertHasAnomalySubTypeWithDescription(pe, subType, "RollbackTransaction");
        assertHasAnomalySubTypeWithDescription(pe, subType, "CreateTransaction");
        assertHasAnomalySubTypeWithDescription(pe, subType, "NtQueryInformationProcess");
    }
}
