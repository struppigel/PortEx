package io.github.struppigel.tools.anomalies;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.idata.ImportDLL;
import io.github.struppigel.parser.sections.idata.ImportFunctionExpectations;
import io.github.struppigel.parser.sections.idata.NameImport;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalySubTypeWithDescription;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class ImportSectionScanningTest {
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }
    @Test
    public void injectionAnomalyMarksOnlyTheDataOfTheImportFunction() throws IOException {
        PEData pe = pedata.get("Lab17-02dll");
        SectionLoader loader = new SectionLoader(pe);
        NameImport function = null;
        int entriesOfItsDll = 0;
        for (ImportDLL dll : pe.loadImports()) {
            for (NameImport candidate : dll.getNameImports()) {
                if (candidate.getName().equals("CreateRemoteThread")) {
                    function = candidate;
                    entriesOfItsDll = dll.getAllImports().size();
                }
            }
        }
        assertNotNull(function);
        assertTrue(entriesOfItsDll > 3, "the DLL has more functions than the three locations of one");

        Anomaly found = null;
        for (Anomaly anomaly : PEAnomalyScanner.newInstance(pe).getAnomalies()) {
            if (anomaly.subtype() == AnomalySubType.PROCESS_INJECTION_OR_UNPACKING_IMPORT
                    && anomaly.description().contains(": CreateRemoteThread ")) {
                found = anomaly;
            }
        }
        assertNotNull(found);
        // lookup table entry, hint and name, address table slot of this function, not the entries of all functions
        assertEquals(ImportFunctionExpectations.keys(found.locations()),
                ImportFunctionExpectations.locations(loader, function));
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
