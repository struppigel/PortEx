package com.github.katjahahn.parser.sections.idata;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.optheader.OptionalHeaderTest;
import com.github.katjahahn.parser.sections.SectionLoader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.testng.Assert.assertEquals;

public class DelayLoadSectionTest {

    @Test
    public void basicWorkingTest() throws IOException {
        File file = new File("portextestfiles/corkami/delay_imports.exe");

        // FIXME check why this file has problems
        // File file = new File("portextestfiles/BinaryCorpus_v2_oldCorkami/yoda/DelayImport (User.dll).exe");
        // new File("portextestfiles/corkami/delayimports.exe"));

        PEData data = PELoader.loadPE(file);
        DelayLoadSection section = new SectionLoader(data).loadDelayLoadSection();
        List<ImportDLL> list = section.getImports();

        logger.debug("size " + list.size());
        assertEquals(list.size(), 1);
        ImportDLL dll = list.get(0);

        logger.debug("dllname " + dll.getName());
        assertEquals(dll.getName(), "USER32.dll");
        List<NameImport> imports = dll.getNameImports();
        logger.debug("size " + imports.size());
        assertEquals(imports.size(), 1);
        NameImport nameImport = imports.get(0);
        logger.debug("hint: " + nameImport.getHint());
        assertEquals(nameImport.getHint(), 0);

        logger.debug("name " + nameImport.getName());
        assertEquals(nameImport.getName(), "MessageBoxA");

        logger.debug("namerva " + nameImport.getNameRVA());
        assertEquals(nameImport.getNameRVA(), 8356);

        logger.debug("rva " + nameImport.getRVA());
        assertEquals(nameImport.getRVA(), 8348);

    }

    private static Logger logger = LogManager.getLogger(OptionalHeaderTest.class.getName());

}
