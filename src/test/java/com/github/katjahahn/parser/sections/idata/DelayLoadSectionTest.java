package com.github.katjahahn.parser.sections.idata;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.sections.SectionLoader;

public class DelayLoadSectionTest {
    
  @Test
  public void basicWorkingTest() throws IOException {
      File file = new File("/home/deque/portextestfiles/unusualfiles/corkami/delay_imports.exe");
      PEData data = PELoader.loadPE(file);
      DelayLoadSection section = new SectionLoader(data).loadDelayLoadSection();
      List<ImportDLL> list = section.getImports();
      assertEquals(list.size(), 1);
      ImportDLL dll = list.get(0);
      assertEquals(dll.getName(), "USER32.dll");
      List<NameImport> imports = dll.getNameImports();
      assertEquals(imports.size(), 1);
      NameImport nameImport = imports.get(0);
      assertEquals(nameImport.hint, 0);
      assertEquals(nameImport.name, "MessageBoxA");
      assertEquals(nameImport.nameRVA, 8356);
      assertEquals(nameImport.rva, 8348);
  }
  
}
