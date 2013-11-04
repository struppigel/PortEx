package com.github.katjahahn.tools;

import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.PELoader;
import com.github.katjahahn.sections.SectionTable;
import com.github.katjahahn.sections.SectionTableEntry;

public class Overlay {

    private final File file;
    private final File outFile;
    private Long eof;

    public Overlay(File file, File outFile) {
        this.file = file;
        this.outFile = outFile;
    }

    public long getEndOfPE() throws IOException {
        if (eof == null) {
            com.github.katjahahn.PEData data = PELoader.loadPE(file);
            SectionTable table = data.getSectionTable();
            eof = 0L;
            for (SectionTableEntry section : table.getSectionEntries()) {
                long endPoint = section.get(POINTER_TO_RAW_DATA)
                        + section.get(SIZE_OF_RAW_DATA);
                if (eof < endPoint) {
                    eof = endPoint;
                }
            }
        }
        return eof;
    }

    public boolean hasOverlay() throws IOException {
        return file.length() > getEndOfPE();
    }

    public boolean dump() throws IOException {
        if (hasOverlay()) {
            dump(getEndOfPE());
            return true;
        } else {
            return false;
        }
    }

    private void dump(long eof) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(file, "r");
                FileOutputStream out = new FileOutputStream(outFile)) {
            raf.seek(eof);
            byte[] buffer = new byte[2048];
            int bytesRead;
            while ((bytesRead = raf.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }

}