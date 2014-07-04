package com.github.katjahahn.parser.sections;

import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo;

public interface DataDirLoader<T extends SpecialSection> {
    T load(LoadInfo loadInfo);
}
