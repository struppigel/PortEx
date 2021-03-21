package com.github.katjahahn.parser.sections.clr;

import com.github.katjahahn.parser.HeaderKey;

public enum CLIHeaderKey implements HeaderKey {
    CB,
    MAJOR_RUNTIME_VERSION,
    MINOR_RUNTIME_VERSION,
    META_DATA_RVA,
    META_DATA_SIZE,
    FLAGS,
    ENTRY_POINT_TOKEN,
    RESOURCES_RVA,
    RESOURCES_SIZE,
    STRONG_NAME_SIGNATURE,
    CODE_MANAGER_TABLE,
    VTABLE_FIXUPS,
    EXPORT_ADDRESS_TABLE_JUMPS,
    MANAGED_NATIVE_HEADER;
}
