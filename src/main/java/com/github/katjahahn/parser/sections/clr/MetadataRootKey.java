package com.github.katjahahn.parser.sections.clr;

import com.github.katjahahn.parser.HeaderKey;

public enum MetadataRootKey implements HeaderKey {
    SIGNATURE,
    MAJOR_VERSION,
    MINOR_VERSION,
    RESERVED,
    LENGTH,
    VERSION,
    FLAGS,
    STREAMS,
    STREAM_HEADERS
}
