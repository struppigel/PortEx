package com.github.struppigel.parser.sections.clr;

import com.github.struppigel.parser.HeaderKey;
import com.github.struppigel.parser.HeaderKey;

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
