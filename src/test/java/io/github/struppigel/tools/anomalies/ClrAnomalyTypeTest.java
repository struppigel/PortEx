package io.github.struppigel.tools.anomalies;

import org.testng.annotations.Test;

import static io.github.struppigel.tools.anomalies.AnomalySubType.*;
import static io.github.struppigel.tools.anomalies.AnomalyType.*;
import static org.testng.Assert.assertEquals;

/**
 * The types of the CLR header and metadata header anomalies, see the evidence in the Javadoc of each subtype.
 * Rule: a value the runtime rejects is WRONG, one it accepts is NON_DEFAULT unless the specification forbids it.
 * ManagedNativeHeader is not reported, ReadyToRun images set it.
 */
public class ClrAnomalyTypeTest {

    @Test
    public void cliHeaderSubtypes() {
        assertEquals(CLR_TOO_SMALL_HEADER_SIZE.getSuperType(), WRONG);
        assertEquals(CLR_UNUSUAL_HEADER_SIZE.getSuperType(), NON_DEFAULT);
        assertEquals(CLR_INVALID_RUNTIME_MAJOR_VERSION.getSuperType(), WRONG);
        assertEquals(CLR_UNUSUAL_RUNTIME_MINOR_VERSION.getSuperType(), NON_DEFAULT);
        assertEquals(CLR_UNUSUAL_ILONLY_CLEARED.getSuperType(), NON_DEFAULT);
        assertEquals(CLR_UNUSUAL_NATIVE_ENTRYPOINT.getSuperType(), NON_DEFAULT);
        assertEquals(CLR_TRACKDEBUGDATA_SET.getSuperType(), RESERVED);
        assertEquals(CLR_UNDEFINED_FLAGS.getSuperType(), RESERVED);
        assertEquals(CLR_NONZERO_HEADER_FIELD.getSuperType(), WRONG);
    }

    @Test
    public void dataDirectorySubtypes() {
        assertEquals(CLR_UNUSUAL_DATA_DIR.getSuperType(), NON_DEFAULT);
        assertEquals(CLR_UNEXPECTED_DATA_DIR.getSuperType(), WRONG);
        assertEquals(CLR_HEADER_IN_WRITEABLE_SECTION.getSuperType(), STRUCTURE);
    }

    @Test
    public void metadataRootSubtypes() {
        assertEquals(METADATA_ROOT_INVALID_VERSION.getSuperType(), WRONG);
        assertEquals(METADATA_ROOT_RESERVED_SET.getSuperType(), RESERVED);
    }

    @Test
    public void tablesStreamSubtypes() {
        assertEquals(TABLES_STREAM_INVALID_VERSION.getSuperType(), WRONG);
        assertEquals(TABLES_STREAM_RESERVED_SET.getSuperType(), RESERVED);
        assertEquals(TABLES_STREAM_UNDEFINED_HEAP_SIZES.getSuperType(), RESERVED);
        assertEquals(TABLES_STREAM_NON_EXISTENT_TABLES.getSuperType(), WRONG);
    }
}
