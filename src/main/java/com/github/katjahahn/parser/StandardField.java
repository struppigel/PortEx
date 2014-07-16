/*******************************************************************************
 * Copyright 2014 Katja Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package com.github.katjahahn.parser;

import com.google.java.contract.Invariant;

/**
 * A data class for a typical entry of PE Headers.
 * 
 * @author Katja Hahn
 * 
 */
@Invariant({ "key != null" })
public class StandardField {

    /**
     * The key that describes the field.
     */
    public final HeaderKey key;
    /**
     * A description of the field, usually a better readable name for the key.
     */
    public final String description;
    /**
     * The actual value of the field entry.
     */
    public final Long value;

    /**
     * The file offset of the entry
     */
    public final long offset;

    /**
     * The size of the entry value
     */
    public final long size;

    /**
     * Creates a standard entry with the values specified.
     * 
     * @param key
     *            the key that describes the field
     * @param description
     *            of the field
     * @param value
     *            of the field entry
     * @param offset
     *            the file offset of the entry
     * @param size
     *            the size of the value
     */
    public StandardField(HeaderKey key, String description, Long value,
            long offset, long size) {
        this.key = key;
        this.description = description;
        this.value = value;
        this.size = size;
        this.offset = offset;
    }

    /**
     * Returns the file offset of the entry
     * 
     * @return file offset of the entry
     */
    public long getOffset() {
        return offset;
    }

    /**
     * Returns the size of the entrie's value in bytes
     * 
     * @return size of entrie's value in bytes
     */
    public long getSize() {
        return size;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        if (value == null) {
            return description;
        }
        return description + ": " + value + " (0x" + Long.toHexString(value)
                + ")";
    }
}
