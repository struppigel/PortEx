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
package com.github.katjahahn;

import java.io.IOException;

import com.google.common.base.Optional;

/**
 * Represents a common structure of a PE like certain headers or the section
 * table
 * 
 * @author Katja Hahn
 * 
 */
public abstract class PEHeader {

    public static final String NL = System.getProperty("line.separator");

    /**
     * Returns the file offset for the beginning of the module
     * 
     * @return file offset for the beginning of the module
     */
    public abstract long getOffset();

    /**
     * Returns a description string of the {@link PEHeader}.
     * 
     * @return description string
     */
    public abstract String getInfo();

    // TODO maybe use factories instead
    /**
     * Reads the information necessary. This is usually done by the
     * {@link PELoader}
     * 
     * @throws IOException
     */
    public abstract void read() throws IOException;

    /**
     * Returns the value for the given key or null if there is no value for that
     * key.
     * 
     * @param key
     * @return long value for the given key or null if value doesn't exist
     */
    public abstract Optional<Long> get(HeaderKey key);

    /**
     * Returns the value for the given key.
     * 
     * @param key
     * @return long value for the given key
     * @throws IllegalArgumentException
     *             if key doesn't exist
     */
    public abstract long getValue(HeaderKey key)
            throws IllegalArgumentException;

    // TODO use Optional instead of returning null!
    /**
     * Returns the {@link StandardField} for the given key or null if there is
     * no value for that key.
     * 
     * @param key
     * @return {@link StandardField} for the given key or null if value doesn't
     *         exist
     */
    public abstract StandardField getField(HeaderKey key);
}
