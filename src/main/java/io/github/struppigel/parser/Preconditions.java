/*******************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
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
package io.github.struppigel.parser;

/**
 * Argument and state checks with the semantics of the Guava class of the same
 * name, which PortEx 5 used. Meant for use inside PortEx.
 */
public final class Preconditions {

    private Preconditions() {
    }

    /**
     * @throws IllegalArgumentException if the expression is false
     */
    public static void checkArgument(boolean expression) {
        if (!expression) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * @throws IllegalArgumentException with the message if the expression is
     *             false
     */
    public static void checkArgument(boolean expression, Object message) {
        if (!expression) {
            throw new IllegalArgumentException(String.valueOf(message));
        }
    }

    /**
     * @throws IllegalStateException if the expression is false
     */
    public static void checkState(boolean expression) {
        if (!expression) {
            throw new IllegalStateException();
        }
    }

    /**
     * @throws IllegalStateException with the message if the expression is
     *             false
     */
    public static void checkState(boolean expression, Object message) {
        if (!expression) {
            throw new IllegalStateException(String.valueOf(message));
        }
    }

    /**
     * @return the reference
     * @throws NullPointerException if the reference is null
     */
    public static <T> T checkNotNull(T reference) {
        if (reference == null) {
            throw new NullPointerException();
        }
        return reference;
    }

    /**
     * @return the reference
     * @throws NullPointerException with the message if the reference is null
     */
    public static <T> T checkNotNull(T reference, Object message) {
        if (reference == null) {
            throw new NullPointerException(String.valueOf(message));
        }
        return reference;
    }
}
