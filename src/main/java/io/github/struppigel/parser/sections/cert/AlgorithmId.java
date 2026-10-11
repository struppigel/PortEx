/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
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
package io.github.struppigel.parser.sections.cert;

import io.github.struppigel.parser.PhysicalLocation;

import java.util.Optional;

/**
 * An algorithm identifier of the signature, e.g. a digest or signature
 * algorithm.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class AlgorithmId {

    private final String oid;
    private final String jdkName;
    private final boolean hasParameters;
    private final PhysicalLocation location;
    private final DerElement parameters;

    AlgorithmId(String oid, String jdkName, DerElement parameters, PhysicalLocation location) {
        this.oid = oid;
        this.jdkName = jdkName;
        this.parameters = parameters;
        this.hasParameters = parameters != null && !parameters.isUniversal(DerElement.NULL);
        this.location = location;
    }

    /**
     * @return the object identifier in dotted notation
     */
    public String getOid() {
        return oid;
    }

    /**
     * @return the name of the algorithm, or the OID if it is unknown
     */
    public String getName() {
        return Oids.nameOrOid(oid);
    }

    /**
     * @return the name the JDK uses for this algorithm, e.g. "SHA-256" for a
     *         digest, empty if the JDK name is unknown
     */
    public Optional<String> getJdkName() {
        return Optional.ofNullable(jdkName);
    }

    /**
     * @return true iff the identifier has parameters other than NULL
     */
    public boolean hasParameters() {
        return hasParameters;
    }

    /**
     * @return the location of the AlgorithmIdentifier
     */
    public PhysicalLocation getLocation() {
        return location;
    }

    /**
     * @return true iff the algorithm is or uses MD2 or MD5
     */
    public boolean isWeak() {
        return Algorithms.isWeak(oid);
    }

    /**
     * @return true iff the algorithm is or uses SHA-1
     */
    public boolean isSha1() {
        return Algorithms.isSha1(oid);
    }

    /**
     * @return the parameters element, null if absent
     */
    DerElement parameters() {
        return parameters;
    }

    @Override
    public String toString() {
        return getName();
    }
}
