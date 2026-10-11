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
 * A signed (authenticated) or unauthenticated attribute of a signer.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class SignatureAttribute {

    private final String oid;
    private final boolean authenticated;
    private final DerElement element;

    SignatureAttribute(String oid, boolean authenticated, DerElement element) {
        this.oid = oid;
        this.authenticated = authenticated;
        this.element = element;
    }

    /**
     * @return the attribute type in dotted notation
     */
    public String getOid() {
        return oid;
    }

    /**
     * @return the name of the attribute type, empty if unknown
     */
    public Optional<String> getName() {
        return Oids.name(oid);
    }

    /**
     * @return true iff the attribute is covered by the signature
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * @return the number of values in the value set of the attribute
     */
    public int getValueCount() {
        DerElement values = valueSet();
        return values == null ? 0 : values.childCount();
    }

    /**
     * @return the size of the encoded attribute in bytes
     */
    public long getSize() {
        return element.encodedLength();
    }

    /**
     * @return the location of the encoded attribute
     */
    public PhysicalLocation getLocation() {
        return element.location();
    }

    /**
     * @return a copy of the DER encoding of the attribute
     */
    public byte[] getEncoded() {
        return element.encoded();
    }

    DerElement element() {
        return element;
    }

    /**
     * @return the SET of values, null if malformed
     */
    DerElement valueSet() {
        return element.optChild(1).filter(DerElement::isSet).orElse(null);
    }

    @Override
    public String toString() {
        return Oids.nameOrOid(oid) + (authenticated ? "" : " (unauthenticated)");
    }
}
