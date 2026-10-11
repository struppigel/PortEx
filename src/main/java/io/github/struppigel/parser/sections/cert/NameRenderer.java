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

import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Renders X.501 names in RFC 2253 format.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class NameRenderer {

    /** keywords for attribute types that RFC 2253 does not define */
    private static final Map<String, String> OID_MAP;
    /** keywords used by the fallback renderer */
    private static final Map<String, String> KEYWORDS;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("1.2.840.113549.1.9.1", "EMAILADDRESS");
        m.put("2.5.4.5", "SERIALNUMBER");
        m.put("2.5.4.4", "SURNAME");
        m.put("2.5.4.42", "GIVENNAME");
        m.put("2.5.4.15", "BUSINESSCATEGORY");
        m.put("2.5.4.17", "POSTALCODE");
        m.put("2.5.4.97", "ORGANIZATIONIDENTIFIER");
        m.put("1.3.6.1.4.1.311.60.2.1.1", "JURISDICTIONL");
        m.put("1.3.6.1.4.1.311.60.2.1.2", "JURISDICTIONST");
        m.put("1.3.6.1.4.1.311.60.2.1.3", "JURISDICTIONC");
        OID_MAP = Collections.unmodifiableMap(m);

        Map<String, String> k = new HashMap<>(m);
        k.put("2.5.4.3", "CN");
        k.put("2.5.4.6", "C");
        k.put("2.5.4.7", "L");
        k.put("2.5.4.8", "ST");
        k.put("2.5.4.9", "STREET");
        k.put("2.5.4.10", "O");
        k.put("2.5.4.11", "OU");
        k.put("0.9.2342.19200300.100.1.25", "DC");
        k.put("0.9.2342.19200300.100.1.1", "UID");
        KEYWORDS = Collections.unmodifiableMap(k);
    }

    private NameRenderer() {
    }

    /**
     * @param name the Name element (SEQUENCE OF RelativeDistinguishedName)
     * @return the name in RFC 2253 format
     */
    static String render(DerElement name) {
        try {
            return new X500Principal(name.encoded()).getName(X500Principal.RFC2253, OID_MAP);
        } catch (RuntimeException e) {
            return fallback(name);
        }
    }

    /**
     * @param name the Name element
     * @return the last common name of the name
     */
    static Optional<String> commonName(DerElement name) {
        String cn = null;
        for (DerElement rdn : name.children()) {
            for (DerElement atav : rdn.children()) {
                Optional<DerElement> type = atav.optChild(0);
                Optional<DerElement> value = atav.optChild(1);
                if (type.isPresent() && value.isPresent() && isOid(type.get(), Oids.COMMON_NAME)) {
                    Optional<String> s = value.get().asString(CertificateTable.MAX_STRING_LENGTH);
                    if (s.isPresent()) {
                        cn = s.get();
                    }
                }
            }
        }
        return Optional.ofNullable(cn);
    }

    private static boolean isOid(DerElement element, String oid) {
        try {
            return oid.equals(element.asOid());
        } catch (DerException e) {
            return false;
        }
    }

    /**
     * Renders a name that the JDK rejects, in RFC 2253 order (most specific
     * RDN first). Bounded by {@link CertificateTable#MAX_NAME_ATTRIBUTES}.
     */
    static String fallback(DerElement name) {
        List<String> rdns = new ArrayList<>();
        int count = 0;
        for (DerElement rdn : name.children()) {
            List<String> atavs = new ArrayList<>();
            for (DerElement atav : rdn.children()) {
                if (++count > CertificateTable.MAX_NAME_ATTRIBUTES) {
                    break;
                }
                atavs.add(renderAttribute(atav));
            }
            rdns.add(String.join("+", atavs));
            if (count > CertificateTable.MAX_NAME_ATTRIBUTES) {
                rdns.add("...");
                break;
            }
        }
        Collections.reverse(rdns);
        String s = String.join(",", rdns);
        return s.length() > CertificateTable.MAX_STRING_LENGTH
                ? s.substring(0, CertificateTable.MAX_STRING_LENGTH) : s;
    }

    private static String renderAttribute(DerElement atav) {
        Optional<DerElement> type = atav.optChild(0);
        Optional<DerElement> value = atav.optChild(1);
        if (!type.isPresent() || !value.isPresent()) {
            return "#" + Hex.of(atav.encoded());
        }
        String oid;
        try {
            oid = type.get().asOid();
        } catch (DerException e) {
            oid = "?";
        }
        String keyword = KEYWORDS.containsKey(oid) ? KEYWORDS.get(oid) : oid;
        Optional<String> s = value.get().asString(CertificateTable.MAX_STRING_LENGTH);
        return keyword + "=" + (s.isPresent() ? escape(s.get()) : "#" + Hex.of(value.get().encoded()));
    }

    private static String escape(String value) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean special = ",+\"\\<>;=".indexOf(c) >= 0
                    || (i == 0 && (c == '#' || c == ' '))
                    || (i == value.length() - 1 && c == ' ');
            if (special) {
                sb.append('\\');
            }
            if (c < 0x20 || c == 0x7f) {
                sb.append(String.format("\\%02x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
