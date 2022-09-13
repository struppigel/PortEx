/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
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
 * ****************************************************************************
 */
package com.github.katjahahn.parser.sections.clr;

import com.github.katjahahn.parser.HeaderKey;

public enum CLRTableKey implements HeaderKey {
    MODULE_GENERATION,
    MODULE_NAME,
    MODULE_MVID,
    MODULE_ENCID,
    MODULE_ENCBASEID,

    TYPEREF_RESOLUTION_SCOPE,
    TYPEREF_TYPE_NAME,
    TYPEREF_TYPE_NAMESPACE,

    TYPEDEF_FLAGS,
    TYPEDEF_TYPE_NAME,
    TYPEDEF_TYPE_NAMESPACE,
    TYPEDEF_EXTENDS,
    TYPEDEF_FIELDLIST,
    TYPEDEF_METHODLIST,

    FIELD_FLAGS,
    FIELD_NAME,
    FIELD_SIGNATURE,

    METHOD_RVA,
    METHOD_IMPLFLAGS,
    METHOD_FLAGS,
    METHOD_NAME,
    METHOD_SIGNATURE,
    METHOD_PARAMLIST
}
