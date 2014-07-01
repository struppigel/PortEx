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

package com.github.katjahahn.parser.sections.pdata;

import com.github.katjahahn.parser.HeaderKey;

public enum ExceptionEntryKey implements HeaderKey {

    /**
     * VA of the corresponding function
     */
    BEGIN_ADDRESS,
    /**
     * VAL of the end of the function
     */
    END_ADDRESS,
    /**
     * pointer to the exception handler
     */
    EXCEPTION_HANDLER,
    /**
     * pointer to additional information to be passed to the handler
     */
    HANDLER_DATA,
    /**
     * VA of the end of the function's prolog
     */
    PROLOG_END_ADDRESS,
    /**
     * The number of instructions in the function's prolog
     */
    PROLOG_LENGTH,
    /**
     * The number of instructions in the function
     */
    FUNCTION_LENGTH,
    /**
     * If set, the function consists of 32-bit instructions. If clear, the
     * function consists of 16-bit instructions.
     */
    BIT_32_FLAG,
    /**
     * If set, an exception handler exists for the function. Otherwise, no
     * exception handler exists.
     */
    EXCEPTION_FLAG,
    /**
     * The RVA of the unwind informations
     */
    UNWIND_INFORMATION
}
