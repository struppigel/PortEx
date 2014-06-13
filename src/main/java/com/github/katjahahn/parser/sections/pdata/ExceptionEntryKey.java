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
