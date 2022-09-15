package com.github.katjahahn.parser.sections.clr;

public enum CLRTableType {

    ASSEMBLY (               0x20),
    ASSEMBLYOS (             0x22),
    ASSEMBLYPROCESSOR (      0x21),
    ASSEMBLYREF (            0x23),
    ASSEMBLYREFPROCESSOR (   0x24),
    ASSEMBLYREFOS (          0x25),
    CLASSLAYOUT (            0x0F),
    CONSTANT (               0x0B),
    CUSTOMATTRIBUTE (        0x0C),
    DECLSECURITY (           0x0E),
    EVENTMAP (               0x12),
    EVENT (                  0x14),
    EXPORTEDTYPE (           0x27),
    FIELD (                  0x04),
    FIELDLAYOUT (            0x10),
    FIELDMARSHAL (           0x0D),
    FIELDRVA (               0x1D),
    FILE (                   0x26),
    GENERICPARAM (           0x2A),
    GENERICPARAMCONSTRAINT ( 0x2C),
    IMPLMAP (                0x1C),
    INTERFACEIMPL (          0x09),
    MANIFESTRESOURCE (       0x28),
    MEMBERREF (              0x0A),
    METHODDEF (              0x06),
    METHODIMPL (             0x19),
    METHODSEMATICS (         0x18),
    METHODSPEC (             0x2B),
    MODULE (                 0x00),
    MODULEREF (              0x1A),
    NESTEDCLASS (            0x29),
    PARAM (                  0x08),
    PROPERTY (               0x17),
    PROPERTYMAP (            0x15),
    STANDALONESIG (          0x11),
    TYPEDEF (                0x02),
    TYPEREF (                0x01),
    TYPESPEC (               0x1B);

    private int index;

    private CLRTableType(int index){
        this.index = index;
    }

    public int getIndex(){
        return index;
    }
}
