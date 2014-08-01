package com.github.katjahahn.parser.sections.reloc

class BaseRelocBlock(
    val pageRVA: Long, 
    val blockSize: Long, 
    val entries: List[BlockEntry]) {

}

case class BlockEntry(relocType: RelocType, offset: Long)