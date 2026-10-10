package io.github.struppigel.parser.sections.clr

import io.github.struppigel.parser.StandardField
import org.testng.Assert._
import org.testng.annotations.Test

class OptimizedStreamCoverageTest {

  @Test def reportsHeapWidthsAndTableSizeMappings(): Unit = {
    val wide = stream(heapSizes = 0x7, validTables = 3L, tableSizes = List(4, 9))
    assertEquals(wide.getStringHeapSize, 4)
    assertEquals(wide.getGUIDHeapSize, 4)
    assertEquals(wide.getBlobHeapSize, 4)
    assertEquals(wide.getTableIndices, List(0, 1))
    assertEquals(wide.getTableNames, List("Module", "TypeRef"))
    assertEquals(wide.getTableIndicesToSizesMap, Map(0 -> 4, 1 -> 9))
    assertEquals(wide.getTableNamesToSizesMap, Map("Module" -> 4, "TypeRef" -> 9))
    assertEquals(wide.getRawOffset, 0x1234L)
    assertTrue(wide.getInfo.contains("Heap sizes"))

    val narrow = stream(heapSizes = 0, validTables = 1L, tableSizes = List(3))
    assertEquals(narrow.getStringHeapSize, 2)
    assertEquals(narrow.getGUIDHeapSize, 2)
    assertEquals(narrow.getBlobHeapSize, 2)
    assertEquals(narrow.getTableNames, List("Module"))
  }

  private def stream(heapSizes: Int, validTables: Long, tableSizes: List[Int]): OptimizedStream = {
    val fields = Map(
      OptimizedStreamKey.HEAP_SIZES -> new StandardField(
        OptimizedStreamKey.HEAP_SIZES, "Heap sizes", heapSizes.toLong, 0, 1),
      OptimizedStreamKey.VALID -> new StandardField(
        OptimizedStreamKey.VALID, "Valid tables", validTables, 1, 8)
    )
    new OptimizedStream(fields, tableSizes, 0x1234L, Map.empty)
  }
}