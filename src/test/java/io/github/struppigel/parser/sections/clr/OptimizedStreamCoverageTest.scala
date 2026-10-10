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

  @Test def tableSpecificationsDoNotShareMutableArraysBetweenReads(): Unit = {
    val first = CLRTable.readSpecificationFromFile(0)
    val second = CLRTable.readSpecificationFromFile(0)
    val originalKey = first.head(CLRTable.KEY_INDEX)

    assertEquals(second.head(CLRTable.KEY_INDEX), originalKey)
    first.head(CLRTable.KEY_INDEX) = "mutated"

    assertEquals(second.head(CLRTable.KEY_INDEX), originalKey)
    assertEquals(CLRTable.readSpecificationFromFile(0).head(CLRTable.KEY_INDEX), originalKey)
  }

  @Test def tableRowLookupPreservesOneBasedAndSparseRowSemantics(): Unit = {
    val first = new CLRTableEntry(0, 0L, 1, Map.empty, None, None, None)
    val second = new CLRTableEntry(0, 0L, 2, Map.empty, None, None, None)
    val contiguous = new CLRTable(List(first, second), 0, 0L)
    assertEquals(contiguous.getEntryByRow(1), Some(first))
    assertEquals(contiguous.getEntryByRow(2), Some(second))
    assertEquals(contiguous.getEntryByRow(0), None)
    assertEquals(contiguous.getEntryByRow(3), None)

    val sparseEntry = new CLRTableEntry(0, 0L, 7, Map.empty, None, None, None)
    val sparse = new CLRTable(List(sparseEntry), 0, 0L)
    assertEquals(sparse.getEntryByRow(7), Some(sparseEntry))
    assertEquals(sparse.getEntryByRow(1), None)
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