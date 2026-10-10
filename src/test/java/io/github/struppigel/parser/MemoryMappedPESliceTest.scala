package io.github.struppigel.parser

import org.testng.Assert._
import org.testng.annotations.Test

import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

class MemoryMappedPESliceTest {

  @Test def sliceWithinOneMappingMatchesSourceBytes(): Unit = {
    val file = fixtureFile("HelloWorld.exe")
    val sourceBytes = Files.readAllBytes(file.toPath)
    val data = PELoader.loadPE(file)
    val mapping = new Mapping(new VirtRange(0, sourceBytes.length),
      new PhysRange(0, sourceBytes.length), data)
    val mapped = new MemoryMappedPE(List(mapping), data)

    assertEquals(mapped.slice(19, sourceBytes.length - 23),
      sourceBytes.slice(19, sourceBytes.length - 23))
  }

  @Test def sliceAcrossMappingsKeepsUnmappedBytesZeroFilled(): Unit = {
    val file = fixtureFile("HelloWorld.exe")
    val sourceBytes = Files.readAllBytes(file.toPath)
    val data = PELoader.loadPE(file)
    val first = new Mapping(new VirtRange(20, 70), new PhysRange(0, 50), data)
    val second = new Mapping(new VirtRange(80, 130), new PhysRange(50, 100), data)
    val mapped = new MemoryMappedPE(List(first, second), data)

    val expected = Array.fill[Byte](140)(0)
    Array.copy(sourceBytes, 0, expected, 20, 50)
    Array.copy(sourceBytes, 50, expected, 80, 50)

    assertEquals(mapped.slice(0, expected.length), expected)
  }

  private def fixtureFile(name: String): File =
    Paths.get("portextestfiles", "testfiles", name).toFile
}
