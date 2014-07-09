/**
 * *****************************************************************************
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
 * ****************************************************************************
 */
package com.github.katjahahn.parser.sections.rsrc

import scala.collection.JavaConverters._
import java.io.File
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.MemoryMappedPE
import com.github.katjahahn.parser.Location

/**
 * Holds the root resource directory table and provides access to the resources.
 *
 * @author Katja Hahn
 *
 * Creates an instance of the resource section with the resource
 * directory table
 * 
 * @param resourceTable the root resource directory table that makes up the tree
 *   of the resource section
 * @param offset the file offset to the beginning of the resource table
 * @param mmBytes the memory mapped PE
 */
class ResourceSection private (
  val resourceTable: ResourceDirectory,
  private val offset: Long,
  private val mmBytes: MemoryMappedPE) extends SpecialSection {
  
  /**
   * Returns all file locations of the special section
   */
  def getLocations(): java.util.List[Location] = 
    Location.mergeContinuous(resourceTable.locations).asJava

  /**
   * {@inheritDoc}
   */
  override def isEmpty(): Boolean = getResources.isEmpty()

  /**
   * {@inheritDoc}
   */
  override def getInfo(): String = resourceTable.getInfo

  /**
   * {@inheritDoc}
   */
  override def getOffset(): Long = offset

  /**
   * Returns the {@link ResourceDirectory} that is the root of the
   * resource tree
   *
   * @return the root node of the resource tree that makes up the resource section
   */
  def getResourceTable(): ResourceDirectory = resourceTable

  /**
   * Collects the resources from the root resource directory table and
   * returns them.
   *
   * @return a List of {@link Resource} instances
   */
  def getResources(): java.util.List[Resource] =
    resourceTable.getResources()

}

object ResourceSection {

  def main(args: Array[String]): Unit = {
    val file = new File("/home/deque/portextestfiles/testfiles/WinRar.exe")
    val pedata = PELoader.loadPE(file)
    val rsrc = new SectionLoader(pedata).loadResourceSection()
    val res = rsrc.getResources.asScala
    println(res.mkString("\n"))
    println("nr of res: " + res.size)
  }

  /**
   * Creates an instance of the ResourceSection.
   *
   * @param file the PE file
   * @param virtualAddress the virtual address all RVAs are relative to
   * @param rsrcOffset the file offset to the rsrc section
   * @param mmBytes the memory mapped PE
   * @return instance of the resource section
   */
  def apply(file: File, virtualAddress: Long,
    rsrcOffset: Long, mmBytes: MemoryMappedPE): ResourceSection = {
    val initialLevel = Level()
    val initialOffset = 0
    val resourceTable = ResourceDirectory(file, initialLevel,
      initialOffset, virtualAddress, rsrcOffset, mmBytes)
    new ResourceSection(resourceTable, rsrcOffset, mmBytes)
  }

  /**
   * Creates an instance of the ResourceSection.
   *
   * @param loadInfo the load information
   * @return instance of the resource section
   */
  def newInstance(loadInfo: LoadInfo): ResourceSection =
    apply(loadInfo.data.getFile, loadInfo.va, loadInfo.fileOffset, loadInfo.memoryMapped)

}
