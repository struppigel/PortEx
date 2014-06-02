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
package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.sections.PESection
import scala.collection.JavaConverters._
import com.github.katjahahn.IOUtil
import com.github.katjahahn.PEHeader
import com.github.katjahahn.sections.SpecialSection
import com.github.katjahahn.PELoader
import java.io.File
import com.github.katjahahn.sections.SectionLoader
import com.github.katjahahn.PEData

/**
 * Holds the root resource directory table and provides access to the resources.
 *
 * @constructor creates an instance of the resource section with the resource 
 *   directory table
 * @param resourceTable the root resource directory table that makes up the tree 
 *   of the resource section
 */
class ResourceSection(
    val resourceTable: ResourceDirectoryTable, 
    private val rsrcBytes: Array[Byte], 
    val virtualAddress: Long,
    val offset: Long,
    val size: Long) extends SpecialSection {

  override def getInfo(): String = resourceTable.getInfo
  
  def getSize(): Long = size
  
  override def getOffset(): Long = offset

  /**
   * Returns the {@link ResourceDirectoryTable} that is the root of the
   * resource tree
   *
   * @return the root node of the resource tree that makes up the resource section
   */
  def getResourceTable(): ResourceDirectoryTable = resourceTable

  /**
   * Collects the resources from the root resource directory table and
   * returns them.
   *
   * @return a List of {@link Resource} instances
   */
  def getResources(): java.util.List[Resource] = 
    resourceTable.getResources(virtualAddress, rsrcBytes)

}

object ResourceSection {
  
  def main(args: Array[String]): Unit = {
    val file = new File("src/main/resources/unusualfiles/corkami/resource_loop.exe")
    val pedata = PELoader.loadPE(file)
    val rsrc = new SectionLoader(pedata).loadResourceSection()
    println(rsrc.getResources.asScala.mkString("\n"))
  }

  /**
   * Creates an instance of the ResourceSection
   *
   * @param file 
   * @param rsrcbytes the array of bytes the section is made up of
   * @param virtualAddress the virtual address all RVAs are relative to
   * @param rsrcOffset
   * @returns
   */
  def apply(file: File, rsrcbytes: Array[Byte], virtualAddress: Long, 
      rsrcOffset: Long): ResourceSection = {
    val initialLevel = Level()
    val initialOffset = 0
    val resourceTable = ResourceDirectoryTable(file, initialLevel, rsrcbytes, 
        initialOffset, virtualAddress, rsrcOffset)
    new ResourceSection(resourceTable, rsrcbytes, virtualAddress, rsrcOffset, rsrcbytes.length)
  }

  /**
   * Creates an instance of the ResourceSection
   *
   * @param file
   * @param rsrcbytes the array of bytes the section is made up of
   * @param virtualAddress the virtual address all RVAs are relative to
   * @param rsrcOffset
   * @returns
   */
  def getInstance(file: File, rsrcbytes: Array[Byte], virtualAddress: Long, 
      rsrcOffset: Long): ResourceSection = 
    apply(file, rsrcbytes, virtualAddress, rsrcOffset)
    
  /**
   * Loads the resource section and returns it.
   * 
   * This is just a shortcut to loading the section using the {@link SectionLoader}
   * 
   * @return instance of the resource section
   */
  def load(data: PEData): ResourceSection = 
    new SectionLoader(data).loadResourceSection()

}
