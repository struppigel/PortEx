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
import com.github.katjahahn.PEModule

/**
 * Holds the root resource directory table and provides access to the resources.
 *
 * @constructor creates an instance of the resource section with the resource 
 *   directory table
 * @param resourceTable the root resource directory table that makes up the tree 
 *   of the resource section
 */
class ResourceSection(val resourceTable: ResourceDirectoryTable) extends PEModule {

  override def read(): Unit = {}
  
  override def getInfo(): String = resourceTable.getInfo

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
  def getResources(): java.util.List[Resource] = resourceTable.getResources().asJava

}

object ResourceSection {

  /**
   * Creates an instance of the ResourceSection
   *
   * @param rsrcbytes the array of bytes the section is made up of
   * @param virtualAddress the virtual address all RVAs are relative to
   * @returns
   */
  def apply(rsrcbytes: Array[Byte], virtualAddress: Long): ResourceSection = {
    val initialLevel = Level()
    val initialOffset = 0
    val resourceTable = ResourceDirectoryTable(initialLevel, rsrcbytes, initialOffset)
    new ResourceSection(resourceTable)
  }

  /**
   * Creates an instance of the ResourceSection
   *
   * @param rsrcbytes the array of bytes the section is made up of
   * @param virtualAddress the virtual address all RVAs are relative to
   * @returns
   */
  def getInstance(rsrcbytes: Array[Byte], virtualAddress: Long): ResourceSection = 
    apply(rsrcbytes, virtualAddress)

}
