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
package com.github.struppigel.parser.sections.rsrc

import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import com.github.struppigel.parser.{Location, MemoryMappedPE, PELoader, PhysicalLocation}
import com.github.struppigel.parser.sections.{SectionLoader, SpecialSection}

import java.io.File
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

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
 * @param hasLoop indicates whether the resource tree has a loop
 */
class ResourceSection private (
  private val resourceTree: ResourceDirectory,
  private val offset: Long,
  private val mmBytes: MemoryMappedPE,
  val hasLoop: Boolean) extends SpecialSection {

  /**
   * Returns all file locations of the special section
   */
  def getPhysicalLocations(): java.util.List[PhysicalLocation] =
    Location.mergeContinuous[PhysicalLocation](resourceTree.locations).toList.asJava

  /**
   * {@inheritDoc}
   */
  override def isEmpty(): Boolean = getResources.isEmpty()

  /**
   * {@inheritDoc}
   */
  override def getInfo(): String = resourceTree.getInfo

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
  def getResourceTree(): ResourceDirectory = resourceTree

  /**
   * Collects the resources from the root resource directory table, removes 
   * duplicates and returns them.
   *
   * @return a List of {@link Resource} instances
   */
  def getResources(): java.util.List[Resource] = 
    resourceTree.getUniqueResources()
 
}

object ResourceSection {

  /**
   * Maximum depth for the resource tree that is read.
   */
  val maxLevel = 10
  
  /**
   * Maximum number of nodes to read.
   */
  val maxResourceDirs = 1000

  def main(args: Array[String]): Unit = {
    val file = new File("/home/deque/portextestfiles/badfiles/VirusShare_10c6fdb01b6b19f84055754b764c6e38")
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
    // empty constructor creates type level (depth 1)
    val initialLevel = Level()
    // initial offset for the resource directory (relative to rsrc table) is zero
    val initialOffset = 0
    // initialize loop checker
    val loopChecker = new ResourceLoopChecker()
    // create the root of the resource directory, this will recursively
    // create all the children too
    val resourceTable = ResourceDirectory(file, initialLevel,
      initialOffset, virtualAddress, rsrcOffset, mmBytes, loopChecker)
    // check if loop was detected during creation
    val hasLoop = loopChecker.loopDetected
    // create resource section instance
    new ResourceSection(resourceTable, rsrcOffset, mmBytes, hasLoop)
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

/**
 * Checks for resources loops. Exactly one instance per resource tree!
 */
class ResourceLoopChecker {
    /**
     * Saves references to known file offsets for resource directories to check for loops
     */
    private val fileOffsets = ListBuffer[Long]()
    private var _loopDetected: Boolean = false

    /**
     * Returns true if the node is a new node, false otherwise. Used to check for
     * resource tree loops.
     */
    def isNewResourceDirFileOffset(fileOffset: Long): Boolean = {
      // a new offset is one that wasn't already added
      val isNew = !fileOffsets.contains(fileOffset)
      // now add the offset to the list
      fileOffsets += fileOffset
      // change status of loopDetected if necessary
      if(!isNew) _loopDetected = true
      // return whether offset was a new one
      isNew
    }
    
    /**
     * Get the number of saved resource directory file offsets
     */
    def size(): Integer = fileOffsets.size

    /**
     * Indicates if a loop was detected.
     */
    def loopDetected(): Boolean = _loopDetected
  }
