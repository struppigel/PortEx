PortEx ![build status](https://travis-ci.org/katjahahn/PortEx.svg?branch=master)
======

### Welcome to PortEx

PortEx is a Java library for static malware analysis of Portable Executable files. Its focus is on PE malformation robustness, and anomaly detection. 
PortEx is written in Java and Scala, and targeted at Java applications.  
Visit the [PortEx project page](http://katjahahn.github.io/PortEx/).

### Features

* Reading header information from: MSDOS Header, COFF File Header, Optional Header, Section Table
* Reading standard section formats: Import Section, Resource Section, Export Section, Debug Section, Relocations
* Dumping of sections, overlay, embedded ZIP, JAR or .class files
* Scanning for file anomalies, including structural anomalies, deprecated, reserved, wrong or non-default values.
* Visualize a PE file structure as it is on disk and visualize the local entropies of the file
* Calculate Shannon Entropy for files and sections
* Calculate hash values for files and sections
* Scan for PEiD signatures or your own signature database
* Scan for Jar to EXE wrapper (e.g. exe4j, jsmooth, jar2exe, launch4j)
* Extract Unicode and ASCII strings contained in the file
* Overlay detection and dumping
* Extraction of ICO files from resource section
* File scoring based on statistical information

For more information have a look at [PortEx Wiki](https://github.com/katjahahn/PortEx/wiki) and the [Documentation](http://katjahahn.github.io/PortEx/javadocs/)

### Using PortEx

#### Including PortEx to a Maven Project

You can include PortEx to your project by adding the following Maven dependency:

```
<dependency>
   <groupId>com.github.katjahahn</groupId>
   <artifactId>portex_2.10</artifactId>
   <version>2.0.2</version>
</dependency> 
```

To use a local build, add the library as follows:

```
<dependency>
   <groupId>com.github.katjahahn</groupId>
   <artifactId>portex_2.10</artifactId>
   <version>2.0.2</version>
   <scope>system</scope>
   <systemPath>$PORTEXDIR/target/scala-2.10/portex_2.10-2.0.2.jar</systemPath>
</dependency> 
```

#### Including PortEx to an SBT project

Add the dependency as follows in your build.sbt

```
libraryDependencies += "com.github.katjahahn" % "portex_2.10" % "2.0.2"
```

### Building PortEx

#### Requirements

PortEx is build with [sbt](http://www.scala-sbt.org)  

#### Compile and Build With sbt

To simply compile the project invoke:

```
$ sbt compile
```

To create a jar: 

```
$ sbt package
```

To compile a fat jar that can be used as command line tool, type:

```
$ sbt assembly
```

#### Create Eclipse Project

You can create an eclipse project by using the sbteclipse plugin.
Add the following line to *project/plugins.sbt*:

```
addSbtPlugin("com.typesafe.sbteclipse" % "sbteclipse-plugin" % "2.4.0")
```

Generate the project files for Eclipse:

```
$ sbt eclipse
```

Import the project to Eclipse via the *Import Wizard*.

### Author and Contact
Katja Hahn  
E-Mail: portx (at) gmx (dot) de

### License
[Apache License, Version 2.0](https://github.com/katjahahn/PortEx/blob/master/LICENSE)
