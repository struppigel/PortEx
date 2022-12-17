PortEx ![build status](https://travis-ci.org/katjahahn/PortEx.svg?branch=master)
======

## Welcome to PortEx

PortEx is a Java library for static malware analysis of Portable Executable files. Its focus is on PE malformation robustness, and anomaly detection. 
PortEx is written in Java and Scala, and targeted at Java applications.  

![visualizer example](http://i.imgur.com/7NBze4O.png)

## Features

* Reading header information from: MSDOS Header, COFF File Header, Optional Header, Section Table
* Reading PE structures: Imports, Resources, Exports, Debug Directory, Relocations, Delay Load Imports, Bound Imports
* Dumping of sections, resources, overlay, embedded ZIP, JAR or .class files
* Scanning for file format anomalies, including structural anomalies, deprecated, reserved, wrong or non-default values.
* Visualize PE file structure, local entropies and byteplot of the file with variable colors and sizes
* Calculate Shannon Entropy for files and sections
* Calculate ImpHash and Rich and RichPV hash values for files and sections
* Scan for PEiD signatures or your own signature database
* Scan for Jar to EXE wrapper (e.g. exe4j, jsmooth, jar2exe, launch4j)
* Extract Unicode and ASCII strings contained in the file
* Overlay detection and dumping
* Extraction and conversion of .ICO files from icons in the resource section
* Extraction of version information and manifest from the file
* Reading .NET metadata and streams (Alpha)

For more information have a look at [PortEx Wiki](https://github.com/katjahahn/PortEx/wiki) and the [Documentation](http://katjahahn.github.io/PortEx/javadocs/)

## PortExAnalyzer

PortExAnalyzer is a command line tool that runs the library PortEx under the hood. If you are looking for a readily compiled command line PE scanner to analyse files with it, download it from here [PortexAnalyzer.jar](https://github.com/katjahahn/PortEx/raw/master/progs/PortexAnalyzer.jar)

## Using PortEx

### Including PortEx to a Maven Project

You can include PortEx to your project by adding the following Maven dependency:

```
<dependency>
   <groupId>com.github.katjahahn</groupId>
   <artifactId>portex_2.12</artifactId>
   <version>3.0.3</version>
</dependency> 
```

To use a local build, add the library as follows:

```
<dependency>
   <groupId>com.github.katjahahn</groupId>
   <artifactId>portex_2.12</artifactId>
   <version>3.0.3</version>
   <scope>system</scope>
   <systemPath>$PORTEXDIR/target/scala-2.12/portex_2.12-3.0.3.jar</systemPath>
</dependency> 
```

### Including PortEx to an SBT project

Add the dependency as follows in your build.sbt

```
libraryDependencies += "com.github.katjahahn" % "portex_2.12" % "3.0.3"
```

## Building PortEx

### Requirements

PortEx is build with [sbt](http://www.scala-sbt.org)  

### Compile and Build With sbt

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

### Create Eclipse Project

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

## Donations

I develop PortEx and PortexAnalyzer as a hobby in my freetime. If you like it, please consider buying me a coffee: https://ko-fi.com/struppigel

## Author

Karsten Hahn 

Twitter: [@Struppigel](https://twitter.com/struppigel)

Mastodon: [struppigel@infosec.exchange](https://infosec.exchange/@struppigel)

Youtube: [MalwareAnalysisForHedgehogs](https://www.youtube.com/c/MalwareAnalysisForHedgehogs)

## License
[Apache License, Version 2.0](https://github.com/katjahahn/PortEx/blob/master/LICENSE)
