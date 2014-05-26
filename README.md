PortEx
======

### Welcome to PortEx

PortEx is a Java library for static malware analysis of portable executable files.  
PortEx is written in Java and Scala, but targeted for Java applications.  
Visit the [PortEx project page](http://katjahahn.github.io/PortEx/).

### Features (so far)

* Reading header information from: MSDOS Header, COFF File Header, Optional Header, Section Table
* Reading standard section formats: Import Section, Resource Section, Export Section, Debug Section
* Dumping of sections, overlay, embedded ZIP, JAR or .class files
* Scanning for file anomalies, including collapsed headers and usage of deprecated, reserved or wrong values
* Scan for PEiD signatures or your own signature database
* Scan for jar2exe or class2exe wrappers
* Scan for Unicode and ASCII strings contained in the file
* Overlay detection

For more information have a look at [PortEx Wiki](https://github.com/katjahahn/PortEx/wiki) and the [Documentation](http://katjahahn.github.io/PortEx/javadocs/)

### Version Information

The current version is in Alpha, so beware of bugs.
The first release will be in December 2014.

### Using PortEx

Download portex.jar and include it to your build path. For more information, read the [PortEx Wiki](https://github.com/katjahahn/PortEx/wiki)

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

For a fat jar (not recommended):

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
