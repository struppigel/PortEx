PortEx
======

### Welcome to PortEx Alpha

PortEx is a Java library for static malware analysis of portable executable files.  
PortEx is written in Java and Scala, but targeted at Java applications.  
Visit the [PortEx project page](http://katjahahn.github.io/PortEx/).

### Features (so far)

* Reading header information from: MSDOS Header, COFF File Header, Optional Header, Section Table
* Reading standard section formats: Import Section, Resource Section, Export Section, Debug Section
* Dumping of sections, overlay, embedded ZIP, JAR or .class files
* Scanning for file anomalies, including structural anomalies, deprecated, reserved, wrong or non-default values
* Visualize a PE file structure as it is on disk and local entropy
* Calculate Shannon Entropy for files and sections
* Calculate MD5 and SHA256 hash values for files and sections
* Scan for PEiD signatures or your own signature database
* Scan for Jar to EXE wrapper (e.g. exe4j, jsmooth, jar2exe, launch4j)
* Scan for Unicode and ASCII strings contained in the file
* Overlay detection and dumping
* Detection Heuristics based on statistical information

For more information have a look at [PortEx Wiki](https://github.com/katjahahn/PortEx/wiki) and the [Documentation](http://katjahahn.github.io/PortEx/javadocs/)

### Version Information

The current version is in Alpha, so beware of bugs and changes of the API until the first release.
The first release will be in December 2014.

### Using PortEx

#### Including PortEx to a Maven Project

PortEx will be added to the Central Maven Repository with its first release. Until then you can include PortEx as follows:

Download portex.pom and portex.jar and install portex to your local Maven repository as follows:

```
$ mvn install:install-file -Dfile=portex.jar -DpomFile=portex.pom
```

Now you can include PortEx to your project by adding the following Maven dependency:

```
<dependency>
  		<groupId>portex</groupId>
  		<artifactId>portex_2.10</artifactId>
  		<version>0.5.0</version>
</dependency>
```

#### Using the Fat Jar

Alternatively download portex.fat.jar and just include it to your build path.

For more information, read the [PortEx Wiki](https://github.com/katjahahn/PortEx/wiki)

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
