PortEx
======

### Welcome to PortEx

PortEx is a Java library for static malware analysis of portable executable files.
PortEx is written in Java and Scala, but targeted for Java applications.

### Features (so far)

* Reading Header information from: MSDOS Header, COFF File Header, Optional Header, Section Table
* Dumping of: MSDOS Load Module, Sections, Overlay, embedded ZIP, JAR or .class files
* Mapping of Data Directory Entries to the corresponding Section
* Reading Standard Section Formats: Import Section, Resource Section
* Scan for PEiD userdb signatures
* Scan for jar2exe or class2exe wrappers

For more information have a look at [PortEx Wiki](https://github.com/katjahahn/PortEx/wiki/Getting-Started) and the [Documentation](http://katjahahn.github.io/PortEx/javadocs/)

### Version Information

The current version is not even Alpha yet, which is the reason that there are no binaries provided by now. However you can build the current source.

### Building PortEx

#### Requirements

PortEx is build with [sbt](http://www.scala-sbt.org)  
You also need [Maven](https://maven.apache.org/)

#### Setup Third Party Libraries

(Note: This process will be simplified when PortEx is in Alpha)

Download [VirusTotalPublic](https://github.com/kdkanishka/Virustotal-Public-API-V2.0-Client/archive/master.zip)

Extract the file and navigate to the *Virustotal-Public-API-V2.0-Client-master* folder. Build the jar with:

```
$ mvn clean install -DskipTests
```

Then publish it to your local Maven repository:

```
$ mvn install:install-file -Dfile=target/VirustotalPublicV2.0.0-1.1-GA.jar -DpomFile=pom.xml
```

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

### Author
[Katja Hahn](http://katjahahn.github.io/)

### License
[BSD 2-Clause License](https://github.com/katjahahn/PortEx/blob/master/LICENSE)
