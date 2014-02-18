PortEx
======

Java library to analyse Portable Executable files with a special focus on malware analysis.

This project is written in Java and Scala, but targeted for Java applications.

So far it supports:

* Reading Header information from: MSDOS Header, COFF File Header, Optional Header, Section Table
* Dumping of: MSDOS Load Module, Sections, Overlay, embedded ZIP, JAR or .class files
* Mapping of Data Directory Entries to the corresponding Section
* Reading Standard Section Formats: Import Section, Resource Section
* Scan for PEiD userdb signatures
* Scan for jar2exe or class2exe wrappers
