PortEx Analyzer

usage: 
 java -jar PortexAnalyzer.jar -v
 java -jar PortexAnalyzer.jar -h
 java -jar PortexAnalyzer.jar --repair <file>
 java -jar PortexAnalyzer.jar --diff <filelist or folder> 
 java -jar PortexAnalyzer.jar --pdiff <file1> <file2> <imagefile>
 java -jar PortexAnalyzer.jar [-a] [-o <outfile>] [-p <imagefile> [-bps <bytes>]] [-i <folder>] <PEfile>

 -h,--help          show help
 -v,--version       show version
 -a,--all           show all info (slow and unstable!)
 -o,--output        write report to output file
 -p,--picture       write image representation of the PE to output file
 -bps               bytes per square in the image
 --repair           repair the PE file
 --diff             compare several files and show common characteristics (alpha feature)
 --pdiff            create a diff visualization
 -i,--ico           extract icons from the resource section as .ico file
