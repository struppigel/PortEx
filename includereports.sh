#!/bin/bash
#includes the specified file as testfile by generating necessary reports for it
pev $1 > /home/deque/git/PortEx/src/main/resources/reports/${1}.txt
importtest.py $1 > /home/deque/git/PortEx/src/main/resources/importreports/${1}.txt
exporttest.py $1 > /home/deque/git/PortEx/src/main/resources/exportreports/${1}.txt
mv $1 /home/deque/git/PortEx/src/main/resources/testfiles
