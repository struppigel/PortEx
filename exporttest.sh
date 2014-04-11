#!/bin/bash
#creates export reports with pefile
while read p; do
  b=$(basename $p)
  echo "creating src/main/resources/exportreports/${b}.txt"
  exporttest.py $p 2> /dev/null > src/main/resources/exportreports/${b}.txt
done < filelist
