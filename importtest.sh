#!/bin/bash
#creates import reports with pefile
while read p; do
  b=$(basename $p)
  echo $b
  importtest.py $p 2> /dev/null > src/main/resources/importreports/${b}.txt
done < filelist
