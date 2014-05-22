#!/usr/bin/python
import pefile
import sys

pe =  pefile.PE(sys.argv[1], fast_load=False)
print pe.get_overlay_data_start_offset()
