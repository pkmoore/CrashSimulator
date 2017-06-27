#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o ../sample_programs/callsigaction.strace ./callsigaction
ltrace -f -s 9999 -o callsigaction.ltrace ./callsigaction 
cd .. > /dev/null;

 python main.py -c "['sample_programs/callsigaction']" -t sample_programs/callsigaction.strace -l DEBUG;

