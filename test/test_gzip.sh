#!/bin/sh
cd ../sample_programs > /dev/null;
mk zippee.txt;
cd .. > /dev/null;

#strace -f -s 9999 -vvvvv -o sample_programs/gzip.strace gzip sample_programs/zippee.txt;
gzip -d sample_programs/zippee.txt;
python main.py -c "['gzip', 'sample_programs/zippee.txt']" -t sample_programs/gzip.strace -l DEBUG


