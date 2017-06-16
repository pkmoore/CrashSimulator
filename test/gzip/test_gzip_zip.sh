#!/bin/sh
cd ../../sample_programs > /dev/null;
touch zippee.txt;
cd .. > /dev/null;

strace -f -s 9999 -vvvvv -o sample_programs/zip_gzip.strace gzip sample_programs/zippee.txt;
gzip -d sample_programs/zippee.txt;
python main.py -c "['gzip', 'sample_programs/zippee.txt']" -t sample_programs/zip_gzip.strace -l DEBUG

rm sample_programs/zippee.txt
rm sample_programs/zip_gzip.strace


