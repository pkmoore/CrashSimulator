#!/bin/sh
cd ../sample_programs > /dev/null;
touch zippee.txt;
gzip zippee.txt;
cd .. > /dev/null;

strace -f -s 9999 -vvvvv -o sample_programs/unzip_gzip.strace gzip -d sample_programs/zippee.txt.gz;

cd sample_programs > /dev/null;
gzip zippee.txt;
cd .. > /dev/null;

python main.py -c "['gzip', '-d', 'sample_programs/zippee.txt.gz']" -t sample_programs/unzip_gzip.strace -l DEBUG

rm sample_programs/zippee.txt.gz
