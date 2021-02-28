#!/bin/sh

touch empty.txt;

strace -f -s 9999 -vvvv -o pandoc_convert_txt.strace pandoc -t plain -o converted.txt empty.txt;
rm converted.txt;

cd ../../ > /dev/null;
python main.py -c "['pandoc', '-t', 'plain', '-o', 'converted.txt', 'empty.txt']" -t test/pandoc/pandoc_convert_txt.strace;

cd test/pandoc/;
rm empty.txt;
rm pandoc_convert_txt.strace
