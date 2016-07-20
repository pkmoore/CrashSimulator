#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o charactertest.strace ./charactertest;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c sample_programs/charactertest \
       -t sample_programs/charactertest.strace);
RET=$?;
echo $OUTPUT | grep -q "()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]";
FOUND=$?;
echo $RET;
echo $FOUND;
rm sample_programs/charactertest.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1;
fi
