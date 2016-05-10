#!/bin/sh
cd ../sample_programs > /dev/null;
echo "asdfasdf" | strace -f -s 9999 -vvvvv -o callread.strace ./callread;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c sample_programs/callread \
       -t sample_programs/callread.strace);
RET=$?;
echo $OUTPUT | grep -q "asdfasd";
FOUND=$?;
rm sample_programs/callread.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1;
fi
