#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o calltcgets.strace ./calltcgets;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c sample_programs/calltcgets \
       -t sample_programs/calltcgets.strace);
RET=$?
echo $OUTPUT | grep -q "ca3b"
FOUND=$?
rm sample_programs/calltcgets.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
