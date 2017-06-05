#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o opensocket.strace ./opensocket;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c "['sample_programs/opensocket']" \
       -t sample_programs/opensocket.strace);
RET=$?
echo $OUTPUT | grep -q "Success!"
FOUND=$?
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
