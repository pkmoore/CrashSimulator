#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o callsetlocale.strace ./callsetlocale;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c ./sample_programs/callsetlocale \
       -t ./sample_programs/callsetlocale.strace);
RET=$?
echo $OUTPUT | grep -q "en_US.UTF-8"
FOUND=$?
rm sample_programs/callsetlocale.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
