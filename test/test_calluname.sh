#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o calluname.strace ./calluname;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c "['./sample_programs/calluname']" \
       -t ./sample_programs/calluname.strace);
RET=$?
echo $RET
echo $OUTPUT | grep -q "Linux"
FOUND=$?
echo $FOUND
#rm sample_programs/calluname.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi

