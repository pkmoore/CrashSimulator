#!/bin/sh
# This test does not have the same problem as the llseek test because
# there is no call to open()
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o callmkstemp.strace ./callmkstemp
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c "['sample_programs/callmkstemp']" \
       -t sample_programs/callmkstemp.strace \
       -l DEBUG);
RET=$?
echo $OUTPUT | grep -q "test.{6,}"
FOUND=$?
#rm sample_programs/callmkstemp.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
