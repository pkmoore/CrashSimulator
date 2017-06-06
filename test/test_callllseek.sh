#!/bin/sh
# This test illustrates a weird problem. The trace is taken in the sample_programs
# directory. This means that test.txt must be present there. During the replay
# execution test.txt must be present in the project root (because we don't replay
# the open() call. We might need to think about his problem more.
cd ../sample_programs > /dev/null;
echo "asdfasdf" > test.txt
strace -f -s 9999 -vvvvv -o callllseek.strace ./callllseek;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c "['sample_programs/callllseek']" \
       -t sample_programs/callllseek.strace);
RET=$?
echo $OUTPUT | grep -q "result: 2"
FOUND=$?
rm sample_programs/callllseek.strace;
rm sample_programs/test.txt;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
