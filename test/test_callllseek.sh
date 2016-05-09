#!/bin/sh
# This test illustrates a weird problem. The trace is taken in the sample_programs
# directory. This means that test.txt must be present there. During the replay
# execution test.txt must be present in the project root (because we don't replay
# the open() call. We might need to think about his problem more.
cd ../sample_programs > /dev/null;
echo "asdfasdf" > test.txt
strace -f -s 9999 -vvvvv -o callllseek.strace ./callllseek;
cd .. > /dev/null;
echo "asdfasdf" > test.txt
output=$(python main.py \
       -c sample_programs/callllseek \
       -t sample_programs/callllseek.strace);
if ! echo $output | grep -q "result: 2"
then echo "$0: failed!";
fi
rm sample_programs/callllseek.strace;
rm sample_programs/test.txt;
rm test.txt;
cd test /dev/null;
