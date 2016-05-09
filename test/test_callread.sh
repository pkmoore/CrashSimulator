#!/bin/sh
cd ../sample_programs > /dev/null;
echo "asdfasdf" > strace -f -s 9999 -vvvvv -o callread.strace ./callread;
cd .. > /dev/null;
output=$(python main.py \
       -c sample_programs/callread \
       -t sample_programs/callread.strace);
if ! echo $output | grep -q "asdfasd"
then echo "$0: failed!";
fi
rm sample_programs/callread.strace;
cd test > /dev/null;
