#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o calltcgets.strace ./calltcgets;
cd .. > /dev/null;
output=$(python main.py \
       -c sample_programs/calltcgets \
       -t sample_programs/calltcgets.strace);
if ! echo $output | grep -q "8a3b"
then echo "$0: failed!";
fi
rm sample_programs/calltcgets.strace;
cd test > /dev/null;
