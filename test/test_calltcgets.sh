#!/bin/sh
cd .. > /dev/null;
output=$(python main.py \
       -c sample_programs/calltcgets \
       -t sample_programs/calltcgets.strace)
if ! echo $output | grep -q "8a3b"
then echo "$0: failed!";
fi
cd - > /dev/null;
