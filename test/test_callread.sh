#!/bin/sh
cd .. > /dev/null;
output=$(python main.py \
       -c sample_programs/callread \
       -t sample_programs/callread.strace)
if ! echo $output | grep -q "hXXXXXr"
then echo "$0: failed!";
fi
cd - > /dev/null;
