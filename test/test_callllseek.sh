#!/bin/sh
cd .. > /dev/null;
output=$(python main.py \
       -c sample_programs/callllseek \
       -t sample_programs/callllseek.strace)
if ! echo $output | grep -q "result: 2"
then echo "$0: failed!";
fi
cd - > /dev/null;
