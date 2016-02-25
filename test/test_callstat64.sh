#!/bin/sh
cd .. > /dev/null;
output=$(python main.py \
       -c sample_programs/callstat64 \
       -t sample_programs/callstat64.strace)
if ! echo $output | grep -q "st_ino: 11f"
then echo "$0: failed!";
fi
cd - > /dev/null;
