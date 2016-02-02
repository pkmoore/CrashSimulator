#!/bin/sh
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c ./sample_programs/calluname \
       -t ./sample_programs/calluname.strace)
if ! echo $OUTPUT | grep -q "Linux";
    then echo "Failed!";
fi
cd - > /dev/null;
