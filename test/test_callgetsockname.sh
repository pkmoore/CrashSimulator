#!/bin/sh
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c ./sample_programs/callgetsockname \
       -t ./sample_programs/callgetsockname.strace)
if ! echo $OUTPUT | grep -q "0.0.0.0:6666";
    then echo "Failed!";
fi
cd - > /dev/null;
