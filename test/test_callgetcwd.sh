#!/bin/sh
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c ./sample_programs/callgetcwd \
       -t ./sample_programs/callgetcwd.strace)
if ! echo $OUTPUT | grep -q "CrashSimulator/sample_programs";
    then echo "Failed!";
fi
cd - > /dev/null;
