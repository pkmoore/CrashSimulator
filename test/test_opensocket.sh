#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o opensocket.strace ./opensocket
cd .. > /dev/null
OUTPUT=$(python main.py \
       -c sample_programs/opensocket \
       -t sample_programs/opensocket.strace)
if ! echo $OUTPUT | grep -q "Success!";
    then echo "failed"
fi
cd - > /dev/null;
