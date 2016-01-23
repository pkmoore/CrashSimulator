#!/bin/sh
cd .. > /dev/null;
output=`python main.py \
       -c sample_programs/opensocket \
       -t sample_programs/opensocket_failure.strace\
       -o .co.log;`
if ! echo $output | grep -q "Failure!"
    then echo "failed"
fi
cd - > /dev/null;
