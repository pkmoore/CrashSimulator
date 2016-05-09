#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o calluname.strace ./calluname;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c ./sample_programs/calluname \
       -t ./sample_programs/calluname.strace);
if ! echo $OUTPUT | grep -q "Linux";
    then echo "Failed!";
fi
rm sample_programs/calluname.strace;
cd test > /dev/null;
