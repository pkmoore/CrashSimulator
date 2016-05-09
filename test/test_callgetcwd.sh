#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o callgetcwd.strace ./callgetcwd;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c ./sample_programs/callgetcwd \
       -t ./sample_programs/callgetcwd.strace);
if ! echo $OUTPUT | grep -q "CrashSimulator/sample_programs";
    then echo "Failed!";
fi
rm sample_programs/callgetcwd.strace;
cd test > /dev/null;
