#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o callgetsockname.strace ./callgetsockname;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c "['./sample_programs/callgetsockname']" \
       -t ./sample_programs/callgetsockname.strace);
RET=$?
echo $OUTPUT | grep -q "0.0.0.0:6666"
FOUND=$?
rm sample_programs/callgetsockname.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
