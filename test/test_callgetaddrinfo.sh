#!/bin/sh
cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o callgetaddrinfo.strace ./callgetaddrinfo;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c sample_programs/callgetaddrinfo \
       -t sample_programs/callgetaddrinfo.strace);
RET=$?;
echo $OUTPUT | grep -q "Worked";
FOUND=$?;
rm sample_programs/callgetaddrinfo.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1;
fi
