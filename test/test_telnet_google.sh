#!/bin/sh

cd ../sample_programs  > /dev/null;
^ | strace -f -s 9999 -vvvvv -o telnet_google.strace telnet www.google.com 80;
cd .. > /dev/null;

OUTPUT=$(python main.py \
       -c "['telnet', 'www.google.com', '80']"  \
       -t sample_programs/telnet_google.strace);
RET=$?
echo $OUTPUT | grep -q "HTTP/1.0 200 OK"
FOUND=$?
rm sample_programs/telnet_google.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
