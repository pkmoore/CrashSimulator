#!/bin/sh

# This script redirects STDERR into STDOUT for testing purposes. This has been
# shown to cause issues in other cases. It seems fine here but might cause
# problems in the future.


cd ..> /dev/null;
strace -f -s 9999 -vvvvv -o netcat_send_noconnect.strace netcat -v localhost 6666;
OUTPUT=$(python main.py \
       -c "['netcat -v localhost 6666']" \
       -t netcat_send_noconnect.strace 2>&1);
RET=$?;
echo $OUTPUT | grep -q "Connection refused";
FOUND=$?;
rm netcat_send_noconnect.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1;
fi
