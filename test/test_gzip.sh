#!/bin/sh
cd ../sample_programs > /dev/null;
#tmpfile="$(mk zippee.txt)";
#trace_name=gzip.strace;
#command="\"['gzip', 'sample_programs/zippee.txt']\"";
#xecho $command

mk zippee.txt;
strace -f -s 9999 -vvvvv -o gzip.strace gzip zippee.txt;
gzip -d zippee.txt;
cd .. > /dev/null;

OUTPUT=$(python main.py \
	 -c "['gzip', 'sample_programs/zippee.txt']" \
	 -t sample_programs/gzip.strace \
	 -l DEBUG);

RET=$?
$OUTPUT;# && $(find sample_programs/zippee.txt.gz | wc -l);
#echo $OUTPUT | grep -q "test.{6,}"

FOUND=$?
0;#rm sample_programs/gzip.strace;# && rm sample_programs/zippee.txt;#.gz;

cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
