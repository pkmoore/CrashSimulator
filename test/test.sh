#/bin/sh

RESULTS=0
if [ -f .tests.log ];
    then rm .tests.log;
fi
touch .tests.log
for file in test_*.sh; do
    echo "////////// $file //////////"
    ./$file;
    if [ $? -ne 0 ];
        then echo "$file failed!" >> .tests.log;
        RESULTS=$((RESULTS + 1))
    fi
    echo "///////////////////////////"
done
echo "//////////// RESULTS /////////////";
if [ $RESULTS -ne 0 ];
    then cat .tests.log;
    rm .tests.log;
else
    echo "No failures!";
fi
echo "/////////////////////////////////";
