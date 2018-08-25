#!/bin/bash

arr[1]="TEST 1: standard compilation"
arr[2]="TEST 2: compile seccomp disabled"

# remove previous reports and output file
cleanup() {
	rm -f report*
	rm -fr firetunnel
	rm -f oc* om*
}

print_title() {
	echo
	echo
	echo
	echo "**************************************************"
	echo $1
	echo "**************************************************"
}

DIST="$1"
while [ $# -gt 0 ]; do    # Until you run out of parameters . . .
    case "$1" in
    --clean)
    	cleanup
    	exit
	;;
    --help)
    	echo "./compile.sh [--clean|--help]"
    	exit
    	;;
    esac
    shift       # Check next set of parameters.
done

cleanup


#*****************************************************************
# TEST 1
#*****************************************************************
# - checkout source code
#*****************************************************************
print_title "${arr[1]}"
echo "$DIST"
tar -xJvf ../../$DIST.tar.xz
mv $DIST firetunnel

cd firetunnel
./configure --prefix=/usr --enable-fatal-warnings 2>&1 | tee ../output-configure
make -j4 2>&1 | tee ../output-make
cd ..
grep Warning output-configure output-make > ./report-test1
grep Error output-configure output-make >> ./report-test1
cp output-configure oc1
cp output-make om1
rm output-configure output-make


#*****************************************************************
# TEST 2
#*****************************************************************
# - disable seccomp configuration
#*****************************************************************
print_title "${arr[2]}"
# seccomp
cd firetunnel
make distclean
./configure --prefix=/usr --disable-seccomp  --enable-fatal-warnings 2>&1 | tee ../output-configure
make -j4 2>&1 | tee ../output-make
cd ..
grep Warning output-configure output-make > ./report-test2
grep Error output-configure output-make >> ./report-test2
cp output-configure oc2
cp output-make om2
rm output-configure output-make



#*****************************************************************
# PRINT REPORTS
#*****************************************************************
echo
echo
echo
echo
echo "**********************************************************"
echo "TEST RESULTS"
echo "**********************************************************"

wc -l report-test*
echo
echo  "Legend:"
echo ${arr[1]}
echo ${arr[2]}
echo
echo
