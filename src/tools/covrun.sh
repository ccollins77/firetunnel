#!/bin/bash

cd /home/netblue/coverity
export PATH="/home/netblue/coverity/cov-analysis-linux64-2017.07/bin:$PATH"
env | grep PATH

git clone http://github.com/netblue30/firetunnel
cd firetunnel
./configure --prefix=/usr

cov-build --dir cov-int make -j 4
tail cov-int/build-log.txt
tar czvf firetunnel.tgz cov-int
mv firetunnel.tgz ../.

cd ..
rm -fr firetunnel


