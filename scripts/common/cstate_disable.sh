#!/bin/bash

NCPU=`nproc`

for ((i = 0; i < $NCPU; i = i + 1))
do
	for ((j = 1; j < 4; j = j + 1))
	do
		echo 1 > /sys/devices/system/cpu/cpu$i/cpuidle/state$j/disable
	done
done
