#!/bin/bash
NCPU=`nproc`
for ((i = 0; i < $NCPU; i = i + 1))
do
    cpufreq-set -c $i -g performance
done
