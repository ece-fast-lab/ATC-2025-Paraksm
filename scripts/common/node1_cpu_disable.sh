#!/bin/bash
RANGE=$(lscpu | grep "NUMA node1" | awk '{print $4}' | sed 's/,/ /g')
IFS='-' read -r START END <<< "$RANGE"
for ((cpu=START; cpu<=END; cpu++)); do
    echo 0 > /sys/devices/system/cpu/cpu$cpu/online
done
