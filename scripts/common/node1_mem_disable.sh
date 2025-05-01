#!/bin/bash

for memory_online_file in /sys/devices/system/node/node1/memory*/online; do
    echo 0 | sudo tee $memory_online_file
done

echo "All memory blocks in node1 have been set to offline."

