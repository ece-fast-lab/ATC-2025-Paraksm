#!/bin/bash

sudo modprobe msr
sudo service irqbalance stop
swapoff -a
echo 0 > /proc/sys/kernel/numa_balancing
echo 2 > /sys/kernel/mm/ksm/run
sudo ../common/node1_cpu_disable.sh
sudo ../common/node1_mem_disable.sh
sudo ../common/change_to_perf.sh
sudo ../common/cstate_disable.sh

./run_redis.sh

#./run_graph500.sh
#./run_liblinear.sh
