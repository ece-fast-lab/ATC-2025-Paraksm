#!/bin/bash
source ../common/config.sh
vm_name_prefix=$1

for ((i=0; i<${vm_num}; i++));
do
	virsh vcpupin ${vm_name_prefix}-$i 0 $i
done

pattern="guest=${vm_name_prefix}-"

pids=$(pgrep -f "$pattern")

for pid in $pids; do
  core=$(ps -o cmd= -p $pid | grep -oP "$pattern\K\d+")
  echo $core

  threads=$(ps -L -p $pid -o tid=)

  for tid in $threads; do
    taskset -pc $core $tid
  done
done
