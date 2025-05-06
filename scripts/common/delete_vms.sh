#!/bin/bash


vm_name_prefix=$1
for i in $(seq 1 39); 
do
	virsh shutdown ${vm_name_prefix}-$i
	virsh undefine ${vm_name_prefix}-$i
	rm /mnt/ssd/vm_images/${vm_name_prefix}-${i}.qcow2
done
