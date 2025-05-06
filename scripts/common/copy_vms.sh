#!/bin/bash

vm_name_prefix=$1
for i in $(seq 1 39); 
do
	virt-clone --original ${vm_name_prefix}-0 --name ${vm_name_prefix}-$i --auto-clone
done
