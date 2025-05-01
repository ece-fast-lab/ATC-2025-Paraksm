#!/bin/bash
source ../common/config.sh

vm_name_prefix=$1
for ((i=0; i<${vm_num}; i++));
do
	virsh shutdown ${vm_name_prefix}-$i
done
