#!/bin/bash
source ../common/config.sh

vm_name=$1

for ((i=0; i<${vm_num}; i++));
do
	server_ip=`virsh domifaddr ${vm_name}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
	sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$server_ip \
		"ls" &
done

wait
