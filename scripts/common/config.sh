#!/bin/bash
set_ksm_dir="/home/mhkim/workspace/paraksm-ae/scripts/common"
#set_ksm_dir="/home/mhkim/workspace/dsa-ksm"

redis_vm="redis"
graph500_vm="graph500"
liblinear_vm="graph500"

vm_id="root"
vm_passwd="mh"

vm_num=40
vm_num_of_group=4

num_of_group=$((vm_num / vm_num_of_group))
start_core=0
server_core=1

declare -A CAT
CAT["server"]=0x1
CAT["client"]=0x7ffe
CAT["vm_ksm"]=0x7ffe
CAT["vm_no_ksm"]=0x1

declare -A CPU
CPU["server"]="1,5,9,13,17,21,25,29,33,37"
CPU["client"]="0,2-4,6-8,10-12,14-16,18-20,22-24,26-28,30-32,34-36,38-39"
CPU["vm_ksm"]="1"
CPU["vm_no_ksm"]="0,2-39"

rccount=700000 # 4GB
declare -A Target
Target[a]=2000
Target[b]=2000
Target[c]=1000
Target[d]=2000
Time=200
