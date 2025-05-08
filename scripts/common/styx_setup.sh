#!/bin/bash


sshpass -p 1234!@#\$qwer ssh -o 'StrictHostKeyChecking=no' root@192.168.200.20 \
	"cd /home/mhkim/kernel_ib_bench/ksm_mod; ./run_server.sh" &
sleep 20
