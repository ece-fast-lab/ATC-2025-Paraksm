#!/bin/bash
source ../common/config.sh

ksmd_pid=$(pidof ksmd)
wait_pids=$()
liblinear_port=10000
declare -A exec_time
affected_pid=0

set_redis_isolation() {
	taskset -pc 1 $ksmd_pid
	sudo pqos -e "llc:1=${CAT[server]};llc:2=${CAT[client]};"
	sudo pqos -a "llc:1=${CPU[server]};llc:2=${CPU[client]};"
}

set_isolation() {
	taskset -pc 1 $ksmd_pid
	sudo pqos -e "llc:1=${CAT[vm_ksm]};llc:2=${CAT[vm_no_ksm]};"
	sudo pqos -a "llc:1=${CPU[vm_ksm]};llc:2=${CPU[vm_no_ksm]};"
}

set_nice() {
	local nice_value=$1

	if [ $nice_value == "rt" ]; then
		chrt -f -p 99 $ksmd_pid
	else
		chrt -o -p 0 $ksmd_pid
		renice -n $nice_value -p $ksmd_pid
	fi
}

set_ksm() {
	local mode=$1
	local tree=$2
	local cand=$3
	local usleep_time=$4

	echo 2 > /sys/kernel/mm/ksm/run
	echo $mode $tree $cand
	echo "SET KSM"
	case $mode in
	cpu_single) 
		${set_ksm_dir}/set_ksm.sh
		;;
	dsa_single)
		${set_ksm_dir}/set_ksm.sh --dsa --dsa-comp-mode spin_sched
		;;
	styx)
		${set_ksm_dir}/set_ksm.sh --styx
		;;
	dsa_hybrid)
		${set_ksm_dir}/set_ksm.sh --dsa --dsa-comp-mode spin_sched --dsa-cpu-hybrid
		;;
	speculative)
		${set_ksm_dir}/set_ksm.sh --dsa --dsa-comp-mode spin_sched --spec-batch --tree-batch-size $tree
		;;
	candidate)
		${set_ksm_dir}/set_ksm.sh --dsa --dsa-comp-mode spin_sched --cand-batch --cand-batch-size $cand
		;;
	spec_cand) 
		${set_ksm_dir}/set_ksm.sh --dsa --dsa-comp-mode spin_sched --cand-batch --cand-batch-size $cand --spec-batch --tree-batch-size $tree
		;;
	*)
		echo "NOT USE KSM"
		;;
	esac

	if [[ $mode != "no_ksm" ]]; then
		echo 0 > /sys/kernel/mm/ksm/sleep_millisecs
		if [[ $mode != "candidate" ]]; then
			echo 2048 > /sys/kernel/mm/ksm/pages_to_scan
		else
			echo 102400 > /sys/kernel/mm/ksm/pages_to_scan
		fi
		echo 1 > /sys/kernel/mm/ksm/run
		while true; do
			value=$(cat /sys/kernel/mm/ksm/full_scans)
			# echo "value $value"
			sleep 0.001
			if [ "$value" -ge 1 ]; then
				echo "value $value"
				echo "Value changed to 1, proceeding to experiment"
				break
			fi
		done
	fi
	echo 0 > /sys/kernel/mm/ksm/run

	if [[ $mode == "cpu_single" ]]; then
		echo 20 > /sys/kernel/mm/ksm/sleep_millisecs
		echo 2048 > /sys/kernel/mm/ksm/pages_to_scan
	fi
	if [[ $mode == "styx" ]]; then
		echo 0 > /sys/kernel/mm/ksm/sleep_millisecs
		echo 2048 > /sys/kernel/mm/ksm/pages_to_scan
	fi
	if [[ $mode == "dsa_single" ]]; then
		echo 0 > /sys/kernel/mm/ksm/sleep_millisecs
		echo 2048 > /sys/kernel/mm/ksm/pages_to_scan
	fi
	if [[ $mode == "candidate" ]]; then
		echo 500 > /sys/kernel/mm/ksm/sleep_millisecs
		echo 102400 > /sys/kernel/mm/ksm/pages_to_scan
	fi
	
	if [[ $mode != "no_ksm" ]]; then
		echo $usleep_time > /sys/kernel/mm/ksm/dsa_sched_us_start
		echo 1 > /sys/kernel/mm/ksm/run
	fi
}

load_liblinear() {
	echo 3 > /proc/sys/vm/drop_caches
	echo "LOAD LIBLINEAR"
	for ((i=${start_core}; i<${start_core}+${vm_num}; i++));
	do
		vm_ip=`virsh domifaddr ${liblinear_vm}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
		new_port=$((liblinear_port + i))

		sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$vm_ip \
			 "swapoff -a; cd ./liblinear; ./train -P $new_port ./dataset/SUSY &" &
	done
	sleep 120
	echo "END LOAD LIBLINEAR"
}

run_liblinear() {
	local stop=0

	echo "RUN LIBLINEAR - vm_num: ${vm_num}"
	wait_pids=()
	for ((i=${start_core}; i<${start_core}+${vm_num}; i++));
	do
		vm_ip=`virsh domifaddr ${liblinear_vm}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
		new_port=$((liblinear_port + i))

		sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$vm_ip \
			"cd ./liblinear; ./client $stop 0 0 $new_port" &
		if [[ $i == "1" ]]; then
			affected_pid=$!
			wait_pids+=(${affected_pid})
			echo "Affected pid: ${affected_pid}"
		else
			wait_pids+=($!)
		fi
	done
	echo "${wait_pids[@]}"
}

load_graph500() {
	echo 3 > /proc/sys/vm/drop_caches
	echo "LOAD GRAPH500 - vm_num: ${vm_num}"
	for ((i=${start_core}; i<${start_core}+${vm_num}; i++));
	do
		vm_ip=`virsh domifaddr ${graph500_vm}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
		new_port=$((liblinear_port + i))

		sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$vm_ip \
			"swapoff -a; cd ./graph500; ./omp-csr/omp-csr -s 23 -p $new_port &" & 
	done
	sleep 240
	echo "END LOAD GRAPH500"
}

run_graph500() {
	local stop=0
	
	echo "RUN GRAPH500 - vm_num: ${vm_num}"
	wait_pids=()
	for ((i=${start_core}; i<${start_core}+${vm_num}; i++));
	do
		vm_ip=`virsh domifaddr ${graph500_vm}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
		new_port=$((liblinear_port + i))

		sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$vm_ip \
			"cd ./graph500; ./client $stop 0 $new_port" &
		if [[ $i == "1" ]]; then
			affected_pid=$!
			wait_pids+=(${affected_pid})
			echo "Affected pid: ${affected_pid}"
		else
			wait_pids+=($!)
		fi
		
	done
	echo "${wait_pids[@]}"
}

load_redis() {
	local workload=c
	echo 3 > /proc/sys/vm/drop_caches

	for ((i=${start_core}; i<${start_core}+${vm_num}; i++));
	do
		moduler=$((i % vm_num_of_group))
		if ((${moduler} == 1)); then
			echo flush all
			server_ip=`virsh domifaddr ${redis_vm}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
			sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$server_ip \
				"redis-cli flushall" &
		fi
	done
	wait

	for ((i=${start_core}; i<${start_core}+${vm_num}; i++));
	do
		moduler=$((i % vm_num_of_group))
		if ((${moduler} != 2)); then
			echo skip
			continue
		fi
		server_id=$((i / vm_num_of_group * vm_num_of_group + 1))
		server_ip=`virsh domifaddr ${redis_vm}-$((server_id)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
		client_ip=`virsh domifaddr ${redis_vm}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`

		sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$client_ip \
		"cd ./YCSB; ./bin/ycsb load redis -s -P workloads/workload${workload} -P configs/config-load.dat -p redis.host=${server_ip} -p recordcount=$rccount" &
	done
	wait
}

run_redis() {
	local workload=$1
	local mode=$2
	local tree=$3
	local cand=$4
	local nice_value=$5
	local us=$6
	local data_dir=$7

	echo "RUN REDIS"
	echo worklkoad : $workload
	echo mode : $mode
	echo tree : $tree
	echo cand : $cand

	client_id=0
	for ((i=${start_core}; i<${start_core}+${vm_num}; i++));
	do
		if ((i % ${vm_num_of_group} == 1)); then
			continue
		fi
		group_id=$((i / vm_num_of_group))
		server_id=$((i / vm_num_of_group * vm_num_of_group + 1))
		server_ip=`virsh domifaddr ${redis_vm}-$((server_id)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`
		client_ip=`virsh domifaddr ${redis_vm}-$((i)) | awk '/vnet/{print \$4}' | cut -d'/' -f1`

		sshpass -p $vm_passwd ssh -o 'StrictHostKeyChecking=no' $vm_id@$client_ip \
			"cd ./YCSB; ./bin/ycsb run redis -s -P workloads/workload${workload} -P configs/config-run.dat -p redis.host=${server_ip} -p recordcount=$rccount -p operationcount=3000000 -p maxexecutiontime=${Time} -p requestdistribution=uniform -target ${Target[${workload}]}" > $data_dir/redis_latency/client${client_id}_${workload}_${mode}_${tree}_${cand}_${nice_value}_${us}_latency.dat 2>/dev/null &
		wait_pids+=($!)

		client_id=$((client_id + 1))
	done
	sleep 17
}

measure_ksm_stat() {
	local workload=$1
	local mode=$2
	local tree=$3
	local cand=$4
	local nv=$5
	local us=$6
	local data_dir=$7

	data_file=${data_dir}/ksm_stat/${workload}_${mode}_${tree}_${cand}_${nv}_${us}.csv
	ksm_dir=/sys/kernel/mm/ksm
	ksm_debug_dir=/sys/kernel/mm/ksm_debug

	echo "MEASIRE KSM STAT"

	echo 0 > ${ksm_dir}/ksm_debug_on # off
	echo 2 > ${ksm_dir}/ksm_debug_on # reset
	echo 1 > ${ksm_dir}/ksm_debug_on # on
	
	T=1
	t=0
	echo "time(s),compare,checksum,full_scans,pages_shared,pages_sharing,pages_unshared,pages_volatile,stable_node_chains,stable_node_dups,memory_saving(MB)" > ${data_file}
	
	while true; do
		start_time=$(date +%s)
		
		compare=`cat ${ksm_debug_dir}/compare/num`
		checksum=`cat ${ksm_debug_dir}/crc/num`
		full_scans=`cat ${ksm_dir}/full_scans`
		pages_shared=`cat ${ksm_dir}/pages_shared`
		pages_sharing=`cat ${ksm_dir}/pages_sharing`
		pages_unshared=`cat ${ksm_dir}/pages_unshared`
		pages_volatile=`cat ${ksm_dir}/pages_volatile`
		stable_node_chains=`cat ${ksm_dir}/stable_node_chains`
		stable_node_dups=`cat ${ksm_dir}/stable_node_dups`
		mem_saving=$((4 * pages_sharing / 1000)) # MB
		
		echo "${t},${compare},${checksum},${full_scans},${pages_shared},${pages_sharing},${pages_unshared},${pages_volatile},${stable_node_chains},${stable_node_dups},${mem_saving}" >> ${data_file}
		t=$((t + T))
	
		end_time=$(date +%s)
		elapsed_time=$((end_time - start_time))
		sleep_time=$((T - elapsed_time))
		if [ $sleep_time -gt 0 ]; then
			sleep $sleep_time
		fi
	done
}

measure_llc_miss() {
	local workload=$1
	local mode=$2
	local tree=$3
	local cand=$4
	local nv=$5
	local us=$6
	local data_dir=$7
	local vm_name=$8

	data_file_core=${data_dir}/llc_miss/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_core.dat
	data_file_ksm=${data_dir}/llc_miss/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_ksm.dat
	data_file_core_total=${data_dir}/llc_miss/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_core_total.dat
	data_file_ksm_total=${data_dir}/llc_miss/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_ksm_total.dat

	vm1_pid=$(ps -C qemu-system-x86_64 -o pid,cmd | grep -w "${vm_name}-1" | awk '{print $1}')

	echo "MEASIRE LLC MISS"
	# CORE
	# sudo perf stat -e 'LLC-load-misses, LLC-loads, LLC-store-misses, LLC-stores' -C 1 -I 1000 \
	sudo perf stat -e 'LLC-load-misses, LLC-loads, LLC-store-misses, LLC-stores' -p ${vm1_pid} -I 1000 \
			-o $data_file_core &
	
	# sudo perf stat -e 'LLC-load-misses, LLC-loads, LLC-store-misses, LLC-stores' -C 1 \
	sudo perf stat -e 'LLC-load-misses, LLC-loads, LLC-store-misses, LLC-stores' -p ${vm1_pid} \
			-o $data_file_core_total &

	# KSM
	sudo perf stat -e 'LLC-load-misses, LLC-loads, LLC-store-misses, LLC-stores' -p ${ksmd_pid} -I 1000 \
			-o $data_file_ksm &
	
	sudo perf stat -e 'LLC-load-misses, LLC-loads, LLC-store-misses, LLC-stores' -p ${ksmd_pid} \
			-o $data_file_ksm_total &
}

measure_cpu_cycle() {
	local workload=$1
	local mode=$2
	local tree=$3
	local cand=$4
	local nv=$5
	local us=$6
	local data_dir=$7
	local vm_name=$8

	data_file_core=${data_dir}/cpu_util/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_core.dat
	data_file_ksm=${data_dir}/cpu_util/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_ksm.dat
	data_file_vm=${data_dir}/cpu_util/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_vm.dat
	data_file_core_per_second=${data_dir}/cpu_util/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_core_per_second.dat
	data_file_ksm_per_second=${data_dir}/cpu_util/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_ksm_per_second.dat
	data_file_vm_per_second=${data_dir}/cpu_util/${workload}_${mode}_${tree}_${cand}_${nv}_${us}_vm_per_second.dat
	
	echo "MEASURE CPU CYCLE"
	vm_pid=$(ps -C qemu-system-x86_64 -o pid,cmd | grep -w "${vm_name}-1" | awk '{print $1}')
	# TOTAL
	# sudo perf stat -e 'cpu-cycles' -C 0 -I 5000 \
	sudo perf stat -e 'cpu-cycles' -C 1 \
			-o $data_file_core &
	sudo perf stat -e 'cpu-cycles' -C 1 -I 1000 \
			-o $data_file_core_per_second &
	# KSM
	# sudo perf stat -e 'cpu-cycles' -p $ksmd_pid -I 5000 \
	sudo perf stat -e 'cpu-cycles' -p $ksmd_pid \
			-o $data_file_ksm &
	sudo perf stat -e 'cpu-cycles' -I 1000 -p $ksmd_pid \
			-o $data_file_ksm_per_second &

	# Redis VM
	sudo perf stat -e 'cpu-cycles' -p $vm_pid \
			-o $data_file_vm &
	sudo perf stat -e 'cpu-cycles' -p $vm_pid -I 1000 \
			-o $data_file_vm_per_second &
}

measure_dram_bandwidth() {
	local workload=$1
	local mode=$2
	local tree=$3
	local cand=$4
	local nv=$5
	local us=$6
	local data_dir=$7

	echo "MEASURE DRAM BW"

	data_file=${data_dir}/dram_bw/${workload}_${mode}_${tree}_${cand}_${nv}_${us}.csv

	sudo pcm-memory 1 -csv=${data_file} &
}

measure_ksm_breakdown() {
	local workload=$1
	local mode=$2
	local tree=$3
	local cand=$4
	local nv=$5
	local us=$6
	local data_dir=$7

	data_file=${data_dir}/ksm_breakdown/${workload}_${mode}_${tree}_${cand}_${nv}_${us}.csv
	
	ksm_dir=/sys/kernel/mm/ksm
	ksm_debug_dir=/sys/kernel/mm/ksm_debug
	debug_infos=(cmp_and_merge compare compare_batch compare_candidate crc crc_batch hybrid_cpu_compare ksm_do_scan scan_get_next_rmap_item stable_tree_insert stable_tree_search unstable_tree_search_insert)

	T=1
	t=0
	echo "time(s),debug_info,num,total_cycles,avg_cycles" > $data_file
	
	while true; do
		start_time=$(date +%s)
		for debug_info in "${debug_infos[@]}"; do
			declare num=`cat ${ksm_debug_dir}/${debug_info}/num`
			declare total_cycles=`cat ${ksm_debug_dir}/${debug_info}/total_cycles`
			declare avg_cycles=`cat ${ksm_debug_dir}/${debug_info}/avg_cycles`

			echo "${t},${debug_info},${num},${total_cycles},${avg_cycles}" >> $data_file
		done
		t=$((t + T))
		
		end_time=$(date +%s)
		elapsed_time=$((end_time - start_time))
		sleep_time=$((T - elapsed_time))
		if [ $sleep_time -gt 0 ]; then
			sleep $sleep_time
		fi
	done
}

stop_measure() {
	local ksm_stat_pid=$1
	local ksm_debug_pid=$2

	pkill -SIGINT perf
	pkill -SIGINT pcm-memory
	pkill -SIGINT pqos
	pkill ksmd_monitor
	pkill alloc_mem
	kill "$ksm_stat_pid"
	kill "$ksm_debug_pid"
}

wait_redis() {
	echo "WAIT REDIS"
	for ((i=0; i<${#wait_pids[@]}; i++));
	do
		while kill -0 "${wait_pids[i]}" 2>/dev/null; do
			sleep 0.01
		done
		echo "stop ${wait_pids[i]}"
		unset "wait_pids[i]"
		wait_pids=("${wait_pids[@]}")
	done
	echo END WAIT REDIS "${wait_pids[@]}"
}

wait_and_measure_exec_time() {
	local data_file=$1
	echo "WAIT AND MEASURE EXEC TIME"
	start_time=$(date +%s)  # 전체 실행 시작 시간
	echo $start_time

	echo "WAIT_PID NUM: ${#wait_pids[@]}"
	# 폴링하여 PID를 추적
	while [ "${#wait_pids[@]}" -gt 0 ]; do
  		for i in "${!wait_pids[@]}"; do
    			pid=${wait_pids[$i]}

   		 	# PID가 종료되었는지 확인
    			if ! kill -0 "$pid" 2>/dev/null; then
      				end_time=$(date +%s)
				echo $end_time
      				exec_time[$pid]=$((end_time - start_time))  # 실행 시간 기록
      				unset 'wait_pids[i]'  # 배열에서 제거
    			fi
  		done

  		# 배열을 정리하여 빈 슬롯 제거
  		wait_pids=("${wait_pids[@]}")
  		sleep 1  # 1초 대기 (폴링 주기)
	done

	# 평균 실행 시간 계산
	local total_time=0
	local count=0
	for i in "${!exec_time[@]}"; do
  		total_time=$((total_time + exec_time[$i]))
  		count=$((count + 1))
	done

	total_time=$((total_time - exec_time[${affected_pid}]))
	count=$((count - 1))

	local avg_time=$(echo "$total_time / $count" | bc -l)

	# 결과 출력
	for e_t in "${exec_time[@]}"; do
		echo -n "${e_t}," >> "${data_file}.all"
	done
	echo >> "${data_file}.all"

	echo "affected: ${exec_time[${affected_pid}]}, not_affected: $avg_time" >> ${data_file}
}

wait_only() {
	echo "WAIT ONLY"
	start_time=$(date +%s)  # 전체 실행 시작 시간

	echo "WAIT_PID NUM: ${#wait_pids[@]}"
	# 폴링하여 PID를 추적
	while [ "${#wait_pids[@]}" -gt 0 ]; do
  		for i in "${!wait_pids[@]}"; do
    			pid=${wait_pids[$i]}

   		 	# PID가 종료되었는지 확인
    			if ! kill -0 "$pid" 2>/dev/null; then
      				end_time=$(date +%s)
      				exec_time[$pid]=$((end_time - start_time))  # 실행 시간 기록
      				unset 'wait_pids[i]'  # 배열에서 제거
    			fi
  		done

  		# 배열을 정리하여 빈 슬롯 제거
  		wait_pids=("${wait_pids[@]}")
  		sleep 1  # 1초 대기 (폴링 주기)
	done


	# 평균 실행 시간 계산
	local total_time=0
	local count=0
	for i in "${!exec_time[@]}"; do
  		total_time=$((total_time + exec_time[$i]))
  		count=$((count + 1))
	done

	total_time=$((total_time - exec_time[${affected_pid}]))
	count=$((count - 1))

	local avg_time=$(echo "$total_time / $count" | bc -l)

	# 결과 출력
	echo "affected: ${exec_time[${affected_pid}]}, not_affected: $avg_time"
}

