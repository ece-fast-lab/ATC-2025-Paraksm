#!/bin/bash

source ../common/for_reviewers.sh
source ../common/config.sh
source ../common/functions.sh

data_dir="./result_${reviewer_id}/redis"

run_expr() {
	local system_mode=$1
	local nice_value=$2
	local tree=$3
	local cand=$4
	local workload=$5
	local usleep_time=$6

	set_redis_isolation
	set_nice $nice_value
	set_ksm $system_mode $tree $cand $usleep_time
	
	run_redis $workload $system_mode $tree $cand $nice_value $usleep_time $data_dir

	measure_llc_miss $workload $system_mode $tree $cand $nice_value $usleep_time ${data_dir} ${redis_vm}
	measure_cpu_cycle $workload $system_mode $tree $cand $nice_value $usleep_time $data_dir $redis_vm
	measure_dram_bandwidth $workload $system_mode $tree $cand $nice_value $usleep_time $data_dir
	measure_ksm_stat $workload $system_mode $tree $cand $nice_value $usleep_time ${data_dir} &
	stat_pid=$!
	measure_ksm_breakdown $workload $system_mode $tree $cand $nice_value $usleep_time $data_dir &
	debug_pid=$!
	sleep $Time
	stop_measure $stat_pid $debug_pid

	wait_redis ${wait_pids}
}

# 1. Check result directories
dirs=(
    "${data_dir}"
    "${data_dir}/llc_miss"
    "${data_dir}/cpu_util"
    "${data_dir}/dram_bw"
    "${data_dir}/ksm_stat"
    "${data_dir}/ksm_breakdown"
    "${data_dir}/redis_latency"
)
for dir in "${dirs[@]}"; do
    	if [ ! -d "$dir" ]; then
        	mkdir -p "$dir"
	fi
done

# 2. Setup Redis VM
echo 2 > /sys/kernel/mm/ksm/run
../common/start_vms.sh ${redis_vm}
sleep 60
../common/pin_vms.sh ${redis_vm}
sleep 60
load_redis
sleep 10

workloads=("a" "b" "c" "d")
for workload in ${workloads[@]}
do
# 3. Run no-ksm
system_mode="no_ksm"
nice_value="5"
tree="1"
cand="1"
usleep_time="0"
run_expr $system_mode $nice_value $tree $cand $workload $usleep_time

# 4. Run CPU-ksm
system_mode="cpu_single"
nice_value="5"
tree="1"
cand="1"
usleep_time="0"
run_expr $system_mode $nice_value $tree $cand $workload $usleep_time

# 5. Run DSA-ksm
system_mode="dsa_single"
nice_value="rt"
tree="1"
cand="1"
usleep_time="50"
run_expr $system_mode $nice_value $tree $cand $workload $usleep_time

# 6. Run Para-ksmC
system_mode="candidate"
nice_value="rt"
tree="1"
cand="256"
usleep_time="115"
run_expr $system_mode $nice_value $tree $cand $workload $usleep_time

done

# 7. Clean Redis VM
echo 2 > /sys/kernel/mm/ksm/run
../common/shutdown_vms.sh ${redis_vm}
sleep 60
../common/vm_check.sh ${redis_vm}
sleep 10
