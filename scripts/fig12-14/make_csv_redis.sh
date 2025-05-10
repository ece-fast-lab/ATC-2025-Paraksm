#!/bin/bash

#########################################################
# 			CONFIG PATH			#
#########################################################
source ../common/config.sh
source ../common/for_reviewers.sh
data_dir=./result_${reviewer_id}/redis
script_dir=../common/data_parsing

#########################################################
# 			PARAM SET			#
#########################################################
# workload
workloads=("a" "b" "c" "d")

system_modes=("no_ksm" "cpu_single" "dsa_single" "candidate")

declare -A tree_sizes
declare -A cand_sizes
declare -A isolates
declare -A nice_values
declare -A usleep_times
declare -A measure_times

# tree size
tree_sizes["no_ksm"]="1"
tree_sizes["cpu_single"]="1"
tree_sizes["dsa_single"]="1"
tree_sizes["candidate"]="1"

# cand size
cand_sizes["no_ksm"]="1"
cand_sizes["cpu_single"]="1"
cand_sizes["dsa_single"]="1"
cand_sizes["candidate"]="256"

# nice_value
nice_values["no_ksm"]="5"
nice_values["cpu_single"]="5"
nice_values["dsa_single"]="rt" 
nice_values["candidate"]="rt" 

# uslee_time
usleep_times["no_ksm"]="0" 
usleep_times["cpu_single"]="0"
usleep_times["dsa_single"]="50"
usleep_times["candidate"]="115" 

measure_times["no_ksm"]="1"
measure_times["cpu_single"]="199"
measure_times["dsa_single"]="199"
measure_times["candidate"]="199"

#########################################################
# 			GET VALUE			#
#########################################################
echo "workload,system_mode,tree_size,cand_size,nice,usleep_time_min(us),read_latency,insert_latency,update_latency,llc_miss_rate(%),ksmd_cpu_utilization(%),dedup_efficiency,memmory_saving(MB)"
for workload in "${workloads[@]}"; do
for system_mode in "${system_modes[@]}"; do
for tree_size in ${tree_sizes[${system_mode}]}; do
for cand_size in ${cand_sizes[${system_mode}]}; do
for nice_value in ${nice_values[${system_mode}]}; do
for usleep_time in ${usleep_times[${system_mode}]}; do
file_name=${workload}_${system_mode}_${tree_size}_${cand_size}_${nice_value}_${usleep_time}

# Run Time
file_dir=${data_dir}/redis_latency
file_path=${file_name}_latency.dat
read_latency_affected_VM=$(python3 "$script_dir"/get_latency.py "$file_dir" "$file_path" [READ] 1)
insert_latency_affected_VM=$(python3 "$script_dir"/get_latency.py "$file_dir" "$file_path" [INSERT] 1)
update_latency_affected_VM=$(python3 "$script_dir"/get_latency.py "$file_dir" "$file_path" [UPDATE] 1)
avg_read_latency_not_affected_VM=$(python3 "$script_dir"/get_latency.py "$file_dir" "$file_path" [READ] 0)
avg_insert_latency_not_affected_VM=$(python3 "$script_dir"/get_latency.py "$file_dir" "$file_path" [INSERT] 0)
avg_update_latency_not_affected_VM=$(python3 "$script_dir"/get_latency.py "$file_dir" "$file_path" [UPDATE] 0)

# Cpu Cycles
file_path=${data_dir}/cpu_util/${file_name}_core.dat
total_cpu_cycles=$(grep "cpu-cycles" ${file_path} | awk '{print $1}')
total_cpu_cycles=$(echo "$total_cpu_cycles" | sed 's/,//g')

file_path=${data_dir}/cpu_util/${file_name}_ksm.dat
ksm_cpu_cycles=$(grep "cpu-cycles" ${file_path} | awk '{print $1}')
ksm_cpu_cycles=$(echo "$ksm_cpu_cycles" | sed 's/,//g')

# Memory Saving
file_path=${data_dir}/ksm_stat/${file_name}.csv
memory_saving_end=$(tail -n 1 "$file_path" | awk -F',' '{print $NF}')
memory_saving_start=$(head -n 2 "$file_path" | tail -n 1 | awk -F',' 'NR==1 {print $NF}')
memory_saving=$((memory_saving_end - memory_saving_start))
# memory_saving=$memory_saving_end 

# LLC Miss Rate
file_path=${data_dir}/llc_miss/${file_name}_core_total.dat
load_misses=$(grep "LLC-load-misses" ${file_path} | awk '{print $1}')
load_misses=$(echo "$load_misses" | sed 's/,//g')
loads=$(grep "LLC-loads" ${file_path} | awk '{print $1}')
loads=$(echo "$loads" | sed 's/,//g')
store_misses=$(grep "LLC-store-misses" ${file_path} | awk '{print $1}')
store_misses=$(echo "$store_misses" | sed 's/,//g')
stores=$(grep "LLC-stores" ${file_path} | awk '{print $1}')
stores=$(echo "$stores" | sed 's/,//g')

# Batch Utilization
file_path=${data_dir}/ksm_breakdown/${file_name}.csv
compare_count=$(tail -n 13 "$file_path" | awk -F',' 'NR==1 {print $3}')
compare_batch_count=$(tail -n 12 "$file_path" | awk -F',' 'NR==1 {print $3}')
crc_count=$(tail -n 10 "$file_path" | awk -F',' 'NR==1 {print $3}')
crc_batch_count=$(tail -n 9 "$file_path" | awk -F',' 'NR==1 {print $3}')

# Memory Saving By Time
file_path=${data_dir}/cpu_util/${file_name}_ksm_per_second.dat
script_file_path=$script_dir/ksm_cycle_by_time.sh 
measure_time=${measure_times[${system_mode}]}
if [ $system_mode = "no_ksm" ]; then
	ksm_cpu_cycles_by_time=0
else
	ksm_cpu_cycles_by_time=$("$script_file_path" "$file_path" "$measure_time")
fi

file_path=${data_dir}/ksm_stat/${file_name}.csv
get_line=$((measure_time + 2))
memory_saving_by_time_start=$(head -n 2 "$file_path" | tail -n 1 | awk -F',' 'NR==1 {print $NF}')
memory_saving_by_time_end=$(head -n $get_line "$file_path" | tail -n 1 | awk -F',' '{print $NF}')
memory_saving_by_time=$((memory_saving_by_time_end - memory_saving_by_time_start))
# memory_saving_by_time=$memory_saving_by_time_end 

# Calculation
llc_miss_rate=$(echo "scale=1; 100*($load_misses + $store_misses)/($loads + $stores)" | bc)
if [ -n "$read_latency_affected_VM" ]; then
	read_latency_increase_ratio=$(echo "scale=1; 100 * $read_latency_affected_VM/$avg_read_latency_not_affected_VM" - 100| bc)
else
	read_latency_affected_VM=NaN
	avg_read_latency_not_affected_VM=NaN
	read_latency_increase_ratio=NaN
fi
if [ -n "$insert_latency_affected_VM" ]; then
	insert_latency_increase_ratio=$(echo "scale=1; 100 * $insert_latency_affected_VM/$avg_insert_latency_not_affected_VM" - 100 | bc)
else
	insert_latency_affected_VM=NaN
	avg_insert_latency_not_affected_VM=NaN
	insert_latency_increase_ratio=NaN
fi
if [ -n "$update_latency_affected_VM" ]; then
	update_latency_increase_ratio=$(echo "scale=1; 100 * $update_latency_affected_VM/$avg_update_latency_not_affected_VM" -100 | bc)
else
	update_latency_affected_VM=NaN
	avg_update_latency_not_affected_VM=NaN
	update_latency_increase_ratio=NaN
fi
if [ $system_mode = "no_ksm" ]; then
	ksmd_cpu_utilization=0
	memory_saving_per_cpu_cycles=0
	memory_saving_per_cpu_cycles_by_time=0
else
	ksmd_cpu_utilization=$(echo "scale=1; 100*$ksm_cpu_cycles/$total_cpu_cycles" | bc)
	memory_saving_per_cpu_cycles=$(echo "scale=3; 1024 * 1024 * $memory_saving/$ksm_cpu_cycles" | bc)
	memory_saving_per_cpu_cycles_by_time=$(echo "scale=3; 1024 * 1024 * $memory_saving_by_time/$ksm_cpu_cycles_by_time" | bc)
fi

echo "$workload,$system_mode,$tree_size,$cand_size,$nice_value,$usleep_time,$read_latency_affected_VM,$insert_latency_affected_VM,$update_latency_affected_VM,$llc_miss_rate,$ksmd_cpu_utilization,$memory_saving_per_cpu_cycles_by_time,$memory_saving"

done
done
done
done
done
done
