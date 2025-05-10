#!/bin/bash

#########################################################
# 			CONFIG PATH			#
#########################################################
source ../common/config.sh
source ../common/for_reviewers.sh
data_dir=./result_${reviewer_id}/liblinear
script_dir=../common/data_parsing

#########################################################
# 			PARAM SET			#
#########################################################
# workload
workloads=("liblinear")

# system mode
system_modes=("no_ksm" "cpu_single" "dsa_single" "candidate") 

measure_time=5

declare -A tree_sizes
declare -A cand_sizes
declare -A nice_values
declare -A usleep_times

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

# usleep
usleep_times["no_ksm"]="0"
usleep_times["cpu_single"]="0"
usleep_times["dsa_single"]="50" 
usleep_times["candidate"]="95"


#########################################################
# 			GET VALUE			#
#########################################################
echo "workload,system_mode,tree_size,cand_size,usleep_time_min(us),exec_time,llc_miss_rate(%),ksmd_cpu_utilization(%),dedup_efficiency,memory_saving(MB)"
for workload in "${workloads[@]}"; do
for system_mode in "${system_modes[@]}"; do
for tree_size in ${tree_sizes[${system_mode}]}; do
for cand_size in ${cand_sizes[${system_mode}]}; do
for nice_value in ${nice_values[${system_mode}]}; do
for usleep_time in ${usleep_times[${system_mode}]}; do
file_name=${workload}_${system_mode}_${tree_size}_${cand_size}_${nice_value}_${usleep_time}

# Run Time
file_path=${data_dir}/run_time/${file_name}_run_time.dat
last_line=$(tail -n 1 "$file_path")
run_time_affected_VM=$(echo "$last_line" | grep -oP 'affected: \K[0-9.]+(?=,.*)' )
avg_run_time_not_affected_VM=$(echo "$last_line" | grep -oP 'not_affected: \K[0-9.]+' )

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
# memory_saving=$(tail -n 1 "$file_path" | awk -F',' '{print $NF}')

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
if [ $system_mode != "no_ksm" ]; then
	file_path=${data_dir}/cpu_util/${file_name}_ksm_per_second.dat
	script_file_path=$script_dir/ksm_cycle_by_time.sh 
	ksm_cpu_cycles_by_time=$("$script_file_path" "$file_path" "$measure_time")

	file_path=${data_dir}/ksm_stat/${file_name}.csv
	get_line=$((measure_time + 2))
	memory_saving_by_time_start=$(head -n 2 "$file_path" | tail -n 1 | awk -F',' 'NR==1 {print $NF}')
	memory_saving_by_time_end=$(head -n $get_line "$file_path" | tail -n 1 | awk -F',' '{print $NF}')
	memory_saving_by_time=$((memory_saving_by_time_end - memory_saving_by_time_start))
	# memory_saving_by_time=$(head -n $get_line "$file_path" | tail -n 1 | awk -F',' '{print $NF}')
fi

# Calculation
llc_miss_rate=$(echo "scale=1; 100*($load_misses + $store_misses)/($loads + $stores)" | bc)
run_time_increase_ratio=$(echo "scale=1; 100 * ($run_time_affected_VM-$avg_run_time_not_affected_VM)/$avg_run_time_not_affected_VM" | bc)
if [ $system_mode = "no_ksm" ]; then
	ksmd_cpu_utilization=0
	memory_saving_per_cpu_cycles=0
	memory_saving_per_cpu_cycles_by_time=0
else
	ksmd_cpu_utilization=$(echo "scale=1; 100*$ksm_cpu_cycles/$total_cpu_cycles" | bc)
	memory_saving_per_cpu_cycles=$(echo "scale=3; 1024 * 1024 * $memory_saving/$ksm_cpu_cycles" | bc)
	memory_saving_per_cpu_cycles_by_time=$(echo "scale=3; 1024 * 1024 * $memory_saving_by_time/$ksm_cpu_cycles_by_time" | bc)
fi

echo "$workload,$system_mode,$tree_size,$cand_size,$usleep_time,$run_time_affected_VM,$llc_miss_rate,$ksmd_cpu_utilization,$memory_saving_per_cpu_cycles,$memory_saving"

done
done
done
done
done
done
