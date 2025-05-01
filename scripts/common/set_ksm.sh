#!/bin/bash

set_bit() {
    local value=$1
    local bit_position=$2

    local mask=$((1 << bit_position))

    local new_value=$((value | mask))

    echo $new_value
}

check_bit() {
    local value=$1
    local bit_position=$2

    local mask=$((1 << bit_position))

    if (( (value & mask) != 0 )); then
        echo "1"
    else
        echo "0"
    fi
}

# DSA COMPLETION MODE:
# 0: DSA ASYNC MODE (USING IRQ)
# 1: DSA SPIN POLLING MODE
# 2: DSA SPIN POLLING WITH WAIT MODE
# 3: DSA MWAIT MODE

ksm_sysfs="/sys/kernel/mm/ksm"

# KSM common config
dsa_on=0
batch_mode=0
cand_batch_size=1
tree_batch_size=1

# DSA config
dsa_completion_mode="async" # [async, spin, spin_wait, mwait, spin_sched, mwait_sched]
dsa_completion_enum=0
hybrid=0
dsa_completion_modes=("async" "spin" "spin_wait" "mwait" "spin_sched" "mwait_sched")

usage() {
	echo "Usage: $0 [--dsa] [--cand-batch] [--spec-batch] [--cand-batch-size <value>] [--tree-batch-size <value>] [--dsa-comp-mode <value>] [--dsa-cpu-hybrid]"
	echo "	--dsa				Use DSA"
	echo "	--cand-batch			Enable KSM candidate batching mode"
	echo "	--spec-batch			Enable KSM speculative batching mode"
	echo "	--cand-batch-size		Candidate batching size"
	echo "	--tree-batch-size		Tree batching size (for Spec)"
	echo "	--dsa-comp-mode			DSA completion mode (Default: async)"
	echo "					[{async}, spin, spin_wait, mwait, spin_sched, mwait_sched]"
	echo "	--dsa-cpu-hybrid		Enable DSA CPU Hybrid mode"
	echo "					(Can't use with batching mode)"

	exit 1
}


ksm_reset() {
	sudo systemctl stop ksmtuned
	sudo systemctl stop ksm
	echo 2 > $ksm_sysfs/run

	echo 0 > $ksm_sysfs/run
	echo 0 > $ksm_sysfs/dsa_on

	echo 0 > $ksm_sysfs/dsa_completion_mode
	echo 0 > $ksm_sysfs/dsa_cpu_hybrid_mode

	echo 0 > $ksm_sysfs/batch_mode
	echo 1 > $ksm_sysfs/batch_size_for_candidate
	echo 1 > $ksm_sysfs/batch_size_for_tree

	echo 0 > $ksm_sysfs/ksm_debug_on
}

dsa_init() {
	sudo /home/mhkim/kernels/linux-ksm-batch/dsa-setup.sh -d dsa0
	echo 1024 > /sys/devices/pci0000:6a/0000:6a:01.0/dsa0/wq0.0/max_batch_size
	sudo /home/mhkim/kernels/linux-ksm-batch/dsa-setup.sh -d dsa0 -w 2 -m d -e 4
}

setup_ksm() {
	ksm_reset

	dsa_init

	echo $batch_mode
	echo $batch_mode > $ksm_sysfs/batch_mode
	echo $cand_batch_size > $ksm_sysfs/batch_size_for_candidate
	echo $tree_batch_size > $ksm_sysfs/batch_size_for_tree

	if [[ "$dsa_on" -eq 1 ]]; then
		echo $dsa_completion_enum > $ksm_sysfs/dsa_completion_mode

		echo 1 > $ksm_sysfs/dsa_on

		if [[ "$hybrid" -eq 1 ]]; then
			echo 1 > $ksm_sysfs/dsa_cpu_hybrid_mode
		fi
	fi

	echo 1 > $ksm_sysfs/run
}

main() {
	while [[ "$#" -gt 0 ]]; do
		case $1 in
		--dsa)
			dsa_on=1
			;;
		--cand-batch)
			batch_mode=$(set_bit $batch_mode 0)
			;;
		--spec-batch)
			batch_mode=$(set_bit $batch_mode 1)
			btree_on=$(check_bit $batch_mode 2)
			if [[ "$btree_on" -eq 1 ]]; then
				usage
			fi
			;;
		--cand-batch-size)
			cand_batch_size="$2"
			shift
			;;
		--tree-batch-size)
			tree_batch_size="$2"
			shift
			;;
		--dsa-comp-mode)
			dsa_completion_mode="$2"
			found=0
			enum=0
			for mode in "${dsa_completion_modes[@]}"; do
				if [[ "$dsa_completion_mode" == "$mode" ]]; then
					found=1
					dsa_completion_enum=$enum
					break
				fi
				enum=$((enum+1))
			done
			if [[ "$found" -eq 0 ]]; then
				usage
			fi
			shift
			;;
		--dsa-cpu-hybrid)
			hybrid=1
			;;
		*)
			usage
			;;
		esac
		shift
	done

	setup_ksm

	grep . $ksm_sysfs/*
}


main $@
