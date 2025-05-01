#!/bin/bash

# Input 및 Output 파일 정의
file_path=$1
measure_time=$2

# output_file="output.csv"

# CSV 헤더 추가
# echo "time(s),cpu_cycles" > "$output_file"

# 누적 CPU 사이클 변수 초기화
total_cpu_cycles=0

# 데이터 처리
while read -r line; do
  	# 데이터 형식 확인 (헤더나 빈 줄 제외)
	if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
		continue
	fi
    	# 시간(time)과 현재 CPU 사이클(current_cpu_cycles) 추출
	time=$(echo "$line" | awk '{print $1}' | sed 's/\.[0-9]*//') # 시간에서 소수점 제거
	current_cpu_cycles=$(echo "$line" | awk '{print $2}' | sed 's/,//g') # 쉼표 제거

	# 누적 CPU 사이클 계산
	total_cpu_cycles=$((total_cpu_cycles + current_cpu_cycles))

	if [[ "$time" == "$measure_time" ]]; then
		echo $total_cpu_cycles
		break
	fi
	# 결과를 CSV 형식으로 추가
	# echo "$time,$total_cpu_cycles" >> "$output_file"
done < "$file_path"

# echo "CSV 파일 변환 완료: $output_file"

