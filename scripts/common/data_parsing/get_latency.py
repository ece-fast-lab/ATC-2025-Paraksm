# Importing necessary module
import pandas as pd
import sys
# from config import *

# workload = sys.argv[1]
# target = sys.argv[2]


data_dir = sys.argv[1] 
file_name = sys.argv[2] 
label_type = sys.argv[3]
is_affected = sys.argv[4]

# Function to calculate average latencies
def calculate_p99_latencies(file_path):
    latency_related_lines = []

    # Reading the file and extracting latency related lines
    with open(file_path, 'r') as file:
        for line in file:
            if 'Latency' in line:
                latency_related_lines.append(line.strip())

    # Extracting and calculating average latencies
    latency_data = {}
    for line in latency_related_lines:
        if '99thPercentileLatency(us)' in line:
            label, latency = line.split(', ')[0], float(line.split(', ')[2])
            if label == '[CLEANUP]':
                continue
            if label not in latency_data:
                latency_data[label] = []
            latency_data[label].append(latency)

    average_latencies = {label: sum(latencies) / len(latencies) for label, latencies in latency_data.items()}
    return average_latencies

def calculate_average_latencies(file_path):
    latency_related_lines = []

    # Reading the file and extracting latency related lines
    with open(file_path, 'r') as file:
        for line in file:
            if 'Latency' in line:
                latency_related_lines.append(line.strip())

    # Extracting and calculating average latencies
    latency_data = {}
    for line in latency_related_lines:
        if 'AverageLatency(us)' in line:
            label, latency = line.split(', ')[0], float(line.split(', ')[2])
            if label == '[CLEANUP]':
                continue
            if label not in latency_data:
                latency_data[label] = []
            latency_data[label].append(latency)

    average_latencies = {label: sum(latencies) / len(latencies) for label, latencies in latency_data.items()}
    return average_latencies


p99s = []
avgs = []    

# print(f"is_affected,label,p99_latencies,average_latencies")


if is_affected == "1": 
    for n in range(3):
        latency_file_path = f"{data_dir}/client{n}_{file_name}"

        p99 = calculate_p99_latencies(latency_file_path)
        avg = calculate_average_latencies(latency_file_path)
        p99s.append(p99)
        avgs.append(avg)

    for label, latency in avgs[0].items():
        p99_total = 0
        avg_total = 0
        p99_all = []
        avg_all = []
        for n in range(3):
            p99_total += p99s[n][label]
            avg_total += avgs[n][label]
            p99_all.append(p99s[n][label])
            avg_all.append(avgs[n][label])

        p99_latencies = p99_total / 3
        average_latencies = avg_total / 3
        p99_max = max(p99_all)
        avg_max = max(avg_all)
        if label == label_type :
            print(f"{p99_latencies:.1f}")
else :
    for n in range(3,30):
        latency_file_path = f"{data_dir}/client{n}_{file_name}"

        p99 = calculate_p99_latencies(latency_file_path)
        avg = calculate_average_latencies(latency_file_path)
        p99s.append(p99)
        avgs.append(avg)

    for label, latency in avgs[0].items():
        p99_total = 0
        avg_total = 0
        p99_all = []
        avg_all = []
        for n in range(3,30):
            p99_total += p99s[n-3][label]
            avg_total += avgs[n-3][label]
            p99_all.append(p99s[n-3][label])
            avg_all.append(avgs[n-3][label])

        p99_latencies = p99_total / 27
        average_latencies = avg_total / 27
        p99_max = max(p99_all)
        avg_max = max(avg_all)
        if label == label_type :
            print(f"{p99_latencies:.1f}")

