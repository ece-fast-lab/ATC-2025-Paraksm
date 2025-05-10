import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import gmean
import sys

r_id = sys.argv[1]

redis_df = pd.read_csv(f"./result_{r_id}/redis.csv")
liblinear_df = pd.read_csv(f"./result_{r_id}/liblinear.csv")
graph500_df = pd.read_csv(f"./result_{r_id}/graph500.csv")

redis_no_ksm = redis_df[redis_df['system_mode'] == 'no_ksm']
redis_ksm = redis_df[redis_df['system_mode'].isin(['cpu_single', 'dsa_single', 'candidate'])]
liblinear_no_ksm = liblinear_df[liblinear_df['system_mode'] == 'no_ksm']
liblinear_ksm = liblinear_df[liblinear_df['system_mode'].isin(['cpu_single', 'dsa_single', 'candidate'])]
graph500_no_ksm = graph500_df[graph500_df['system_mode'] == 'no_ksm']
graph500_ksm = graph500_df[graph500_df['system_mode'].isin(['cpu_single', 'dsa_single', 'candidate'])]

def compute_perf_degradation(ksm_df, base_df, workload_col, perf_col):
    result = []
    modes = ['cpu_single', 'dsa_single', 'candidate']
    for mode in modes:
        values = []
        for _, row in ksm_df[ksm_df['system_mode'] == mode].iterrows():
            workload = row[workload_col]
            base_val = base_df[(base_df[workload_col] == workload)][perf_col].values
            if len(base_val) == 0 or np.isnan(base_val[0]) or base_val[0] == 0:
                values.append(np.nan)
            else:
                values.append(row[perf_col] / base_val[0])
        result.append(values)
    return result

liblinear_deg = compute_perf_degradation(liblinear_ksm, liblinear_no_ksm, 'workload', 'exec_time')
graph500_deg = compute_perf_degradation(graph500_ksm, graph500_no_ksm, 'workload', 'exec_time')
redis_read_deg = compute_perf_degradation(redis_ksm, redis_no_ksm, 'workload', 'read_latency')
redis_update_deg = compute_perf_degradation(redis_ksm, redis_no_ksm, 'workload', 'update_latency')
redis_insert_deg = compute_perf_degradation(redis_ksm, redis_no_ksm, 'workload', 'insert_latency')

cpu_ksm = [
    liblinear_deg[0][0], graph500_deg[0][0],
    redis_read_deg[0][0], redis_update_deg[0][0],
    redis_read_deg[0][1], redis_update_deg[0][1],
    redis_read_deg[0][2],
    redis_read_deg[0][3], redis_insert_deg[0][3]
]
dsa_ksm = [
    liblinear_deg[1][0], graph500_deg[1][0],
    redis_read_deg[1][0], redis_update_deg[1][0],
    redis_read_deg[1][1], redis_update_deg[1][1],
    redis_read_deg[1][2],
    redis_read_deg[1][3], redis_insert_deg[1][3]
]
para_ksm = [
    liblinear_deg[2][0], graph500_deg[2][0],
    redis_read_deg[2][0], redis_update_deg[2][0],
    redis_read_deg[2][1], redis_update_deg[2][1],
    redis_read_deg[2][2],
    redis_read_deg[2][3], redis_insert_deg[2][3]
]

cpu_ksm.append(gmean([x for x in cpu_ksm if not np.isnan(x)]))
dsa_ksm.append(gmean([x for x in dsa_ksm if not np.isnan(x)]))
para_ksm.append(gmean([x for x in para_ksm if not np.isnan(x)]))

labels = [
    'Liblinear', 'Graph500',
    'Read\nYCSB-a', 'Update\nYCSB-a',
    'Read\nYCSB-b', 'Update\nYCSB-b',
    'Read\nYCSB-c',
    'Read\nYCSB-d', 'Insert\nYCSB-d',
    'GeoMean'
]

x = np.arange(len(labels))
width = 0.25

fig, ax = plt.subplots(figsize=(10, 3.5))
ax.bar(x - width, cpu_ksm, width, label='CPU-ksm', color='forestgreen')
ax.bar(x, dsa_ksm, width, label='DSA-ksm', color='cornflowerblue')
ax.bar(x + width, para_ksm, width, label='Para-ksmC', color='goldenrod')

ax.set_ylabel('Perf. degradation\nnorm. no-ksm', fontsize=9)
ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=8)
ax.legend(fontsize=8, ncol=3, loc='upper center', bbox_to_anchor=(0.5, 1.10))
ax.grid(axis='y', linestyle='--', linewidth=0.5)

group_separators = [1.5, 3.5, 5.5, 6.5, 8.5]
for sep in group_separators:
    ax.axvline(sep, color='black', linewidth=0.8)

fig.tight_layout()
plt.savefig('fig12.png')
