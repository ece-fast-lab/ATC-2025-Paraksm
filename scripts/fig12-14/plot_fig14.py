import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import sys

r_id = sys.argv[1]

redis_df = pd.read_csv(f"./result_{r_id}/redis.csv")
liblinear_df = pd.read_csv(f"./result_{r_id}/liblinear.csv")
graph500_df = pd.read_csv(f"./result_{r_id}/graph500.csv")

redis_df = redis_df[redis_df['workload'].isin(['a', 'b', 'c', 'd'])]
redis_df['workload'] = redis_df['workload'].apply(lambda x: f"YCSB-{x}")
liblinear_df['workload'] = 'Liblinear'
graph500_df['workload'] = 'Graph 500'

redis_filtered = redis_df[redis_df['system_mode'].isin(['cpu_single', 'dsa_single', 'candidate'])]
liblinear_filtered = liblinear_df[liblinear_df['system_mode'].isin(['cpu_single', 'dsa_single', 'candidate'])]
graph500_filtered = graph500_df[graph500_df['system_mode'].isin(['cpu_single', 'dsa_single', 'candidate'])]

all_df = pd.concat([redis_filtered, liblinear_filtered, graph500_filtered])

mode_map = {
    'cpu_single': 'cpu-ksm',     
    'dsa_single': 'DSA-ksm',
    'candidate': 'Para-ksmC'
}
all_df['system_mode'] = all_df['system_mode'].map(mode_map)

cpu_baseline = all_df[all_df['system_mode'] == 'cpu-ksm'].set_index('workload')['dedup_efficiency']
all_df = all_df.set_index('workload')
all_df['baseline'] = cpu_baseline
all_df = all_df.reset_index()
all_df['normalized_eff'] = all_df['dedup_efficiency'] / all_df['baseline']

pivot_df = all_df.pivot(index='workload', columns='system_mode', values='normalized_eff')

geomean = pivot_df.prod()**(1/len(pivot_df))
pivot_df.loc['Geomean'] = geomean

pivot_df = pivot_df.drop(columns=['cpu-ksm'])

colors = {'DSA-ksm': '#5B9BD5', 'Para-ksmC': '#FFC000'}
bar_width = 0.35
font_size = 12

x = np.arange(len(pivot_df.index))
fig, ax = plt.subplots(figsize=(8, 3))

bar1 = ax.bar(x - bar_width/2, pivot_df['DSA-ksm'], bar_width, label='DSA-ksm', color=colors['DSA-ksm'])
bar2 = ax.bar(x + bar_width/2, pivot_df['Para-ksmC'], bar_width, label='Para-ksmC', color=colors['Para-ksmC'])

ax.set_ylabel("Dedup. efficiency\n(norm. cpu-ksm)", fontsize=font_size)
ax.set_xticks(x)
ax.set_xticklabels(pivot_df.index, rotation=45, ha='right', fontsize=font_size)
ax.set_ylim(0, 2.0)
ax.legend(loc='upper center', ncol=2, fontsize=font_size)

plt.tight_layout()
#plt.show()
plt.savefig('fig14.png')
