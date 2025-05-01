import pandas as pd
import matplotlib.pyplot as plt

# data_dir="/home/mhkim/workspace/dsa-ksm/graph500/atc_data/mem_saving/stat"
# data_dir="/home/mhkim/workspace/dsa-ksm/graph500/atc_data/fig_10/stat"
data_dir="/home/mhkim/workspace/dsa-ksm/redis-bench/atc_data/mem_saving/stat"

# Load all the CSV files
files = {
    # "dsa_single": f"{data_dir}/liblinear_dsa_single_1_1_cat_rt_30.csv",
    # "dsa_single": f"{data_dir}/graph500_dsa_single_1_1_cat_rt_30.csv",
    # "dsa_single": f"{data_dir}/c_dsa_single_1_1_rt_30.csv",
    "candidate": f"{data_dir}/c_candidate_1_256_rt_95.csv",
}

# Read CSV files into dataframes
dataframes = {name: pd.read_csv(path) for name, path in files.items()}

# Define the y-axes
y_axes = ['memory_saving(MB)']
titles = ['Memory Saving over Time']
# y_axes = ['compare', 'checksum', 'pages_shared', 'pages_sharing', 'pages_unshared', 'pages_volatile', 'stable_node_chains', 'stable_node_dups', 'memory_saving(MB)']
# titles = ['Compare over Time', 'Checksum over Time', 'Pages_shared over Time', 'Pages_sharing over  Time', 'Pages_unshared over Time', 'Pages_volatile over Time', 'Stable_node_chains over Time', 'Stable_node_dups over Time', 'Memory Saving over Time']

plt.rcParams.update({'font.size': 20})
line_width = 4.0
marker_size = 5

# Plot each graph individually
for i, y_axis in enumerate(y_axes):
    plt.figure(figsize=(10, 5))
    for j, (name, df) in enumerate(dataframes.items()):
        plt.plot(df['time(s)'], df[y_axis], label=name, linewidth=line_width)
    plt.title(titles[i])
    plt.xlabel('Time (s)')
    plt.ylabel(y_axis)
    plt.legend()
    plt.tight_layout()
    plt.show()
