import pandas as pd
import matplotlib.pyplot as plt

#data_dir="./data/find_best_batch_size/spec"
#data_dir="./data/find_best_batch_size/btree"
#data_dir="./data/find_best_batch_size/spec_hybrid"
#data_dir="./data/find_best_batch_size/btree_hybrid"
#data_dir="./data/find_best_batch_size/cand_with_set_up"
#data_dir="./data/find_best_batch_size/cand"
#data_dir="./data/find_best_batch_size/cand_hybrid"
#data_dir="./data/find_best_batch_size/btree_cand/no_vm"
#data_dir="./data/find_best_batch_size/btree_cand_hybrid/no_vm"
#data_dir="./data/find_best_batch_size/spec_cand/no_vm"
data_dir="./data/find_best_batch_size/spec_cand_hybrid/no_vm"

# Load all the CSV files
files = {
    #"1": f"{data_dir}/1.csv",
    #"4": f"{data_dir}/4.csv",
    # "5": f"{data_dir}/5.csv",
    # "6": f"{data_dir}/6.csv",
    # "7": f"{data_dir}/7.csv",
    #"8": f"{data_dir}/8.csv",
    # "9": f"{data_dir}/9.csv",
    # "10": f"{data_dir}/10.csv",
    # "11": f"{data_dir}/11.csv",
    # "12": f"{data_dir}/12.csv",
    # "13": f"{data_dir}/13.csv",
    # "14": f"{data_dir}/14.csv",
    # "15": f"{data_dir}/15.csv",
    #"16": f"{data_dir}/16.csv",
    #"32": f"{data_dir}/32.csv",
    #"64": f"{data_dir}/64.csv",
    # "128": f"{data_dir}/128.csv",
    #"256": f"{data_dir}/256.csv",
    # "512": f"{data_dir}/512.csv",
    #"1024": f"{data_dir}/1024.csv",
    "4_4": f"{data_dir}/4_4.csv",
    "4_16": f"{data_dir}/4_16.csv",
    "4_64": f"{data_dir}/4_64.csv",
    # "4_256": f"{data_dir}/4_256.csv",
    "16_4": f"{data_dir}/16_4.csv",
    "16_16": f"{data_dir}/16_16.csv",
    # "16_64": f"{data_dir}/16_64.csv",
    "32_4": f"{data_dir}/32_4.csv",
    "32_16": f"{data_dir}/32_16.csv",
    # "32_64": f"{data_dir}/32_64.csv",
    "64_4": f"{data_dir}/64_4.csv",
    "64_16": f"{data_dir}/64_16.csv",
    "256_4": f"{data_dir}/256_4.csv",
}

# Read CSV files into dataframes
dataframes = {name: pd.read_csv(path) for name, path in files.items()}

# Define the y-axes
# y_axes = ['compare', 'checksum', 'memory_saving(MB)']
# titles = ['Compare over Time', 'Checksum over Time', 'Memory Saving over Time']
y_axes = ['compare', 'checksum', 'pages_shared', 'pages_sharing', 'pages_unshared', 'pages_volatile', 'stable_node_chains', 'stable_node_dups', 'memory_saving(MB)']
titles = ['Compare over Time', 'Checksum over Time', 'Pages_shared over Time', 'Pages_sharing over  Time', 'Pages_unshared over Time', 'Pages_volatile over Time', 'Stable_node_chains over Time', 'Stable_node_dups over Time', 'Memory Saving over Time']

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
