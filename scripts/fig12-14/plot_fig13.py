import pandas as pd
import matplotlib.pyplot as plt
import sys

r_id = sys.argv[1]

df_cpu = pd.read_csv(f"./result_{r_id}/liblinear/ksm_stat/liblinear_cpu_single_1_1_5_0.csv")
df_dsa = pd.read_csv(f"./result_{r_id}/liblinear/ksm_stat/liblinear_dsa_single_1_1_rt_30.csv")
df_candidate = pd.read_csv(f"./result_{r_id}/liblinear/ksm_stat/liblinear_candidate_1_256_rt_95.csv")

df_cpu["memory_saving(GB)"] = df_cpu["memory_saving(MB)"] / 1024
df_dsa["memory_saving(GB)"] = df_dsa["memory_saving(MB)"] / 1024
df_candidate["memory_saving(GB)"] = df_candidate["memory_saving(MB)"] / 1024

df_cpu_trimmed = df_cpu[df_cpu["time(s)"] <= 200]
df_dsa_trimmed = df_dsa[df_dsa["time(s)"] <= 200]
df_candidate_trimmed = df_candidate[df_candidate["time(s)"] <= 200]

plt.figure(figsize=(6, 3))
plt.plot(df_cpu_trimmed["time(s)"], df_cpu_trimmed["memory_saving(GB)"],
         color='green', label="CPU-ksm")
plt.plot(df_dsa_trimmed["time(s)"], df_dsa_trimmed["memory_saving(GB)"],
         color='blue', label="DSA-ksm")
plt.plot(df_candidate_trimmed["time(s)"], df_candidate_trimmed["memory_saving(GB)"],
         color='orange', label="Para-ksmC")

plt.xlabel("Time (s)")
plt.ylabel("Mem. savings (GB)")
plt.legend()
plt.ylim(0,20)
plt.grid(True, linestyle='--', linewidth=0.5)
plt.tight_layout()
#plt.show()
plt.savefig('fig13.png')

