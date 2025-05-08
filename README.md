# ATC-2025-Paraksm

Our artifact contains the linux kernel source files for $\texttt{Para-ksm}$ and provides instructions on how to reproduce key experimental results shown in the paper. There are two key sets of experiments: 

1. Experiments that evaluate the workload performance degradation in system running $\texttt{CPU-ksm}$, $\texttt{DSA-ksm}$, and $\texttt{Para-ksm}$, respectively normalized to  $\texttt{no-ksm}$ (Figure.12).

2. Experiments that evaluate the memory deduplication performance of $\texttt{CPU-ksm}$, $\texttt{DSA-ksm}$, and $\texttt{Para-ksm}$: memory saving and deduplication efficiency (Figure.13, 14).

---

## Testbed Specification

### Hardware
- A server with an Intel 4th-generation Xeon Scalable Processor equipped with DSA (Intel Xeon Gold 8460Y+ CPU).

### Software
- Ubuntu 18.04.6 LTS
- Linux kernel 6.2.15
- gcc 11.4.0
- Python 3
- QEMU-KVM v2.11.1
---

## Contents
- `/scripts` contains scripts to reproduce figures in the paper.
- `/linux-paraksm` contains a modifed Linux Kernel source code with $\texttt{Para-ksm}$ implementation.
- `README.md` contains instructions to build the kernel and run the experiments.
---

## Experiment Workflow
For setting up the environment and building from scratch, please follow steps 1, 2, and 3.

For ATC 2025 AE, we have already cloned this repo and precompiled the kernel on the server. The kernel is already installed on the server. All the necessary drivers and libraries are installed on server and benchmarks are ready in the virtual machines. You can skip step 1, 2, and only perform step 3 for result reproduction.

### 1. Kernel compilation
To compile the kernel, please follow these steps:
```
$ cd /linux-paraksm
$ bash make.sh
```
This will compile the kernel and create a new kernel image in the server.

### 2. Kernel selection
Please make sure the following kernel boot parameters are properly set in `/etc/default/grub` on the server. 
```
GRUB_DEFAULT='Advanced options for GNU/Linux>GNU/Linux, with Linux 6.2.15-paraksm'
GRUB_CMDLINE_LINUX_DEFAULT='quiet intel_iommu=on,sm_on no5lvl splash efi=nosoftreserve transparent_hagepages=never'
```

Then, to apply these modifications, a reboot is required:
```
$ sudo update-grub
$ sudo reboot
```

### 3. Experiment execution
1. Set the reviwer_id in the `/scripts/common/for_reviwers.sh`. This is only necessary for the reviewers to make sure the reproduced results are placed into folders with their reviewer IDs.
2. Run experiments on the server by
    ```
    $ cd /scripts/fig12-14/
    $ bash run.sh
    ``` 

    Within the `run.sh` script, you can specify the experiment you want to run by commenting out the unwanted lines. The script by default runs all the experiments with $\texttt{Liblinear}$, $\texttt{Graph500}$ and $\texttt{Redis}$ benchmarks. The script will automatically run the experiments and save the results in the `/results/reviwer_id` folder.
3. The figures (Figure 12, 13 and 14) can be plotted and saved as `.png` by running the `bash plot.sh` under the `/scripts/fig12-14/` folder. 
---


## Experiments to reproduce

### Application performance
1. Performance degradation of $\texttt{Liblinear}$, $\texttt{Graph500}$ and $\texttt{Redis}$ on systems that deploy $\texttt{CPU-ksm}$, $\texttt{DSA-ksm}$, and $\texttt{Para-ksmC}$, normalized to those of a system without running $\texttt{ksm}$ ($\texttt{no-ksm}$) (Figure 12). Specifically, we use execution time as the performance metric for $\texttt{Liblinear}$ and $\texttt{Graph500}$ and 99th-percentile (p99) latency for $\texttt{Redis}$.

### Memory deduplication performance
1. Memory saving over the a time period using $\texttt{Liblinear}$ as a representative workload in systems that deploy $\texttt{CPU-ksm}$, $\texttt{DSA-ksm}$, and $\texttt{Para-ksmC}$, reflecting trends observed across other workloads. (Figure. 13).

2. Memory deduplication efficiency of $\texttt{DSA-ksm}$ and $\texttt{Para-ksmC}$ normalized to $\texttt{CPU-ksm}$ across workloads. Deduplication efficiency is measured as the memory savings per 1K CPU cycles consumed by the aforementioned three deduplication features.

---




