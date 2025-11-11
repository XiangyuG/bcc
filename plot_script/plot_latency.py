import re
import matplotlib.pyplot as plt
import numpy as np
import sys

if len(sys.argv) != 5:
    print("Usage: python3 plot_latency.py <trace_output_file> <ACC/DROP/HYBRID> <OPT/NAIVE> <num of test cases> ")
    sys.exit(1)

filename = sys.argv[1]
print(f"Reading from file: {filename}")
result = sys.argv[2]
assert result in ["ACC", "DROP", "HYBRID"], "Mode must be one of ACC, DROP, HYBRID"
mode = sys.argv[3]
assert mode in ["OPT", "NAIVE"], "Mode must be one of OPT, NAIVE"
num = sys.argv[4]

# ---- Raw trace output ----
with open(filename, "rb") as f:
    raw_data = f.read()

# ---- Step 1: Extract numeric latency values ----
matches = re.findall(r"latency=(\d+)\s*ns", raw_data.decode(errors="ignore"))

if not matches:
    print("⚠️  No latency values found (ignored non-matching lines).")
    sys.exit(0)

latencies = np.array([int(x) for x in matches])

# ---- Step 2: Basic statistics ----
mean_latency = np.mean(latencies)
median_latency = np.median(latencies)
p99_latency = np.percentile(latencies, 99)
std_v_latency = np.std(latencies)

print(f"Count: {len(latencies)} samples")
print(f"Mean: {mean_latency:.2f} ns")
print(f"Median: {median_latency:.2f} ns")
print(f"Std Dev: {std_v_latency:.2f} ns")
print(f"99th Percentile: {p99_latency:.2f} ns")
print(f"Min: {np.min(latencies)} ns", f"Max: {np.max(latencies)} ns")

filtered = [x for x in latencies if x <= p99_latency]

# ---- Step 3: Plot histogram ----
plt.figure(figsize=(8, 5))
plt.hist(filtered, bins=range(min(filtered), max(filtered)+1), color='steelblue', edgecolor='black', alpha=0.7)
plt.title("Latency (" + mode + " approach + " + result + ") Distribution (ns)")
plt.xlabel("Latency (ns)")
plt.ylabel("Count")
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Annotate key stats
plt.axvline(mean_latency, color='red', linestyle='--', linewidth=1.5, label=f'Mean: {mean_latency:.1f} ns')
plt.axvline(median_latency, color='green', linestyle='--', linewidth=1.5, label=f'Median: {median_latency:.1f} ns')
plt.axvline(std_v_latency, color='blue', linestyle='--', linewidth=1.5, label=f'STD: {std_v_latency:.1f} ns')
plt.axvline(p99_latency, color='orange', linestyle='--', linewidth=1.5, label=f'P99: {p99_latency:.1f} ns')
# plt.axvline(np.min(latencies), color='purple', linestyle='--', linewidth=1.5, label=f'Min: {np.min(latencies):.1f} ns')
# plt.axvline(np.max(latencies), color='purple', linestyle='--', linewidth=1.5, label=f'Max: {np.max(latencies):.1f} ns')
plt.legend()

plt.tight_layout()

# ---- Step 4: Save to PDF ----
output_file = result + "_" + mode + str(num) + ".pdf"
plt.savefig(output_file, format='pdf')
print(f"Saved plot to {output_file}")
