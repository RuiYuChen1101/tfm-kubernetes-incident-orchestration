import time

print("starting memory workload service", flush=True)

chunks = []
target_mib = 118
chunk_mib = 2

for i in range(target_mib // chunk_mib):
    chunks.append(bytearray(chunk_mib * 1024 * 1024))
    print(f"allocated_memory_mib={(i + 1) * chunk_mib}", flush=True)
    time.sleep(0.2)

print("memory workload reached steady state", flush=True)

counter = 0
while True:
    counter += 1
    if counter % 30 == 0:
        print("service is still running with steady memory usage", flush=True)
    time.sleep(1)
