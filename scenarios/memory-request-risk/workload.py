import time

blocks = []

while len(blocks) < 96:
    blocks.append(bytearray(1024 * 1024))
    print(f"memory workload active: {len(blocks)} MiB allocated", flush=True)
    time.sleep(0.2)

while True:
    print("memory workload active", flush=True)
    time.sleep(10)
