import time
import math

print("starting cpu workload service", flush=True)

counter = 0

while True:
    for i in range(2_000_000):
        counter = (counter + i * i) % 1_000_003

    if counter % 100 == 0:
        print("service is still running", flush=True)

    time.sleep(0.01)
