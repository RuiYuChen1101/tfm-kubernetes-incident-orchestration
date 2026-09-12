import time

value = 1
last_report = time.time()

while True:
    value = (value * 1664525 + 1013904223) % 4294967296

    now = time.time()
    if now - last_report >= 10:
        print("cpu workload active", flush=True)
        last_report = now
