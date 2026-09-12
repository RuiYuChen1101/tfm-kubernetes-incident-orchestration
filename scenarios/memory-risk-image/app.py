import time

data = []

for i in range(120):
    data.append("x" * 1024 * 1024)
    print(f"allocated {i + 1} MB", flush=True)
    time.sleep(2)

print("allocation phase complete; holding allocated memory", flush=True)

while True:
    print("steady state; allocated memory is being retained", flush=True)
    time.sleep(60)
