import subprocess
import os
import sys
from parse import parse_files

print("Creating ip file...")
filename_in = "ips.txt"
filename_out = "scripts/aws/ips"

f_in = open(filename_in, "r")
f_out = open(filename_out, "w")

for i, line in enumerate(f_in):
    port = 9000 + i
    f_out.write(line.splitlines()[0] + ":" + str(port) + "\n")

f_in.close()
f_out.close()

if len(sys.argv) > 1:
    print("Installing...")
    subprocess.run("bash scripts/aws/do_setup.sh", shell=True)

print("Deleting old logs...")
for file in os.scandir("logs"):
    if file.name.endswith(".log"):
        os.unlink(file.path)

print("Running experiments...")
subprocess.run("bash scripts/aws/do_test.sh", shell=True)

print("Parsing logs...")
timedelta, counter = parse_files("logs/")
beacons_per_seconds = 1 / ((timedelta.total_seconds())/counter)
print(f'Beacons per seconds: {beacons_per_seconds}')
print(f'Average time between two beacon values: {timedelta/counter}ms')
