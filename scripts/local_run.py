import subprocess
import sys
import time
import os
from aws.parse import parse_files


def create_ip_files(nodes: int, filename: str):
    print("Creating ip files...")
    prefix = "127.0.0.1:"
    ips = []

    with open(filename, "w", encoding="utf-8") as f:
        for i in range(nodes):
            port = 9000 + i
            f.write(prefix + str(port) + '\n')
            ips.append(prefix + str(port) + '\n')


def delete_logs(path: str):
    print("Deleting old logs...")
    try:
        for file in os.scandir(path):
            if file.name.endswith(".log"):
                os.unlink(file.path)
    except:
        os.mkdir(path)


def generate_config(nodes: int):
    print("Generating configs...")
    subprocess.run("cargo build --bin generator --release",
                   shell=True, check=False)
    subprocess.run(
        f'target/release/generator {nodes}', shell=True, check=False)


def compile_project(app_name: str):
    print("Compiling...")
    subprocess.run(
        f'cargo build --bin {app_name} --release', shell=True, check=False)


def test_run(nodes: int, app_name: str, filename: str, duration: int):
    # start all nodes
    subprocess.run(f'killall -9 {app_name}', shell=True, check=False)

    print("Starting nodes...")
    processes = []
    for i in range(nodes):
        cmd = f'target/release/app {i} {filename} 2 &> logs/{i}.log'
        p = subprocess.Popen(cmd, shell=True)
        processes.append(p)

    # wait and kill nodes
    time.sleep(duration)
    print("Shutting down nodes...")
    for p in processes:
        p.kill()

    # just to be sure
    subprocess.run(f'killall -9 {app_name}', shell=True, check=False)


def parse_logs(path: str):
    print("Parsing logs...")
    timedelta, counter = parse_files(path + "/")
    beacons_per_seconds = 1 / ((timedelta.total_seconds())/counter)
    print(f'Beacons per seconds: {beacons_per_seconds}')
    print(f'Average time between two beacon values: {timedelta/counter}ms')


def main():
    if len(sys.argv) < 3:
        print("Argument 1: number of nodes, Argument 2: duration of test run")
        return
    nodes = int(sys.argv[1])
    duration = int(sys.argv[2])
    binary_name = "app"
    filename = "local_ips.txt"
    logs = "logs"

    delete_logs(logs)
    create_ip_files(nodes, filename)
    compile_project(binary_name)
    generate_config(nodes)
    test_run(nodes, binary_name, filename, duration)
    parse_logs(logs)


if __name__ == "__main__":
    main()
