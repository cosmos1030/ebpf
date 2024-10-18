# Network Monitoring and Packet Capture Tools

## Overview

This repository contains scripts designed for monitoring system performance and capturing network packets using **eBPF (Extended Berkeley Packet Filter)** and **Python**. The tools are divided into two main components:

- **Edge (Remote Monitoring):** Runs on edge devices to collect system metrics and capture network packets.
- **Server (Local Data Collection):** Runs on a local server to receive and process data from edge devices.

## Directory Structure

```
.
├── archive                 # Contains additional utility scripts (not explained here)
├── edge
│   └── remote_monitor.py   # Monitors system performance and captures packet data on the edge
├── server
│   └── local_receiver.py   # Receives and processes system metrics and packet events on the server
└── README.md               # This file
```

---

## Environment Setup

### System Requirements

Ensure your system supports eBPF by verifying the kernel and OS versions.

```bash
$ uname -r
6.8.0-45-generic

$ lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.5 LTS
Release:        22.04
Codename:       jammy
```

### Setting Up the Environment

You can set up the environment using Docker (recommended) or manually.

---

### Option 1: Using Docker

#### 1. Clone the Repository

```bash
git clone https://github.com/cosmos1030/ebpf.git
cd ebpf
```

#### 2. Modify `docker-compose.yml`

Update the `volumes` path in the `docker-compose.yml` file to point to the directory where you cloned the `ebpf` repository.

```yaml
# In docker-compose.yml
services:
  server:
    # ...
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
  edge1:
    # ...
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
  edge2:
    # ...
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
  edge3:
    # ...
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
```

Replace `/path/to/your/ebpf` with the actual path where you cloned the repository.

#### 3. Build the Docker Image

Build a Docker image with the eBPF environment:

```bash
docker build -t custom-ubuntu-ebpf .
```

#### 4. Start the Containers

Start one server and three edge device containers using Docker Compose:

```bash
docker rm -f server edge1 edge2 edge3  # Remove existing containers if any
docker compose up -d                   # Start containers in detached mode
```

#### 5. Configure the Edge Devices

After the containers are running, check the virtual IP address of the server container:

```bash
docker exec -it server ip addr show
```

Look for the `eth0` interface and note the IP address (e.g., `172.18.0.3`).

Update the `LOCAL_MACHINE_IP` in `remote_monitor.py` on each edge container to match the server's IP address:

```python
# In edge/remote_monitor.py
LOCAL_MACHINE_IP = "172.18.0.3"  # Replace with your server's IP address
iface_name = "eth0"              # Adjust if necessary
```

#### 6. Running the Scripts

**On the Server:**

1. Access the server container:

   ```bash
   docker exec -it server bash
   ```

2. Switch to root (if not already):

   ```bash
   sudo su
   ```

3. Run the server script:

   ```bash
   python3 server/local_receiver.py
   ```

**On Each Edge Device:**

1. Access the edge container:

   ```bash
   docker exec -it edge1 bash  # Replace 'edge1' with 'edge2' or 'edge3' as needed
   ```

2. Switch to root (if not already):

   ```bash
   sudo su
   ```

3. Run the edge script:

   ```bash
   python3 edge/remote_monitor.py
   ```

---

### Option 2: Manual Setup (Without Docker)

#### 1. Update the System

```bash
sudo apt update
```

#### 2. Install Required Packages

**Install Clang and LLVM (required for compiling eBPF programs):**

```bash
sudo apt install clang llvm
```

Verify the installation:

```bash
llvm-config --version
clang --version
```

**Install BCC tools and Linux headers:**

```bash
sudo apt install bpfcc-tools linux-headers-$(uname -r)
```

Test the installation:

```bash
sudo /usr/sbin/execsnoop-bpfcc
```

**Install libraries for BCC development:**

```bash
sudo apt install libbpfcc libbpf-dev
```

**Install Python libraries:**

```bash
sudo apt install python3-pyroute2 python3-psutil
```

#### 3. Clone the Repository

```bash
git clone https://github.com/cosmos1030/ebpf.git
cd ebpf
```

#### 4. Configure the Scripts

Update `LOCAL_MACHINE_IP`, `LOCAL_MACHINE_PORT`, and `iface_name` in `edge/remote_monitor.py` to match your server's IP address, desired port, and network interface.

#### 5. Running the Scripts

**On the Server:**

1. Switch to root:

   ```bash
   sudo su
   ```

2. Run the server script:

   ```bash
   python3 server/local_receiver.py
   ```

**On the Edge Device:**

1. Switch to root:

   ```bash
   sudo su
   ```

2. Run the edge script:

   ```bash
   python3 edge/remote_monitor.py
   ```

---

## Running the Scripts

> **Note:** Due to permission issues when working with eBPF and network interfaces, make sure to run the Python scripts as `root` using `sudo su` to avoid errors.

### Edge

1. **Update Configuration:**

   - In `edge/remote_monitor.py`, set:

     ```python
     LOCAL_MACHINE_IP = "your_server_ip"  # Replace with your server's IP
     LOCAL_MACHINE_PORT = your_port       # Replace with your desired port
     iface_name = "your_network_interface" # e.g., "eth0"
     ```

2. **Switch to Root:**

   ```bash
   sudo su
   ```

3. **Run the Script:**

   ```bash
   python3 edge/remote_monitor.py
   ```

### Server

1. **Ensure Port Configuration:**

   - In `server/local_receiver.py`, ensure the `LOCAL_MACHINE_PORT` matches the port used by the edge devices.

2. **Switch to Root:**

   ```bash
   sudo su
   ```

3. **Run the Script:**

   ```bash
   python3 server/local_receiver.py
   ```

---

## Scripts Overview

### 1. `edge/remote_monitor.py` (Edge Device)

This script runs on a remote edge device to monitor system metrics and capture network packet data using eBPF. The collected data is sent to a local server via TCP.

- **Features:**
  - eBPF program for packet capture.
  - Filters TCP and UDP packets.
  - Collects system metrics: CPU usage, memory usage, and bandwidth utilization.
  - Sends data periodically to a specified local machine.

- **Configuration:**
  - Set `LOCAL_MACHINE_IP` and `LOCAL_MACHINE_PORT` to the local server's IP and port.
  - Adjust `iface_name` to the appropriate network interface on the remote device.

### 2. `server/local_receiver.py` (Server)

This script runs on the local machine, listening for incoming data from the remote device. It deserializes and processes system metrics and network packet data, then displays the information along with calculated network performance metrics (e.g., throughput and packet delay).

- **Features:**
  - Receives system metrics and packet data.
  - Calculates network metrics: throughput, average packet delay, and packet loss (placeholder).
  - Displays data in a human-readable format.

- **Configuration:**
  - Ensure the `LOCAL_MACHINE_PORT` matches the one used by the remote devices.

---

## Notes

- **Root Privileges:** Due to the permissions required for eBPF and network interfaces, run all scripts as root using `sudo su`.
- **Network Interfaces:** Adjust `iface_name` in `remote_monitor.py` to match the network interface used for monitoring.
- **Port Configuration:** Ensure the port numbers in both scripts are the same and that the port is open and accessible on the server.
- **Docker Volume Mapping:** When using Docker, make sure the `volumes` path in `docker-compose.yml` points to your local `ebpf` directory.
- **Working Directory in Docker:** By setting `working_dir: /mnt/ebpf` in `docker-compose.yml`, you will automatically start in the `/mnt/ebpf` directory when you enter the container.

---

## Contact

For any issues or suggestions for improvements, feel free to open an issue or submit a pull request on the [GitHub repository](https://github.com/cosmos1030/ebpf).