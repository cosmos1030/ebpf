# Network Monitoring and Packet Capture Tools

## Overview

This repository contains scripts designed for **monitoring system performance** and **capturing network packets** using **eBPF (Extended Berkeley Packet Filter)** and **Python**. 

The system consists of two main components:

- **Edge (Remote Monitoring):** Runs on edge devices to collect system metrics and capture network packets.
- **Server (Local Data Collection):** Receives and processes data from edge devices.

---

## Directory Structure

```
.
├── archive/                 # Contains additional utility scripts
├── edge/
│   └── remote_monitor.py    # Monitors system performance and captures packet data on edge devices
├── server/
│   └── local_receiver.py    # Receives and processes system metrics and packet events on the server
└── README.md                # This file
```

---

## Environment Setup

### System Requirements

Ensure your system supports eBPF by checking the kernel and OS versions:

```bash
$ uname -r
6.8.0-45-generic

$ lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.5 LTS
Release:        22.04
Codename:       jammy
```

---

### Option 1: Using Docker (Recommended)

#### 1. Clone the Repository

```bash
git clone https://github.com/cosmos1030/ebpf.git
cd ebpf
```

#### 2. Modify `docker-compose.yml`

Update the `volumes` path in the `docker-compose.yml` file to point to your cloned repository:

```yaml
# docker-compose.yml
services:
  server:
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
  edge1:
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
  edge2:
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
  edge3:
    volumes:
      - /path/to/your/ebpf:/mnt/ebpf
```

Replace `/path/to/your/ebpf` with the correct path on your system.

#### 3. Build the Docker Image

```bash
docker build -t custom-ubuntu-ebpf .
```

#### 4. Start the Containers

```bash
docker rm -f server edge1 edge2 edge3  # Remove existing containers (if any)
docker compose up -d                   # Start containers in detached mode
```

#### 5. Configure the Edge Devices

Get the server container's virtual IP:

```bash
docker exec -it server ip addr show eth0
```

Update the `LOCAL_MACHINE_IP` in `remote_monitor.py` with the server's IP:

```python
# edge/remote_monitor.py
LOCAL_MACHINE_IP = "172.18.0.3"  # Replace with server's IP
iface_name = "eth0"              # Network interface (adjust if needed)
```

#### 6. Run the Scripts

- **Server:**

  ```bash
  docker exec -it server bash
  python3 server/local_receiver.py
  ```

- **Edge Devices:**

  ```bash
  docker exec -it edge1 bash  # Use 'edge2' or 'edge3' for other devices
  python3 edge/remote_monitor.py
  ```

---

### Option 2: Manual Setup (Without Docker)

#### 1. Update the System

```bash
sudo apt update
```

#### 2. Install Required Packages

```bash
sudo apt install clang llvm bpfcc-tools linux-headers-$(uname -r)
sudo apt install libbpfcc libbpf-dev python3-pyroute2 python3-psutil sqlite3
```

#### 3. Clone the Repository

```bash
git clone https://github.com/cosmos1030/ebpf.git
cd ebpf
```

#### 4. Configure the Scripts

Update the IP, port, and network interface in `edge/remote_monitor.py`:

```python
LOCAL_MACHINE_IP = "your_server_ip"  # Server IP
LOCAL_MACHINE_PORT = your_port       # Port (e.g., 9999)
iface_name = "your_network_interface" # Network interface (e.g., "eth0")
```

#### 5. Run the Scripts

- **Server:**

  ```bash
  sudo python3 server/local_receiver.py
  ```

- **Edge Devices:**

  ```bash
  sudo python3 edge/remote_monitor.py
  ```

---

## SQLite Database Setup and Usage

On the server, data is stored in `metrics.db`. To interact with the database:

1. Access the database:

   ```bash
   sqlite3 metrics.db
   ```

2. Enable headers for column names:

   ```sql
   .headers on
   ```

3. View the data:

   ```sql
   SELECT * FROM metrics;
   ```

   Example output:

   ```
   id|client_ip|timestamp|cpu_usage|mem_usage|bytes_sent|bytes_recv|throughput|average_delay|packet_loss
   1|172.18.0.5|2024-10-18 07:18:44|3.5|18.0|13118478|13177540|0.0|0.0|N/A
   2|172.18.0.5|2024-10-18 07:18:50|2.5|17.9|13120249|13179153|24760267.8880407|0.000093|N/A
   ```

---

## Scripts Overview

### `edge/remote_monitor.py`

This script runs on edge devices to monitor system performance and capture packet data using eBPF. 

**Features:**
- Monitors CPU, memory, and bandwidth usage.
- Captures TCP and UDP packets with eBPF.
- Sends data periodically to the server via TCP.

**Configuration:**
- Update `LOCAL_MACHINE_IP` with the server's IP.
- Adjust `iface_name` to the correct network interface.

---

### `server/local_receiver.py`

This script runs on the server to receive and process data from edge devices.

**Features:**
- Receives metrics and packet events.
- Calculates network metrics: throughput, average delay, and packet loss (if applicable).
- Displays the collected data in the terminal and stores it in the SQLite database.

---

## Notes

- **Root Privileges:** Use `sudo` or run scripts as `root` to avoid permission issues with eBPF and network interfaces.
- **Network Interfaces:** Adjust `iface_name` in the scripts to match your network interface.
- **Port Configuration:** Ensure that the port numbers are the same on both the edge devices and the server.
- **Docker Volume Mapping:** When using Docker, ensure the `volumes` paths in `docker-compose.yml` point to your local `ebpf` directory.

---

## Contact

For any issues, suggestions, or improvements, feel free to open an issue or submit a pull request on the [GitHub repository](https://github.com/cosmos1030/ebpf).