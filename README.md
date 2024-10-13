# Network Monitoring and Packet Capture Tools

## Overview

This repository contains scripts designed to monitor system performance and capture network packets using eBPF and Python. The tools are divided into edge (remote monitoring) and server (local data collection) components.

### Directory Structure

```
.
├── archive                 # Contains additional utility scripts
├── edge
│   └── remote_monitor.py    # Monitors system performance and captures packet data on the edge
├── server
│   ├── local_receiver.py    # Receives and processes system metrics and packet events on the server
├── README.md                # This file
```

---

## Environment Setup

### System Information

Ensure you are running the correct kernel and OS version for eBPF support.

```bash
uname -r
6.8.0-45-generic

lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.5 LTS
Release:        22.04
Codename:       jammy
```

### Steps to Set Up the Environment

1. **Update the system:**
   ```bash
   sudo apt update
   ```

2. **Install Clang and LLVM:**
   These tools are required for compiling eBPF programs.
   ```bash
   sudo apt install clang llvm
   ```
   Confirm the versions:
   ```bash
   llvm-config --version
   clang --version
   ```
   Example output:
   ```
   LLVM 14.0.0
   Clang 14.0.0
   ```

3. **Install BCC Tools and Linux Headers:**
   BCC provides an easy way to write and execute eBPF programs.
   ```bash
   sudo apt install bpfcc-tools linux-headers-$(uname -r)
   ```

4. **Test the Installation:**
   Run a built-in BCC tool to ensure everything is working:
   ```bash
   sudo /usr/sbin/execsnoop-bpfcc
   ```

5. **Install Libraries for BCC Development:**
   If you are developing custom eBPF programs, install the necessary libraries:
   ```bash
   sudo apt install libbpfcc libbpf-dev
   ```

6. **Install Python Libraries:**
   The Python libraries `pyroute2` and `psutil` are required for network monitoring and system metrics collection.
   ```bash
   sudo apt install python3-pyroute2
   sudo apt install python3-psutil
   ```

---

## Scripts

### 1. `remote_monitor.py` (Edge)

This script runs on a remote edge device to monitor system metrics (CPU usage, memory usage, bandwidth utilization) and capture network packet data using eBPF. The collected data is sent to a local server via TCP.

- **Features**:
  - eBPF program for packet capture
  - Filters TCP and UDP packets
  - Collects system metrics: CPU, memory, and bandwidth usage
  - Sends data periodically to a specified local machine
  
- **Adjustments**:
  - Set `LOCAL_MACHINE_IP` and `LOCAL_MACHINE_PORT` to the local server's IP and port.
  - Adjust `iface_name` to the appropriate network interface on the remote device.

### 2. `local_receiver.py` (Server)

This script runs on the local machine, listening for incoming data from the remote device. It deserializes and processes system metrics and network packet data, then displays the information along with calculated network performance metrics (e.g., throughput and packet delay).

- **Features**:
  - Receives system metrics and packet data
  - Calculates network metrics: throughput, average packet delay, and packet loss (placeholder)
  - Displays data in a human-readable format

- **Usage**:
  - Ensure the `LISTEN_PORT` matches the port used in `remote_monitor.py`.
  - Run the script to start the server and wait for connections from the edge devices.

---

## How to Run

### Edge (Remote Device)
1. Update `LOCAL_MACHINE_IP`, `LOCAL_MACHINE_PORT`, and `iface_name` in `remote_monitor.py`.
2. Run the script:
   ```bash
   python remote_monitor.py
   ```

### Server (Local Machine)
1. Ensure the port number in `local_receiver.py` matches the one used by the remote device.
2. Start the server:
   ```bash
   python local_receiver.py
   ```

---

## Contact

For any issues or further improvements, feel free to open an issue or submit a pull request.
