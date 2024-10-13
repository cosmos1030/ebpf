from bcc import BPF
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
import struct
import socket
import time
import os
import psutil

# Log file path (adjust as necessary)
log_file_path = os.path.join("/home/dykim6208", "packet_log.txt")
try:
    log_file = open(log_file_path, "a", buffering=1)  # Line buffering
except IOError as e:
    print(f"Failed to open log file {log_file_path}: {e}")
    exit(1)

# System boot time retrieval
def get_boot_time():
    try:
        boot_time_epoch = psutil.boot_time()
        return boot_time_epoch
    except Exception as e:
        print(f"Failed to get boot time using psutil: {e}")
        return time.time() - time.monotonic()

boot_time = get_boot_time()

# Define the monitored IP address
MONITORED_IP = "10.128.0.3"
# MONITORED_IP = "10.128.0.1"

# Convert monitored IP address to integer in network byte order
monitored_ip_packed = struct.unpack("I", socket.inet_aton(MONITORED_IP))[0]
monitored_ip_hex = f"{monitored_ip_packed:08x}"

# eBPF program to capture UDP and TCP packets from/to MONITORED_IP
program = f"""
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/time.h>

// Packet event structure
struct packet_event {{
    u32 saddr;
    u32 daddr;
    u64 timestamp;
    u8 protocol; // 6 for TCP, 17 for UDP
}};

// PERF event output
BPF_PERF_OUTPUT(events);

int packet_monitor(struct __sk_buff *skb) {{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {{
        return 0;
    }}

    if (eth->h_proto != htons(ETH_P_IP)) {{
        return 0;
    }}

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {{
        return 0;
    }}

    // Check for TCP or UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {{
        return 0;
    }}

    // Check if source or destination IP matches MONITORED_IP
    if (ip->saddr != 0x{monitored_ip_hex} && ip->daddr != 0x{monitored_ip_hex}) {{
        return 0;
    }}

    struct packet_event event = {{
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .timestamp = bpf_ktime_get_ns(),
        .protocol = ip->protocol,
    }};

    events.perf_submit(skb, &event, sizeof(event));

    return 0;
}}
"""

# Load the eBPF program
try:
    b = BPF(text=program)
except Exception as e:
    print(f"Failed to load BPF program: {e}")
    log_file.close()
    exit(1)

# Load the function
try:
    function_packet = b.load_func("packet_monitor", BPF.SCHED_CLS)
except Exception as e:
    print(f"Failed to load BPF function: {e}")
    log_file.close()
    exit(1)

# Attach the program to the network interface
ip = IPRoute()
iface_name = "ens4"  # Adjust the interface name as necessary
interfaces = ip.get_links()

iface_idx = None
for iface in interfaces:
    if iface.get_attr("IFLA_IFNAME") == iface_name:
        iface_idx = iface['index']
        break

if iface_idx:
    # Remove existing clsact qdisc if exists
    try:
        ip.tc("del", "clsact", iface_idx)
        print(f"Removed existing clsact from interface {iface_name}")
    except NetlinkError as e:
        print(f"No clsact to remove on {iface_name}: {e}")

    # Add clsact qdisc
    try:
        ip.tc("add", "clsact", iface_idx)
        print(f"Added clsact to interface {iface_name}")
    except NetlinkError as e:
        if e.code == 17:  # EEXIST
            print(f"clsact already exists on {iface_name}, continuing.")
        else:
            print(f"Error adding clsact to {iface_name}: {e}")

    # Attach the eBPF program to ingress and egress
    parents = ["ffff:fff2", "ffff:fff1"]  # ingress, egress
    for parent in parents:
        try:
            ip.tc("add-filter", "bpf", iface_idx, ":1", fd=function_packet.fd, name=function_packet.name, parent=parent, action="ok", classid=1)
            direction = "ingress" if parent == "ffff:fff2" else "egress"
            print(f"Attached BPF filter to {direction} of interface {iface_name}")
        except NetlinkError as e:
            direction = "ingress" if parent == "ffff:fff2" else "egress"
            print(f"Error attaching BPF filter to {direction} of interface {iface_name}: {e}")
else:
    print(f"Interface {iface_name} not found.")
    log_file.close()
    exit(1)

# eBPF event handler
def handle_event(cpu, data, size):
    try:
        event = b["events"].event(data)
        src_ip = socket.inet_ntoa(struct.pack("<I", event.saddr))
        dst_ip = socket.inet_ntoa(struct.pack("<I", event.daddr))
        protocol = event.protocol
        protocol_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "Unknown"
        # Convert timestamp
        absolute_time = boot_time + (event.timestamp / 1e9)
        # Formatted time string
        try:
            time_struct = time.localtime(absolute_time)
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time_struct) + f".{int((absolute_time % 1) * 1e6):06d}"
        except Exception as e:
            time_str = "Invalid Time"
            print(f"Time conversion error: {e}")

        log = f"[{time_str}] {protocol_name} Packet from {src_ip} to {dst_ip}"
        print(log)
        try:
            log_file.write(f"{log}\n")
        except Exception as e:
            print(f"Failed to write to log file: {e}")
        log_file.flush()  # Ensure immediate write to file
    except Exception as e:
        print(f"Error handling event: {e}")

# Open the perf buffer
b["events"].open_perf_buffer(handle_event)

# Start monitoring
try:
    print("Starting packet monitoring. Press Ctrl+C to stop.")
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
except Exception as e:
    print(f"Error during perf buffer polling: {e}")
finally:
    log_file.close()
    print("Logging stopped.")
