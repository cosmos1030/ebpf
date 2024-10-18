import socket
import struct
import threading
import time
import psutil
from bcc import BPF
from collections import deque
import ctypes

# Define the IP and port of the local machine to send data to
LOCAL_MACHINE_IP = "172.18.0.3"  # Replace with your local machine's IP
LOCAL_MACHINE_PORT = 9999  # Ensure this matches the port on the local machine

# Network interface to attach the eBPF program
iface_name = "eth0"  # Adjust as necessary

# eBPF program
program = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <linux/stddef.h>  // For offsetof

struct packet_event {
    u64 timestamp;
    u32 saddr;
    u32 daddr;
    u32 pkt_len;
    u8 protocol;
} __attribute__((packed));

BPF_PERF_OUTPUT(events);

int packet_monitor(struct __sk_buff *skb) {
    struct packet_event event = {};
    u8 ip_proto = 0;
    u64 nh_off = 0;

    // Ethernet header size
    nh_off = ETH_HLEN;

    // Load IP header's protocol field
    if (bpf_skb_load_bytes(skb, nh_off + offsetof(struct iphdr, protocol), &ip_proto, sizeof(ip_proto)) < 0) {
        return 0;
    }

    // Filter TCP and UDP packets
    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
        return 0;
    }

    // Load source and destination IP addresses
    if (bpf_skb_load_bytes(skb, nh_off + offsetof(struct iphdr, saddr), &event.saddr, sizeof(event.saddr)) < 0) {
        return 0;
    }
    if (bpf_skb_load_bytes(skb, nh_off + offsetof(struct iphdr, daddr), &event.daddr, sizeof(event.daddr)) < 0) {
        return 0;
    }

    // Get packet length
    event.pkt_len = skb->len;

    // Get timestamp
    event.timestamp = bpf_ktime_get_ns();

    // Set protocol
    event.protocol = ip_proto;

    // Submit event to user-space
    events.perf_submit_skb(skb, skb->len, &event, sizeof(event));

    return 0;
}
"""

# Define the PacketEvent structure in Python
class PacketEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("pkt_len", ctypes.c_uint32),
        ("protocol", ctypes.c_uint8),
    ]
    _pack_ = 1  # Ensure the structure is packed

# Initialize variables
packet_events = deque()
boot_time = psutil.boot_time()

# Create a socket to send data to the local machine
sock_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock_send.connect((LOCAL_MACHINE_IP, LOCAL_MACHINE_PORT))
except ConnectionRefusedError as e:
    print(f"Connection to {LOCAL_MACHINE_IP}:{LOCAL_MACHINE_PORT} refused: {e}")
    exit(1)

# Load eBPF program
b = BPF(text=program)
function_packet = b.load_func("packet_monitor", BPF.SOCKET_FILTER)

# Attach the eBPF program to the network interface
BPF.attach_raw_socket(function_packet, iface_name)

# Create a socket object to read packets
socket_fd = function_packet.sock
sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.setblocking(False)

# eBPF event handler
def handle_event(cpu, data, size):
    # Cast the raw data to our PacketEvent structure
    event = ctypes.cast(data, ctypes.POINTER(PacketEvent)).contents
    packet_data = {
        'timestamp': boot_time + event.timestamp / 1e9,
        'saddr': socket.inet_ntoa(struct.pack('!I', event.saddr)),
        'daddr': socket.inet_ntoa(struct.pack('!I', event.daddr)),
        'protocol': 'TCP' if event.protocol == 6 else 'UDP',
        'pkt_len': event.pkt_len
    }
    packet_events.append(packet_data)

# Function to collect and send metrics
def send_metrics():
    try:
        while True:
            # Collect system metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            mem_usage = mem.percent

            # Bandwidth utilization
            net_io = psutil.net_io_counters()
            bandwidth = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
            }

            # Prepare data to send
            metrics = {
                'timestamp': time.time(),
                'cpu_usage': cpu_usage,
                'mem_usage': mem_usage,
                'bandwidth': bandwidth,
                'packet_events': list(packet_events)
            }

            # Send metrics to local machine
            import json
            data = json.dumps(metrics).encode('utf-8')
            length = struct.pack('!I', len(data))
            sock_send.sendall(length + data)

            # Clear packet events
            packet_events.clear()

            # Wait before next send
            time.sleep(5)  # Adjust interval as needed
    except Exception as e:
        print(f"Error sending metrics: {e}")
    finally:
        sock_send.close()

# Start the metrics sending thread
threading.Thread(target=send_metrics, daemon=True).start()

# Start monitoring
b["events"].open_perf_buffer(handle_event)
print("Remote monitoring started. Press Ctrl+C to stop.")
try:
    while True:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break
except Exception as e:
    print(f"Error during perf buffer polling: {e}")
finally:
    sock_send.close()
    print("Remote monitoring stopped.")
