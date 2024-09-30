from bcc import BPF
from pyroute2 import IPRoute
import time

log_file = open("icmp_log.txt", "a")

# BPF program - ICMP packet tracing eBPF code
program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>

int icmp_monitor(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }

    // Check if the packet is ICMP
    if (ip->protocol == IPPROTO_ICMP) {
        // Output packet information to kernel message
        bpf_trace_printk("ICMP Packet: src IP %x, dst IP %x\n", ip->saddr, ip->daddr);
    }

    return 0;
}
"""

# Load the eBPF program using BCC
b = BPF(text=program)

# Attach the eBPF program to the network interface
function_icmp = b.load_func("icmp_monitor", BPF.SCHED_CLS)
ip = IPRoute()
iface_name = "enp0s31f6"  # Name of the network interface on the local computer
interfaces = ip.get_links()

iface_idx = None
for iface in interfaces:
    if iface.get_attr("IFLA_IFNAME") == iface_name:
        iface_idx = iface['index']
        break

if iface_idx:
    # Remove existing clsact
    ip.tc("del", "clsact", iface_idx)

    # Re-add clsact
    ip.tc("add", "clsact", iface_idx)

    # Attach the BPF program filter to the interface
    ip.tc("add-filter", "bpf", iface_idx, ":1", fd=function_icmp.fd, name=function_icmp.name, parent="ffff:fff2", action="ok")

# Function to print kernel debug messages
def print_event():
    with open("/sys/kernel/debug/tracing/trace_pipe", "r") as f:
        while True:
            try:
                line = f.readline()
                if line:
                    print(line.strip())
                    log_file.write(f"{line.strip()}\n")
            except KeyboardInterrupt:
                log_file.close()  # Close the file
                break

# Real-time output and logging of kernel debug messages
print_event()
