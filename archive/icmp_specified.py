from bcc import BPF
from pyroute2 import IPRoute
import struct
import socket

log_file = open("icmp_log.txt", "a")

# 변환할 소스 IP 주소
SOURCE_IP = "35.202.28.101"

# IP 주소를 정수로 변환 (네트워크 바이트 오더)
source_ip_packed = struct.unpack("I", socket.inet_aton(SOURCE_IP))[0]
source_ip_hex = f"{source_ip_packed:08x}"

# BPF 프로그램 - 특정 소스 IP의 ICMP 패킷 추적 eBPF 코드
program = f"""
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>

struct icmp_event {{
    u32 saddr;
    u32 daddr;
}};

BPF_PERF_OUTPUT(events);

int icmp_monitor(struct __sk_buff *skb) {{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {{
        return 0;
    }}

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {{
        return 0;
    }}

    // ICMP 패킷인지 확인하고, 소스 IP가 35.202.28.101인지 확인
    if (ip->protocol == IPPROTO_ICMP && ip->saddr == 0x{source_ip_hex}) {{
        struct icmp_event event = {{
            .saddr = ip->saddr,
            .daddr = ip->daddr,
        }};
        events.perf_submit(skb, &event, sizeof(event));
    }}

    return 0;
}}
"""

# eBPF 프로그램 로드
b = BPF(text=program)

# eBPF 프로그램을 네트워크 인터페이스에 연결
function_icmp = b.load_func("icmp_monitor", BPF.SCHED_CLS)
ip = IPRoute()
iface_name = "ens4"  # 로컬 컴퓨터의 네트워크 인터페이스 이름
interfaces = ip.get_links()

iface_idx = None
for iface in interfaces:
    if iface.get_attr("IFLA_IFNAME") == iface_name:
        iface_idx = iface['index']
        break

if iface_idx:
    try:
        # clsact가 이미 존재하는지 확인
        ip.tc("show", iface_idx)  # 기존 tc 설정 표시

        # 기존 clsact 제거 (존재하는 경우)
        ip.tc("del", "clsact", iface_idx)
        print(f"Removed existing clsact from interface {iface_name}")
    except Exception as e:
        # clsact가 존재하지 않으면 메시지 출력하고 계속
        print(f"No clsact to remove on {iface_name}: {e}")

    # clsact 다시 추가
    try:
        ip.tc("add", "clsact", iface_idx)
        print(f"Added clsact to interface {iface_name}")
    except Exception as e:
        print(f"Error adding clsact to {iface_name}: {e}")

    # eBPF 프로그램 필터를 ingress 방향으로만 연결
    try:
        ip.tc("add-filter", "bpf", iface_idx, ":1", fd=function_icmp.fd, name=function_icmp.name, parent="ffff:fff2", action="ok")
        print(f"Attached BPF filter to ingress of interface {iface_name}")
    except Exception as e:
        print(f"Error attaching BPF filter to ingress of {iface_name}: {e}")

# eBPF 이벤트 핸들러
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    src_ip = socket.inet_ntoa(struct.pack("<I", event.saddr))
    dst_ip = socket.inet_ntoa(struct.pack("<I", event.daddr))
    log = f"ICMP Packet from {src_ip} to {dst_ip}"
    print(log)
    log_file.write(f"{log}\n")

# BPF_PERF_OUTPUT 이벤트 열기
b["events"].open_perf_buffer(handle_event)

# 실시간 출력 및 로깅
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    log_file.close()
