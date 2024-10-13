from bcc import BPF
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
import struct
import socket
import time
import os
import subprocess
import psutil  # psutil 임포트

# 로그 파일의 절대 경로 지정 (필요에 따라 경로 변경)
log_file_path = os.path.join("/home/dykim6208", "icmp_log.txt")
try:
    log_file = open(log_file_path, "a", buffering=1)  # buffering=1: 라인 버퍼링
except IOError as e:
    print(f"Failed to open log file {log_file_path}: {e}")
    exit(1)

# 변환할 소스 IP 주소
SOURCE_IP = "35.202.28.101"

# IP 주소를 정수로 변환 (네트워크 바이트 오더)
source_ip_packed = struct.unpack("I", socket.inet_aton(SOURCE_IP))[0]
source_ip_hex = f"{source_ip_packed:08x}"

# 시스템 부팅 시간 가져오기 (psutil 사용)
def get_boot_time():
    try:
        boot_time_epoch = psutil.boot_time()
        return boot_time_epoch
    except Exception as e:
        print(f"Failed to get boot time using psutil: {e}")
        return time.time() - time.monotonic()

boot_time = get_boot_time()

# BPF 프로그램 - 특정 소스 IP의 ICMP 패킷 추적 eBPF 코드
program = f"""
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/time.h>

// ICMP 이벤트 구조체
struct icmp_event {{
    u32 saddr;
    u32 daddr;
    u64 timestamp;
    u8 is_request;  // 요청인지 응답인지 구분
}};

// PERF 이벤트 출력
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

    // ICMP 패킷인지 확인
    if (ip->protocol != IPPROTO_ICMP) {{
        return 0;
    }}

    bool is_request = false;

    // 소스 IP가 SOURCE_IP인 경우 (핑 요청)
    if (ip->saddr == 0x{source_ip_hex}) {{
        is_request = true;
    }}
    // 목적지 IP가 SOURCE_IP인 경우 (핑 응답)
    else if (ip->daddr == 0x{source_ip_hex}) {{
        is_request = false;
    }}
    else {{
        // 둘 다 아니면 무시
        return 0;
    }}

    struct icmp_event event = {{
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .timestamp = bpf_ktime_get_ns(),
        .is_request = is_request ? 1 : 0,  // bool을 u8로 변환
    }};
    events.perf_submit(skb, &event, sizeof(event));

    // 디버깅 메시지 (선택 사항)
    // bpf_trace_printk("ICMP Packet detected\\n");
    return 0;
}}
"""

# eBPF 프로그램 로드
try:
    b = BPF(text=program)
except Exception as e:
    print(f"Failed to load BPF program: {e}")
    log_file.close()
    exit(1)

# eBPF 프로그램을 네트워크 인터페이스에 연결
try:
    function_icmp = b.load_func("icmp_monitor", BPF.SCHED_CLS)
except Exception as e:
    print(f"Failed to load BPF function: {e}")
    log_file.close()
    exit(1)

ip = IPRoute()
iface_name = "ens4"  # 로컬 컴퓨터의 네트워크 인터페이스 이름 (필요 시 변경)
interfaces = ip.get_links()

iface_idx = None
for iface in interfaces:
    if iface.get_attr("IFLA_IFNAME") == iface_name:
        iface_idx = iface['index']
        break

if iface_idx:
    # clsact 설정 시도: 삭제 후 추가
    try:
        ip.tc("del", "clsact", iface_idx)
        print(f"Removed existing clsact from interface {iface_name}")
    except NetlinkError as e:
        print(f"No clsact to remove on {iface_name}: {e}")

    # clsact 추가 (이미 존재하면 무시)
    try:
        ip.tc("add", "clsact", iface_idx)
        print(f"Added clsact to interface {iface_name}")
    except NetlinkError as e:
        if e.code == 17:  # EEXIST: File exists
            print(f"clsact already exists on {iface_name}, continuing.")
        else:
            print(f"Error adding clsact to {iface_name}: {e}")

    # eBPF 프로그램 필터를 ingress과 egress에 모두 연결
    parents = ["ffff:fff2", "ffff:fff1"]  # ingress, egress
    for parent in parents:
        try:
            ip.tc("add-filter", "bpf", iface_idx, ":1", fd=function_icmp.fd, name=function_icmp.name, parent=parent, action="ok")
            direction = "ingress" if parent == "ffff:fff2" else "egress"
            print(f"Attached BPF filter to {direction} of interface {iface_name}")
        except NetlinkError as e:
            print(f"Error attaching BPF filter to {direction} of interface {iface_name}: {e}")
else:
    print(f"Interface {iface_name} not found.")
    log_file.close()
    exit(1)

# eBPF 이벤트 핸들러
def handle_event(cpu, data, size):
    try:
        event = b["events"].event(data)
        src_ip = socket.inet_ntoa(struct.pack("<I", event.saddr))
        dst_ip = socket.inet_ntoa(struct.pack("<I", event.daddr))
        is_request = event.is_request
        # 타임스탬프 변환 (ns 단위에서 초 단위)
        absolute_time = boot_time + (event.timestamp / 1e9)
        # 구조화된 시간 문자열 생성
        try:
            time_struct = time.localtime(absolute_time)
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time_struct) + f".{int((absolute_time % 1) * 1e6):06d}"
        except Exception as e:
            time_str = "Invalid Time"
            print(f"Time conversion error: {e}")
        direction = "Request" if is_request else "Reply"
        log = f"[{time_str}] ICMP {direction} from {src_ip} to {dst_ip}"
        print(log)
        try:
            log_file.write(f"{log}\n")
        except Exception as e:
            print(f"Failed to write to log file: {e}")
        log_file.flush()  # 즉시 파일에 기록
    except Exception as e:
        print(f"Error handling event: {e}")

# BPF_PERF_OUTPUT 이벤트 열기
b["events"].open_perf_buffer(handle_event)

# 실시간 출력 및 로깅
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
