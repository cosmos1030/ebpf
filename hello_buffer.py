#!/home/shpark/anaconda3/bin/python
# -*- coding: utf-8 -*-

from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);                                                 // (1)

struct data_t {                                                          // (2)
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int hello(void *ctx) {
    struct data_t data = {};                                             // (3)
    char message[12] = "Hello World";

    data.pid = bpf_get_current_pid_tgid() >> 32;                         // (4)
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;                   // (5)

    bpf_get_current_comm(&data.command, sizeof(data.command));           // (6)
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message); // (7)

    output.perf_submit(ctx, &data, sizeof(data));                        // (8)

    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):                                        # (9)
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
    
b["output"].open_perf_buffer(print_event)                                # (10)

while True:
    b.perf_buffer_poll()                                                 # (11)