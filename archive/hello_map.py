from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);                                            // (1)

int hello(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;                   // (2)
    p = counter_table.lookup(&uid);                                 // (3)
    if( p!= 0) {                                                    // (4)
        counter = *p;
    }
    counter++;                                                      // (5)
    counter_table.update(&uid, &counter);                           // (6)
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():                          # (7)
        s += f"ID {k.value}: {v.value}\t"
    print(s)