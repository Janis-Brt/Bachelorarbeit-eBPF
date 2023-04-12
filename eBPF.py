import signal
import sys

from bcc import BPF

prog = """ 
struct data_t {
    int syscallnumber;
    u32 pid;
    u32 cgroup;
    u32 classid;
};

BPF_PERF_OUTPUT(events);

int sgettimeofday(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.classid = class_id;
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 0;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sread(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 1;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
b = BPF(text=prog)


def attachkretprobe():
    b.attach_kretprobe(event=b.get_syscall_fnname("gettimeofday"), fn_name="sgettimeofday")
    b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="sread")


patterns = []


def detetpatterns(cpu, data, size):
    data = b["events"].event(data)
    syscall = data.syscallnumber
    pid = data.pid
    cgroup = data.cgroup
    classid = data.classid
    if syscall == 0:
        print("found gettimeofdate! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup) + " and class_id: " + str(
            classid))
        patterns.append(syscall)
        print(patterns)
    # elif syscall == 1:
    #     print("found read!")


def getringbuffer():
    uptime = 0
    b["events"].open_perf_buffer(detetpatterns, page_cnt=256)
    while True:
        try:
            b.perf_buffer_poll(timeout=10 * 1000)
        except KeyboardInterrupt:
            print("Abbruch")
            signal_handler(signal.SIGINT, signal_handler)


def signal_handler(sig, frame):
    print('Exited with Keyboard Interrupt')
    sys.exit(0)


attachkretprobe()
print("attachment ready" + "\n" + "now tracing! \npress CTRL + C to stop tracing.")
getringbuffer()
