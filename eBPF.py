import os
import signal
import sys

from bcc import BPF

prog = """ 
struct data_t {
    int syscallnumber;
    u32 pid;
    u32 cgroup;
};

BPF_PERF_OUTPUT(events);

int sgettimeofday(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 0;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sread(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
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


def detectpatterns(cpu, data, size):
    data = b["events"].event(data)
    syscall = data.syscallnumber
    pid = data.pid
    cgroup = data.cgroup
    # if localpids.__contains__(str(pid)):
    if syscall == 0:
        print("found gettimeofdate! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup))
        syscall = "gettimeofday"
        patterns.append(syscall)

        # if syscall == 1:
        #     print("found read! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup))
        #     syscall = "read"
        #     patterns.append(syscall)

        # elif syscall == 1:
        #     print("found read!")


def getringbuffer():
    uptime = 0
    b["events"].open_perf_buffer(detectpatterns, page_cnt=256)
    while True:
        try:
            b.perf_buffer_poll(timeout=10 * 1000)
        except KeyboardInterrupt:
            print("Abbruch")
            print(patterns)
            signal_handler(signal.SIGINT, signal_handler)


def signal_handler(sig, frame):
    print('Exited with Keyboard Interrupt')
    sys.exit(0)

# Die Funktion führt einen Shell Befehl aus, welcher sich alle PIDs des übergebenen Binaries holt und in ein Array
# schreibt.
def getpids(input):
    result = os.popen("pgrep -f " + input).read()
    result = result[:-5]
    print("tracing PIDs: " "\n" + result)
    return result


# Eingabe des zu tracenden Binaries.
ibinary = input("Input Binary: ")
localpids = getpids(ibinary)
print("attaching to kretprobes")
attachkretprobe()
print("attachment ready" + "\n" + "now tracing! \npress CTRL + C to stop tracing.")
getringbuffer()