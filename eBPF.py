import os
import signal
import sys

from bcc import BPF

prog = """ 

#include <linux/pid_namespace.h>

struct data_t {
    int syscallnumber;
    u32 pid;
    u32 cgroup;
};

BPF_PERF_OUTPUT(events);

int sgettimeofday(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct nsproxy = t->nsproxy; 
    //->pid_namespaces->ns_common->inum;
    //bpf_trace_printk("pid=%d; upid=%d!\\n", pid, upid);
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
int swrite(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 2;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
b = BPF(text=prog)


def attachkretprobe():
    b.attach_kretprobe(event=b.get_syscall_fnname("gettimeofday"), fn_name="sgettimeofday")
    b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="sread")
    b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="swrite")


patterns = []


def detectpatterns(cpu, data, size):
    data = b["events"].event(data)
    syscall = data.syscallnumber
    pid = data.pid
    cgroup = data.cgroup
    if localpids.__contains__(str(pid)):
        if syscall == 0:
            print("found gettimeofdate! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup))
            syscall = "gettimeofday"
            patterns.append(syscall)
        elif syscall == 1:
            print("found read! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup))
            syscall = "read"
            patterns.append(syscall)
        elif syscall == 2:
            print("found write! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup))
            syscall = "write"
            patterns.append(syscall)

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
            getprobability()
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

def getprobability():
    anzahl_eintraege = len(patterns)
    haeufigkeiten = {}
    for eintrag in patterns:
        if eintrag in haeufigkeiten:
            haeufigkeiten[eintrag] += 1
        else:
            haeufigkeiten[eintrag] = 1

    # Berechne die prozentuale Verteilung
    prozent_verteilung = {}
    for eintrag, haeufigkeit in haeufigkeiten.items():
        prozent_verteilung[eintrag] = (haeufigkeit / anzahl_eintraege) * 100

    # Ergebnis ausgeben
    print("Prozentuale Verteilung der Einträge:")
    for eintrag, prozent in prozent_verteilung.items():
        print(f"{eintrag}: {prozent}%")


# Eingabe des zu tracenden Binaries.
ibinary = input("Input Binary: ")
localpids = getpids(ibinary)
print("attaching to kretprobes")
attachkretprobe()
print("attachment ready" + "\n" + "now tracing! \npress CTRL + C to stop tracing.")
getringbuffer()