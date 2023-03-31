import signal
import sys

from bcc import BPF

prog = """ 
struct data_t {
    int syscallnumber;
};

BPF_PERF_OUTPUT(events);

int sgettimeofday(struct pt_regs *ctx) {
    struct data_t data = {};
    data.syscallnumber = 0;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
b = BPF(text=prog)


def attachkretprobe():
    b.attach_kretprobe(event=b.get_syscall_fnname("gettimeofday"), fn_name="sgettimeofday")


def updateoccurences(cpu, data, size):
    data = b["events"].event(data)
    syscall = data.syscallnumber
    if syscall == 0:
        print("found gettimeofdate!")
    else:
        print("Error")


def getringbuffer():
    uptime = 0
    b["events"].open_perf_buffer(updateoccurences, page_cnt=256)
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
