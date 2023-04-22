from bcc import BPF
import os
import time
import signal
import sys

# Die Lokale Variable speichert den eBPF C-Code.
prog = """
#include <uapi/linux/ptrace.h>

// Daten Struct für den Ring Buffer
struct data_t {
    int syscallnumber;
    u32 pid;
};

// Initialisierung des BPF Ring Buffers. Mit diesem kann man Daten an den Userspace übergeben
BPF_PERF_OUTPUT(events);

/**Diese Funktion wird immer aufgerufen, wenn der System Call clone detektiert wird. 
Zuerst wird geprüft, ob der Return Wert kleiner als 0 ist, in diesem Fall wurde der System Call nicht korrekt aufgerufen 
und es wird nichts übergeben, andernfalls wird die PID des Prozesses übergeben und die eindeutige System Call Nummer, 
in diesem Fall die 0.**/
int sclone(struct pt_regs *ctx) {
    // hier auf return Value zugreifen
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 0;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sopen(struct pt_regs *ctx) {
    // hier auf return Value zugreifen
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 1;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sread(struct pt_regs *ctx) {
    // hier auf return Value zugreifen
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 2;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int swrite(struct pt_regs *ctx) {
    // hier auf return Value zugreifen
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 3;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclose(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 4;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sstat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 5;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfstat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 6;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slstat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 7;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spoll(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 8;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slseek(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 9;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smmap(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 10;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smprotect(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 11;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smunmap(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 12;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sbrk(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 13;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigaction(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 14;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigprocmask(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 15;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigreturn(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 16;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 17;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spread64(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 18;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spwrite64(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 19;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadv(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 20;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int swritev(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 21;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int saccess(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 22;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spipe(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 23;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sselect(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 24;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smremap(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 25;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_yield(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 26;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsync(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 27;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smincore(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 28;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smadvise(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 29;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshmget(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 30;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshmat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 31;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshmctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 32;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sdup(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 33;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sdup2(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 34;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spause(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 35;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int snanosleep(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 36;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetitimer(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 37;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int salarm(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 38;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetitimer(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 39;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 40;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssendfile(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 41;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssocket(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 42;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sconnect(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 43;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int saccept(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 44;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssendto(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 45;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srecvfrom(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 46;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int ssendmsg(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 47;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srecvmsg(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 48;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshutdown(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 49;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sbind(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 50;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slisten(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 51;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetsockname(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 52;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpeername(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 53;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssocketpair(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 54;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetsockopt(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 55;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetsockopt(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 56;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfork(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 57;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int svfork(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 58;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sexecve(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 59;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sexit(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 60;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int swait4(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 61;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skill(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 62;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int suname(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 63;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemget(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 64;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemop(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 65;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 66;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshmdt(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 67;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int smsgget(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 68;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsgsnd(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 69;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsgrcv(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 70;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsgctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 71;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfcntl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 72;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sflock(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 73;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfsync(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 74;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfdatasync(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 75;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int struncate(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 76;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sftruncate(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 77;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetdents(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 78;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetcwd(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 79;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int schdir(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 80;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchdir(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 81;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srename(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 82;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smkdir(struct pt_regs *ctx) {
    /**if(PT_REGS_RC(ctx) < 0){
        return 0;
    }**/
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 83;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srmdir(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 84;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int screat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 85;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slink(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 86;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sunlink(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 87;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssymlink(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 88;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadlink(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 89;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int schmod(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 90;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int sfchmod(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 91;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int schown(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 92;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchown(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 93;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slchown(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 94;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sumask(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 95;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgettimeofday(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 96;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetrlimit(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 97;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int sgetrusage(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 98;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int ssysinfo(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 99;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimes(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 100;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sptrace(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 102;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetuid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 103;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssyslog(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 104;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetgid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 105;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetuid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 106;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetgid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 107;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgeteuid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 108;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetegid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 109;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetpgid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 110;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetppid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 111;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpgrp(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 112;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetsid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 113;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetreuid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 114;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetregid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 115;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetgroups(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 116;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetgroups(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 117;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetresuid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 118;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetresuid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 119;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetresgid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 120;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetresgid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 121;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpgid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 122;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetfsuid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 123;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetfsgid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 124;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetsid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 125;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int scapget(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 126;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int scapset(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 127;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigpending(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 128;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigtimedwait(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 129;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigqueueinfo(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 130;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigsuspend(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 131;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssigaltstack(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 132;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sutime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 133;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smknod(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 134;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int suselib(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 135;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spersonality(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 136;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sustat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 137;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sstatfs(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 138;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfstatfs(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 139;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssysfs(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 140;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpriority(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 141;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetpriority(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 142;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_setparam(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 143;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_getparam(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 144;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_setscheduler(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 145;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_getscheduler(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 146;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_get_priority_max(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 147;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_get_priority_min(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 148;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_rr_get_interval(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 149;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smlock(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 150;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smunlock(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 151;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smlockall(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 152;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smunlockall(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 153;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int svhangup(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 154;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smodify_ldt(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 155;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spivot_root(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 156;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssysctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 157;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sprctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 158;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sarch_prctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 159;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sadjtimex(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 160;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetrlimit(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 161;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int schroot(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 162;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssync(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 163;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sacct(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 164;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssettimeofday(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 165;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smount(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 166;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sumount2(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 167;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sswapon(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 168;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sswapoff(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 169;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreboot(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 170;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssethostname(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 171;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetdomainname(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 172;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int siopl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 173;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioperm(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 174;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int screate_module(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 175;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinit_module(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 176;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sdelete_module(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 177;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_kernel_syms(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 178;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int squery_module(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 179;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int squotactl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 180;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int snfsservctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 181;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpmsg(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 182;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sputpmsg(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 183;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int safs_syscall(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 184;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stuxcall(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 185;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssecurity(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 186;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgettid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 187;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadahead(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 188;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 189;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slsetxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 190;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfsetxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 191;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 192;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfgetxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 193;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slistxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 194;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sllistxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 195;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sflistxattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 196;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sremovexattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 197;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slremovexattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 198;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfremovexattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 199;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stkill(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 200;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 201;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfutex(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 202;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_setaffinity(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 203;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_getaffinity(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 204;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_thread_area(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 205;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_setup(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 206;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_destroy(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 207;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_getevents(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 208;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_submit(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 209;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_cancel(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 210;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_thread_area(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 211;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slookup_dcookie(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 212;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_create(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 213;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_ctl_old(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 214;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_wait_old(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 215;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sremap_file_pages(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 216;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetdents64(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 217;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_tid_address(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 218;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srestart_syscall(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 219;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemtimedop(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 220;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfadvise64(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 221;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_create(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 222;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_settime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 223;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_gettime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 224;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_getoverrun(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 225;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_delete(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 226;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_settime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 227;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_gettime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 228;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_getres(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 229;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_nanosleep(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 230;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sexit_group(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 231;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_wait(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 232;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_ctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 233;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stgkill(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 234;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sutimes(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 235;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int svserver(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 236;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smbind(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 237;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_mempolicy(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 238;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_mempolicy(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 239;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_open(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 240;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_unlink(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 241;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_timedsend(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 242;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_timedreceive(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 243;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_notify(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 244;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_getsetattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 245;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skexec_load(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 246;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int swaitid(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 247;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sadd_key(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 248;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srequest_key(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 249;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skeyctl(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 250;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioprio_set(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 251;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioprio_get(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 252;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinotify_init(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 253;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinotify_add_watch(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 254;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinotify_rm_watch(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 255;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smigrate_pages(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 256;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sopenat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 257;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smkdirat(struct pt_regs *ctx) {
    /**if(PT_REGS_RC(ctx) < 0){
        return 0;
    }**/
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 258;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smknodat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 259;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchownat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 260;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfutimesat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 261;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int snewfstatat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 262;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sunlinkat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 263;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srenameat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 264;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slinkat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 265;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssymlinkat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 266;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadlinkat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 267;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchmodat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 268;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfaccessat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 269;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spselect6(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 270;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sppoll(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 271;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sunshare(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 272;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_robust_list(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 273;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_robust_list(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 274;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssplice(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 275;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stee(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 276;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssync_file_range(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 277;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int svmsplice(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 278;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smove_pages(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 279;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sutimensat(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 280;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_pwait(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 281;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssignalfd(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 282;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimerfd_create(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 283;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int seventfd(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 284;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfallocate(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 285;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimerfd_settime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 286;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimerfd_gettime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 287;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int saccept4(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 288;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssignalfd4(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 289;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int seventfd2(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 290;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int epoll_create1(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 291;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sdup3(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 292;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spipe2(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 293;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinotify_init1(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 294;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spreadv(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 295;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spwritev(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 296;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_tgsigqueueinfo(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 297;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sperf_event_open(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 298;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int srecvmmsg(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 299;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfanotify_init(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 300;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfanotify_mark(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 301;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sprlimit64(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 302;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sname_to_handle_at(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 303;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sopen_by_handle_at(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 304;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_adjtime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 305;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssyncfs(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 306;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssendmmsg(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 307;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetns(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 308;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetcpu(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 309;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sprocess_vm_readv(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 310;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sprocess_vm_writev(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 311;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skcmp(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 312;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfinit_module(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 313;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_setattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 314;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int ssched_getattr(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 315;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srenameat2(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 316;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int sseccomp(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 317;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetrandom(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 318;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smemfd_create(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 319;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skexec_file_load(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 320;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sbpf(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.syscallnumber = 321;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialisierung des BPF Objekts, welches den C-Code übergeben bekommt
b = BPF(text=prog)


# attachkretprobe ruft die Kernel Space Funktion für jeden Syscall auf, und heftet sich an den entsprechenden
# Kernel Hook Point an. Einige System Calls sind jedoch nicht tracebar.
def attachkretprobe():
    b.attach_kretprobe(event=b.get_syscall_fnname("clone"), fn_name="sclone")
    b.attach_kretprobe(event=b.get_syscall_fnname("open"), fn_name="sopen")
    b.attach_kretprobe(event=b.get_syscall_fnname("open"), fn_name="sopen")
    b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="sread")
    b.attach_kretprobe(event=b.get_syscall_fnname("write"), fn_name="swrite")
    b.attach_kretprobe(event=b.get_syscall_fnname("open"), fn_name="sopen")
    b.attach_kretprobe(event=b.get_syscall_fnname("close"), fn_name="sclose")
    b.attach_kretprobe(event=b.get_syscall_fnname("stat"), fn_name="sstat")
    b.attach_kretprobe(event=b.get_syscall_fnname("fstat"), fn_name="sfstat")
    b.attach_kretprobe(event=b.get_syscall_fnname("lstat"), fn_name="slstat")
    b.attach_kretprobe(event=b.get_syscall_fnname("poll"), fn_name="spoll")
    b.attach_kretprobe(event=b.get_syscall_fnname("lseek"), fn_name="slseek")
    b.attach_kretprobe(event=b.get_syscall_fnname("mmap"), fn_name="smmap")
    b.attach_kretprobe(event=b.get_syscall_fnname("mprotect"), fn_name="smprotect")
    b.attach_kretprobe(event=b.get_syscall_fnname("munmap"), fn_name="smunmap")
    b.attach_kretprobe(event=b.get_syscall_fnname("brk"), fn_name="sbrk")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_sigaction"), fn_name="srt_sigaction")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_sigprocmask"), fn_name="srt_sigprocmask")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_sigreturn"), fn_name="srt_sigreturn")
    b.attach_kretprobe(event=b.get_syscall_fnname("ioctl"), fn_name="sioctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("pread64"), fn_name="spread64")
    b.attach_kretprobe(event=b.get_syscall_fnname("pwrite64"), fn_name="spwrite64")
    b.attach_kretprobe(event=b.get_syscall_fnname("readv"), fn_name="sreadv")
    b.attach_kretprobe(event=b.get_syscall_fnname("writev"), fn_name="swritev")
    b.attach_kretprobe(event=b.get_syscall_fnname("access"), fn_name="saccess")
    b.attach_kretprobe(event=b.get_syscall_fnname("pipe"), fn_name="spipe")
    b.attach_kretprobe(event=b.get_syscall_fnname("select"), fn_name="sselect")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_yield"), fn_name="ssched_yield")
    b.attach_kretprobe(event=b.get_syscall_fnname("mremap"), fn_name="smremap")
    b.attach_kretprobe(event=b.get_syscall_fnname("msync"), fn_name="smsync")
    b.attach_kretprobe(event=b.get_syscall_fnname("mincore"), fn_name="smincore")
    b.attach_kretprobe(event=b.get_syscall_fnname("madvise"), fn_name="smadvise")
    b.attach_kretprobe(event=b.get_syscall_fnname("shmget"), fn_name="sshmget")
    b.attach_kretprobe(event=b.get_syscall_fnname("shmat"), fn_name="sshmat")
    b.attach_kretprobe(event=b.get_syscall_fnname("shmctl"), fn_name="sshmctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("dup"), fn_name="sdup")
    b.attach_kretprobe(event=b.get_syscall_fnname("dup2"), fn_name="sdup2")
    b.attach_kretprobe(event=b.get_syscall_fnname("pause"), fn_name="spause")
    b.attach_kretprobe(event=b.get_syscall_fnname("nanosleep"), fn_name="snanosleep")
    b.attach_kretprobe(event=b.get_syscall_fnname("getitimer"), fn_name="sgetitimer")
    b.attach_kretprobe(event=b.get_syscall_fnname("alarm"), fn_name="salarm")
    b.attach_kretprobe(event=b.get_syscall_fnname("setitimer"), fn_name="ssetitimer")
    b.attach_kretprobe(event=b.get_syscall_fnname("getpid"), fn_name="sgetpid")
    b.attach_kretprobe(event=b.get_syscall_fnname("sendfile"), fn_name="ssendfile")
    b.attach_kretprobe(event=b.get_syscall_fnname("socket"), fn_name="ssocket")
    b.attach_kretprobe(event=b.get_syscall_fnname("connect"), fn_name="sconnect")
    b.attach_kretprobe(event=b.get_syscall_fnname("accept"), fn_name="saccept")
    b.attach_kretprobe(event=b.get_syscall_fnname("sendto"), fn_name="ssendto")
    b.attach_kretprobe(event=b.get_syscall_fnname("recvfrom"), fn_name="srecvfrom")
    b.attach_kretprobe(event=b.get_syscall_fnname("sendmsg"), fn_name="ssendmsg")
    b.attach_kretprobe(event=b.get_syscall_fnname("recvmsg"), fn_name="srecvmsg")
    b.attach_kretprobe(event=b.get_syscall_fnname("shutdown"), fn_name="sshutdown")
    b.attach_kretprobe(event=b.get_syscall_fnname("bind"), fn_name="sbind")
    b.attach_kretprobe(event=b.get_syscall_fnname("listen"), fn_name="slisten")
    b.attach_kretprobe(event=b.get_syscall_fnname("getsockname"), fn_name="sgetsockname")
    b.attach_kretprobe(event=b.get_syscall_fnname("getpeername"), fn_name="sgetpeername")
    b.attach_kretprobe(event=b.get_syscall_fnname("socketpair"), fn_name="ssocketpair")
    b.attach_kretprobe(event=b.get_syscall_fnname("setsockopt"), fn_name="ssetsockopt")
    b.attach_kretprobe(event=b.get_syscall_fnname("getsockopt"), fn_name="sgetsockopt")
    b.attach_kretprobe(event=b.get_syscall_fnname("fork"), fn_name="sfork")
    b.attach_kretprobe(event=b.get_syscall_fnname("vfork"), fn_name="svfork")
    b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="sexecve")
    b.attach_kretprobe(event=b.get_syscall_fnname("exit"), fn_name="sexit")
    b.attach_kretprobe(event=b.get_syscall_fnname("wait4"), fn_name="swait4")
    b.attach_kretprobe(event=b.get_syscall_fnname("kill"), fn_name="skill")
    b.attach_kretprobe(event=b.get_syscall_fnname("uname"), fn_name="suname")
    b.attach_kretprobe(event=b.get_syscall_fnname("semget"), fn_name="ssemget")
    b.attach_kretprobe(event=b.get_syscall_fnname("semop"), fn_name="ssemop")
    b.attach_kretprobe(event=b.get_syscall_fnname("semctl"), fn_name="ssemctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("shmdt"), fn_name="sshmdt")
    b.attach_kretprobe(event=b.get_syscall_fnname("msgget"), fn_name="smsgget")
    b.attach_kretprobe(event=b.get_syscall_fnname("msgsnd"), fn_name="smsgsnd")
    b.attach_kretprobe(event=b.get_syscall_fnname("msgrcv"), fn_name="smsgrcv")
    b.attach_kretprobe(event=b.get_syscall_fnname("msgctl"), fn_name="smsgctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("fcntl"), fn_name="sfcntl")
    b.attach_kretprobe(event=b.get_syscall_fnname("flock"), fn_name="sflock")
    b.attach_kretprobe(event=b.get_syscall_fnname("fsync"), fn_name="sfsync")
    b.attach_kretprobe(event=b.get_syscall_fnname("fdatasync"), fn_name="sfdatasync")
    b.attach_kretprobe(event=b.get_syscall_fnname("truncate"), fn_name="struncate")
    b.attach_kretprobe(event=b.get_syscall_fnname("ftruncate"), fn_name="sftruncate")
    b.attach_kretprobe(event=b.get_syscall_fnname("getdents"), fn_name="sgetdents")
    b.attach_kretprobe(event=b.get_syscall_fnname("getcwd"), fn_name="sgetcwd")
    b.attach_kretprobe(event=b.get_syscall_fnname("chdir"), fn_name="schdir")
    b.attach_kretprobe(event=b.get_syscall_fnname("fchdir"), fn_name="sfchdir")
    b.attach_kretprobe(event=b.get_syscall_fnname("rename"), fn_name="srename")
    b.attach_kretprobe(event=b.get_syscall_fnname("mkdir"), fn_name="smkdir")
    b.attach_kretprobe(event=b.get_syscall_fnname("rmdir"), fn_name="srmdir")
    b.attach_kretprobe(event=b.get_syscall_fnname("creat"), fn_name="screat")
    b.attach_kretprobe(event=b.get_syscall_fnname("link"), fn_name="slink")
    b.attach_kretprobe(event=b.get_syscall_fnname("unlink"), fn_name="sunlink")
    b.attach_kretprobe(event=b.get_syscall_fnname("symlink"), fn_name="ssymlink")
    b.attach_kretprobe(event=b.get_syscall_fnname("readlink"), fn_name="sreadlink")
    b.attach_kretprobe(event=b.get_syscall_fnname("chmod"), fn_name="schmod")
    b.attach_kretprobe(event=b.get_syscall_fnname("fchmod"), fn_name="sfchmod")
    b.attach_kretprobe(event=b.get_syscall_fnname("chown"), fn_name="schown")
    b.attach_kretprobe(event=b.get_syscall_fnname("fchown"), fn_name="sfchown")
    b.attach_kretprobe(event=b.get_syscall_fnname("lchown"), fn_name="slchown")
    b.attach_kretprobe(event=b.get_syscall_fnname("umask"), fn_name="sumask")
    b.attach_kretprobe(event=b.get_syscall_fnname("gettimeofday"), fn_name="sgettimeofday")
    b.attach_kretprobe(event=b.get_syscall_fnname("getrlimit"), fn_name="sgetrlimit")
    b.attach_kretprobe(event=b.get_syscall_fnname("getrusage"), fn_name="sgetrusage")
    b.attach_kretprobe(event=b.get_syscall_fnname("sysinfo"), fn_name="ssysinfo")
    b.attach_kretprobe(event=b.get_syscall_fnname("times"), fn_name="stimes")
    b.attach_kretprobe(event=b.get_syscall_fnname("ptrace"), fn_name="sptrace")
    b.attach_kretprobe(event=b.get_syscall_fnname("getuid"), fn_name="sgetuid")
    b.attach_kretprobe(event=b.get_syscall_fnname("syslog"), fn_name="ssyslog")
    b.attach_kretprobe(event=b.get_syscall_fnname("getgid"), fn_name="sgetgid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setuid"), fn_name="ssetuid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setgid"), fn_name="ssetgid")
    b.attach_kretprobe(event=b.get_syscall_fnname("geteuid"), fn_name="sgeteuid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getegid"), fn_name="sgetegid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setpgid"), fn_name="ssetpgid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getppid"), fn_name="sgetppid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getpgrp"), fn_name="sgetpgrp")
    b.attach_kretprobe(event=b.get_syscall_fnname("setsid"), fn_name="ssetsid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setreuid"), fn_name="ssetreuid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setregid"), fn_name="ssetregid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getgroups"), fn_name="sgetgroups")
    b.attach_kretprobe(event=b.get_syscall_fnname("setgroups"), fn_name="ssetgroups")
    b.attach_kretprobe(event=b.get_syscall_fnname("setresuid"), fn_name="ssetresuid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getresuid"), fn_name="sgetresuid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setresgid"), fn_name="ssetresgid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getresgid"), fn_name="sgetresgid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getpgid"), fn_name="sgetpgid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setfsuid"), fn_name="ssetfsuid")
    b.attach_kretprobe(event=b.get_syscall_fnname("setfsgid"), fn_name="ssetfsgid")
    b.attach_kretprobe(event=b.get_syscall_fnname("getsid"), fn_name="sgetsid")
    b.attach_kretprobe(event=b.get_syscall_fnname("capget"), fn_name="scapget")
    b.attach_kretprobe(event=b.get_syscall_fnname("capset"), fn_name="scapset")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_sigpending"), fn_name="srt_sigpending")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_sigtimedwait"), fn_name="srt_sigtimedwait")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_sigqueueinfo"), fn_name="srt_sigqueueinfo")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_sigsuspend"), fn_name="srt_sigsuspend")
    b.attach_kretprobe(event=b.get_syscall_fnname("sigaltstack"), fn_name="ssigaltstack")
    b.attach_kretprobe(event=b.get_syscall_fnname("utime"), fn_name="sutime")
    b.attach_kretprobe(event=b.get_syscall_fnname("mknod"), fn_name="smknod")
    b.attach_kretprobe(event=b.get_syscall_fnname("uselib"), fn_name="suselib")
    b.attach_kretprobe(event=b.get_syscall_fnname("personality"), fn_name="spersonality")
    b.attach_kretprobe(event=b.get_syscall_fnname("ustat"), fn_name="sustat")
    b.attach_kretprobe(event=b.get_syscall_fnname("statfs"), fn_name="sstatfs")
    b.attach_kretprobe(event=b.get_syscall_fnname("fstatfs"), fn_name="sfstatfs")
    b.attach_kretprobe(event=b.get_syscall_fnname("sysfs"), fn_name="ssysfs")
    b.attach_kretprobe(event=b.get_syscall_fnname("getpriority"), fn_name="sgetpriority")
    b.attach_kretprobe(event=b.get_syscall_fnname("setpriority"), fn_name="ssetpriority")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_setparam"), fn_name="ssched_setparam")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_getparam"), fn_name="ssched_getparam")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_setscheduler"), fn_name="ssched_setscheduler")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_getscheduler"), fn_name="ssched_getscheduler")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_get_priority_max"), fn_name="ssched_get_priority_max")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_get_priority_min"), fn_name="ssched_get_priority_min")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_rr_get_interval"), fn_name="ssched_rr_get_interval")
    b.attach_kretprobe(event=b.get_syscall_fnname("mlock"), fn_name="smlock")
    b.attach_kretprobe(event=b.get_syscall_fnname("munlock"), fn_name="smunlock")
    b.attach_kretprobe(event=b.get_syscall_fnname("mlockall"), fn_name="smlockall")
    b.attach_kretprobe(event=b.get_syscall_fnname("munlockall"), fn_name="smunlockall")
    b.attach_kretprobe(event=b.get_syscall_fnname("vhangup"), fn_name="svhangup")
    b.attach_kretprobe(event=b.get_syscall_fnname("modify_ldt"), fn_name="smodify_ldt")
    b.attach_kretprobe(event=b.get_syscall_fnname("pivot_root"), fn_name="spivot_root")
    # b.attach_kretprobe(event=b.get_syscall_fnname("sysctl"), fn_name="ssysctl") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("prctl"), fn_name="sprctl") not traceable
    b.attach_kretprobe(event=b.get_syscall_fnname("arch_prctl"), fn_name="sarch_prctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("adjtimex"), fn_name="sadjtimex")
    b.attach_kretprobe(event=b.get_syscall_fnname("setrlimit"), fn_name="ssetrlimit")
    b.attach_kretprobe(event=b.get_syscall_fnname("chroot"), fn_name="schroot")
    b.attach_kretprobe(event=b.get_syscall_fnname("sync"), fn_name="ssync")
    b.attach_kretprobe(event=b.get_syscall_fnname("acct"), fn_name="sacct")
    b.attach_kretprobe(event=b.get_syscall_fnname("settimeofday"), fn_name="ssettimeofday")
    b.attach_kretprobe(event=b.get_syscall_fnname("mount"), fn_name="smount")
    # b.attach_kretprobe(event=b.get_syscall_fnname("umount2"), fn_name="sumount2") not traceble
    b.attach_kretprobe(event=b.get_syscall_fnname("swapon"), fn_name="sswapon")
    b.attach_kretprobe(event=b.get_syscall_fnname("swapoff"), fn_name="sswapoff")
    b.attach_kretprobe(event=b.get_syscall_fnname("reboot"), fn_name="sreboot")
    b.attach_kretprobe(event=b.get_syscall_fnname("sethostname"), fn_name="ssethostname")
    # b.attach_kretprobe(event=b.get_syscall_fnname("setdomainname"), fn_name="ssetdomainname")
    # b.attach_kretprobe(event=b.get_syscall_fnname("iopl"), fn_name="siopl")
    # b.attach_kretprobe(event=b.get_syscall_fnname("ioperm"), fn_name="sioperm")
    # b.attach_kretprobe(event=b.get_syscall_fnname("create_module"), fn_name="screate_module") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("init_module"), fn_name="sinit_module")
    # b.attach_kretprobe(event=b.get_syscall_fnname("delete_module"), fn_name="sdelete_module")
    # b.attach_kretprobe(event=b.get_syscall_fnname("get_kernel_syms"), fn_name="sget_kernel_syms") not traceable, removed from Linux Kernel
    # b.attach_kretprobe(event=b.get_syscall_fnname("query_module"), fn_name="squery_module") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("quotactl"), fn_name="squotactl")
    # b.attach_kretprobe(event=b.get_syscall_fnname("quotactl"), fn_name="squotactl")
    # b.attach_kretprobe(event=b.get_syscall_fnname("nfsservctl"), fn_name="snfsservctl")
    # b.attach_kretprobe(event=b.get_syscall_fnname("getpmsg"), fn_name="sgetpmsg")
    # b.attach_kretprobe(event=b.get_syscall_fnname("putpmsg"), fn_name="sputpmsg")
    # b.attach_kretprobe(event=b.get_syscall_fnname("afs_syscall"), fn_name="safs_syscall")
    # b.attach_kretprobe(event=b.get_syscall_fnname("tuxcall"), fn_name="stuxcall")
    # b.attach_kretprobe(event=b.get_syscall_fnname("security"), fn_name="ssecurity")
    b.attach_kretprobe(event=b.get_syscall_fnname("gettid"), fn_name="sgettid")
    b.attach_kretprobe(event=b.get_syscall_fnname("readahead"), fn_name="sreadahead")
    b.attach_kretprobe(event=b.get_syscall_fnname("setxattr"), fn_name="ssetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("lsetxattr"), fn_name="slsetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("fsetxattr"), fn_name="sfsetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("getxattr"), fn_name="sgetxattr")
#    b.attach_kretprobe(event=b.get_syscall_fnname("lgetxattr"), fn_name="slgetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("fgetxattr"), fn_name="sfgetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("listxattr"), fn_name="slistxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("llistxattr"), fn_name="sllistxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("flistxattr"), fn_name="sflistxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("removexattr"), fn_name="sremovexattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("lremovexattr"), fn_name="slremovexattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("fremovexattr"), fn_name="sfremovexattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("tkill"), fn_name="stkill")
    b.attach_kretprobe(event=b.get_syscall_fnname("time"), fn_name="stime")
    b.attach_kretprobe(event=b.get_syscall_fnname("futex"), fn_name="sfutex")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_setaffinity"), fn_name="ssched_setaffinity")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_getaffinity"), fn_name="ssched_getaffinity")
    b.attach_kretprobe(event=b.get_syscall_fnname("set_thread_area"), fn_name="sset_thread_area")
    b.attach_kretprobe(event=b.get_syscall_fnname("io_setup"), fn_name="sio_setup")
    b.attach_kretprobe(event=b.get_syscall_fnname("io_destroy"), fn_name="sio_destroy")
    b.attach_kretprobe(event=b.get_syscall_fnname("io_getevents"), fn_name="sio_getevents")
    b.attach_kretprobe(event=b.get_syscall_fnname("io_submit"), fn_name="sio_submit")
    b.attach_kretprobe(event=b.get_syscall_fnname("io_cancel"), fn_name="sio_cancel")
    b.attach_kretprobe(event=b.get_syscall_fnname("get_thread_area"), fn_name="sget_thread_area")
    b.attach_kretprobe(event=b.get_syscall_fnname("lookup_dcookie"), fn_name="slookup_dcookie")
    b.attach_kretprobe(event=b.get_syscall_fnname("epoll_create"), fn_name="sepoll_create")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_ctl_old"), fn_name="sepoll_ctl_old")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_wait_old"), fn_name="sepoll_wait_old")
    b.attach_kretprobe(event=b.get_syscall_fnname("remap_file_pages"), fn_name="sremap_file_pages")
    b.attach_kretprobe(event=b.get_syscall_fnname("getdents64"), fn_name="sgetdents64")
    b.attach_kretprobe(event=b.get_syscall_fnname("set_tid_address"), fn_name="sset_tid_address")
    b.attach_kretprobe(event=b.get_syscall_fnname("restart_syscall"), fn_name="srestart_syscall")
    b.attach_kretprobe(event=b.get_syscall_fnname("semtimedop"), fn_name="ssemtimedop")
    b.attach_kretprobe(event=b.get_syscall_fnname("fadvise64"), fn_name="sfadvise64")
    b.attach_kretprobe(event=b.get_syscall_fnname("timer_create"), fn_name="stimer_create")
    b.attach_kretprobe(event=b.get_syscall_fnname("timer_settime"), fn_name="stimer_settime")
    b.attach_kretprobe(event=b.get_syscall_fnname("timer_gettime"), fn_name="stimer_gettime")
    b.attach_kretprobe(event=b.get_syscall_fnname("timer_getoverrun"), fn_name="stimer_getoverrun")
    b.attach_kretprobe(event=b.get_syscall_fnname("timer_delete"), fn_name="stimer_delete")
    b.attach_kretprobe(event=b.get_syscall_fnname("clock_settime"), fn_name="sclock_settime")
    b.attach_kretprobe(event=b.get_syscall_fnname("clock_gettime"), fn_name="sclock_gettime")
    b.attach_kretprobe(event=b.get_syscall_fnname("clock_getres"), fn_name="sclock_getres")
    b.attach_kretprobe(event=b.get_syscall_fnname("clock_nanosleep"), fn_name="sclock_nanosleep")
    b.attach_kretprobe(event=b.get_syscall_fnname("exit_group"), fn_name="sexit_group")
    b.attach_kretprobe(event=b.get_syscall_fnname("epoll_wait"), fn_name="sepoll_wait")
    b.attach_kretprobe(event=b.get_syscall_fnname("epoll_ctl"), fn_name="sepoll_ctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("tgkill"), fn_name="stgkill")
    b.attach_kretprobe(event=b.get_syscall_fnname("utimes"), fn_name="sutimes")
    # b.attach_kretprobe(event=b.get_syscall_fnname("vserver"), fn_name="svserver")
    b.attach_kretprobe(event=b.get_syscall_fnname("mbind"), fn_name="smbind")
    b.attach_kretprobe(event=b.get_syscall_fnname("set_mempolicy"), fn_name="sset_mempolicy")
    b.attach_kretprobe(event=b.get_syscall_fnname("get_mempolicy"), fn_name="sget_mempolicy")
    b.attach_kretprobe(event=b.get_syscall_fnname("mq_open"), fn_name="smq_open")
    b.attach_kretprobe(event=b.get_syscall_fnname("mq_unlink"), fn_name="smq_unlink")
    b.attach_kretprobe(event=b.get_syscall_fnname("mq_timedsend"), fn_name="smq_timedsend")
    b.attach_kretprobe(event=b.get_syscall_fnname("mq_timedreceive"), fn_name="smq_timedreceive")
    b.attach_kretprobe(event=b.get_syscall_fnname("mq_notify"), fn_name="smq_notify")
    b.attach_kretprobe(event=b.get_syscall_fnname("mq_getsetattr"), fn_name="smq_getsetattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("kexec_load"), fn_name="skexec_load")
    b.attach_kretprobe(event=b.get_syscall_fnname("waitid"), fn_name="swaitid")
    b.attach_kretprobe(event=b.get_syscall_fnname("add_key"), fn_name="sadd_key")
    b.attach_kretprobe(event=b.get_syscall_fnname("request_key"), fn_name="srequest_key")
    b.attach_kretprobe(event=b.get_syscall_fnname("keyctl"), fn_name="skeyctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("ioprio_set"), fn_name="sioprio_set")
    b.attach_kretprobe(event=b.get_syscall_fnname("ioprio_get"), fn_name="sioprio_get")
    b.attach_kretprobe(event=b.get_syscall_fnname("inotify_init"), fn_name="sinotify_init")
    b.attach_kretprobe(event=b.get_syscall_fnname("inotify_add_watch"), fn_name="sinotify_add_watch")
    b.attach_kretprobe(event=b.get_syscall_fnname("inotify_rm_watch"), fn_name="sinotify_rm_watch")
    b.attach_kretprobe(event=b.get_syscall_fnname("migrate_pages"), fn_name="smigrate_pages")
    b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="sopenat")
    b.attach_kretprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="smkdirat")
    b.attach_kretprobe(event=b.get_syscall_fnname("mknodat"), fn_name="smknodat")
    b.attach_kretprobe(event=b.get_syscall_fnname("fchownat"), fn_name="sfchownat")
    b.attach_kretprobe(event=b.get_syscall_fnname("futimesat"), fn_name="sfutimesat")
    b.attach_kretprobe(event=b.get_syscall_fnname("newfstatat"), fn_name="snewfstatat")
    b.attach_kretprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="sunlinkat")
    b.attach_kretprobe(event=b.get_syscall_fnname("renameat"), fn_name="srenameat")
    b.attach_kretprobe(event=b.get_syscall_fnname("linkat"), fn_name="slinkat")
    b.attach_kretprobe(event=b.get_syscall_fnname("symlinkat"), fn_name="ssymlinkat")
    b.attach_kretprobe(event=b.get_syscall_fnname("readlinkat"), fn_name="sreadlinkat")
    b.attach_kretprobe(event=b.get_syscall_fnname("fchmodat"), fn_name="sfchmodat")
    b.attach_kretprobe(event=b.get_syscall_fnname("faccessat"), fn_name="sfaccessat")
    b.attach_kretprobe(event=b.get_syscall_fnname("pselect6"), fn_name="spselect6")
    b.attach_kretprobe(event=b.get_syscall_fnname("ppoll"), fn_name="sppoll")
    b.attach_kretprobe(event=b.get_syscall_fnname("unshare"), fn_name="sunshare")
    b.attach_kretprobe(event=b.get_syscall_fnname("set_robust_list"), fn_name="sset_robust_list")
    b.attach_kretprobe(event=b.get_syscall_fnname("get_robust_list"), fn_name="sget_robust_list")
    b.attach_kretprobe(event=b.get_syscall_fnname("splice"), fn_name="ssplice")
    b.attach_kretprobe(event=b.get_syscall_fnname("tee"), fn_name="stee")
    b.attach_kretprobe(event=b.get_syscall_fnname("sync_file_range"), fn_name="ssync_file_range")
    b.attach_kretprobe(event=b.get_syscall_fnname("vmsplice"), fn_name="svmsplice")
    b.attach_kretprobe(event=b.get_syscall_fnname("move_pages"), fn_name="smove_pages")
    b.attach_kretprobe(event=b.get_syscall_fnname("utimensat"), fn_name="sutimensat")
    b.attach_kretprobe(event=b.get_syscall_fnname("epoll_pwait"), fn_name="sepoll_pwait")
    b.attach_kretprobe(event=b.get_syscall_fnname("signalfd"), fn_name="ssignalfd")
    b.attach_kretprobe(event=b.get_syscall_fnname("timerfd_create"), fn_name="stimerfd_create")
    b.attach_kretprobe(event=b.get_syscall_fnname("eventfd"), fn_name="seventfd")
    b.attach_kretprobe(event=b.get_syscall_fnname("fallocate"), fn_name="sfallocate")
    b.attach_kretprobe(event=b.get_syscall_fnname("timerfd_settime"), fn_name="stimerfd_settime")
    b.attach_kretprobe(event=b.get_syscall_fnname("timerfd_gettime"), fn_name="stimerfd_gettime")
    b.attach_kretprobe(event=b.get_syscall_fnname("accept4"), fn_name="saccept4")
    b.attach_kretprobe(event=b.get_syscall_fnname("signalfd4"), fn_name="ssignalfd4")
    b.attach_kretprobe(event=b.get_syscall_fnname("eventfd2"), fn_name="seventfd2")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_create1"), fn_name="sepoll_create1")
    b.attach_kretprobe(event=b.get_syscall_fnname("dup3"), fn_name="sdup3")
    b.attach_kretprobe(event=b.get_syscall_fnname("pipe2"), fn_name="spipe2")
    b.attach_kretprobe(event=b.get_syscall_fnname("inotify_init1"), fn_name="sinotify_init1")
    b.attach_kretprobe(event=b.get_syscall_fnname("preadv"), fn_name="spreadv")
    b.attach_kretprobe(event=b.get_syscall_fnname("pwritev"), fn_name="spwritev")
    b.attach_kretprobe(event=b.get_syscall_fnname("rt_tgsigqueueinfo"), fn_name="srt_tgsigqueueinfo")
    # b.attach_kretprobe(event=b.get_syscall_fnname("perf_event_open"), fn_name="sperf_event_open")
    b.attach_kretprobe(event=b.get_syscall_fnname("recvmmsg"), fn_name="srecvmmsg")
    b.attach_kretprobe(event=b.get_syscall_fnname("fanotify_init"), fn_name="sfanotify_init")
    b.attach_kretprobe(event=b.get_syscall_fnname("fanotify_mark"), fn_name="sfanotify_mark")
    b.attach_kretprobe(event=b.get_syscall_fnname("prlimit64"), fn_name="sprlimit64")
    b.attach_kretprobe(event=b.get_syscall_fnname("name_to_handle_at"), fn_name="sname_to_handle_at")
    b.attach_kretprobe(event=b.get_syscall_fnname("open_by_handle_at"), fn_name="sopen_by_handle_at")
    b.attach_kretprobe(event=b.get_syscall_fnname("clock_adjtime"), fn_name="sclock_adjtime")
    b.attach_kretprobe(event=b.get_syscall_fnname("syncfs"), fn_name="ssyncfs")
    b.attach_kretprobe(event=b.get_syscall_fnname("sendmmsg"), fn_name="ssendmmsg")
    b.attach_kretprobe(event=b.get_syscall_fnname("setns"), fn_name="ssetns")
    b.attach_kretprobe(event=b.get_syscall_fnname("getcpu"), fn_name="sgetcpu")
    b.attach_kretprobe(event=b.get_syscall_fnname("process_vm_readv"), fn_name="sprocess_vm_readv")
    b.attach_kretprobe(event=b.get_syscall_fnname("process_vm_writev"), fn_name="sprocess_vm_writev")
    b.attach_kretprobe(event=b.get_syscall_fnname("kcmp"), fn_name="skcmp")
    b.attach_kretprobe(event=b.get_syscall_fnname("finit_module"), fn_name="sfinit_module")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_setattr"), fn_name="ssched_setattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("sched_getattr"), fn_name="ssched_getattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("renameat2"), fn_name="srenameat2")
    b.attach_kretprobe(event=b.get_syscall_fnname("seccomp"), fn_name="sseccomp")
    b.attach_kretprobe(event=b.get_syscall_fnname("getrandom"), fn_name="sgetrandom")
    b.attach_kretprobe(event=b.get_syscall_fnname("memfd_create"), fn_name="smemfd_create")
    b.attach_kretprobe(event=b.get_syscall_fnname("kexec_file_load"), fn_name="skexec_file_load")
    b.attach_kretprobe(event=b.get_syscall_fnname("bpf"), fn_name="sbpf")


# Das Dictionary occurences speichert die Häufigkeit aller System Calls. Initial wird die Häufigkeit für alle
# System Calls auf 0 gesetzt und beim erfolgreichen Aufruf abgeändert.
occurences = dict(read=0,
                  write=0,
                  open=0,
                  close=0,
                  stat=0,
                  fstat=0,
                  lstat=0,
                  poll=0,
                  lseek=0,
                  mmap=0,
                  mprotect=0,
                  munmap=0,
                  brk=0,
                  rt_sigaction=0,
                  rt_sigprocmask=0,
                  rt_sigreturn=0,
                  ioctl=0,
                  pread64=0,
                  pwrite64=0,
                  readv=0,
                  writev=0,
                  access=0,
                  pipe=0,
                  select=0,
                  sched_yield=0,
                  mremap=0,
                  msync=0,
                  mincore=0,
                  madvise=0,
                  shmget=0,
                  shmat=0,
                  shmctl=0,
                  dup=0,
                  dup2=0,
                  pause=0,
                  nanosleep=0,
                  getitimer=0,
                  alarm=0,
                  setitimer=0,
                  getpid=0,
                  sendfile=0,
                  socket=0,
                  connect=0,
                  accept=0,
                  sendto=0,
                  recvfrom=0,
                  sendmsg=0,
                  recvmsg=0,
                  shutdown=0,
                  bind=0,
                  listen=0,
                  getsockname=0,
                  getpeername=0,
                  socketpair=0,
                  setsockopt=0,
                  getsockopt=0,
                  clone=0,
                  fork=0,
                  vfork=0,
                  execve=0,
                  exit=0,
                  wait4=0,
                  kill=0,
                  uname=0,
                  semget=0,
                  semop=0,
                  semctl=0,
                  shmdt=0,
                  msgget=0,
                  msgsnd=0,
                  msgrcv=0,
                  msgctl=0,
                  fcntl=0,
                  flock=0,
                  fsync=0,
                  fdatasync=0,
                  truncate=0,
                  ftruncate=0,
                  getdents=0,
                  getcwd=0,
                  chdir=0,
                  fchdir=0,
                  rename=0,
                  mkdir=0,
                  rmdir=0,
                  creat=0,
                  link=0,
                  unlink=0,
                  symlink=0,
                  readlink=0,
                  chmod=0,
                  fchmod=0,
                  chown=0,
                  fchown=0,
                  lchown=0,
                  umask=0,
                  gettimeofday=0,
                  getrlimit=0,
                  getrusage=0,
                  sysinfo=0,
                  times=0,
                  ptrace=0,
                  getuid=0,
                  syslog=0,
                  getgid=0,
                  setuid=0,
                  setgid=0,
                  geteuid=0,
                  getegid=0,
                  setpgid=0,
                  getppid=0,
                  getpgrp=0,
                  setsid=0,
                  setreuid=0,
                  setregid=0,
                  getgroups=0,
                  setgroups=0,
                  setresuid=0,
                  getresuid=0,
                  setresgid=0,
                  getresgid=0,
                  getpgid=0,
                  setfsuid=0,
                  setfsgid=0,
                  getsid=0,
                  capget=0,
                  capset=0,
                  rt_sigpending=0,
                  rt_sigtimedwait=0,
                  rt_sigqueueinfo=0,
                  rt_sigsuspend=0,
                  sigaltstack=0,
                  utime=0,
                  mknod=0,
                  uselib=0,
                  personality=0,
                  ustat=0,
                  statfs=0,
                  fstatfs=0,
                  sysfs=0,
                  getpriority=0,
                  setpriority=0,
                  sched_setparam=0,
                  sched_getparam=0,
                  sched_setscheduler=0,
                  sched_getscheduler=0,
                  sched_get_priority_max=0,
                  sched_get_priority_min=0,
                  sched_rr_get_interval=0,
                  mlock=0,
                  munlock=0,
                  mlockall=0,
                  munlockall=0,
                  vhangup=0,
                  modify_ldt=0,
                  pivot_root=0,
                  sysctl=0,
                  prctl=0,
                  arch_prctl=0,
                  adjtimex=0,
                  setrlimit=0,
                  chroot=0,
                  sync=0,
                  acct=0,
                  settimeofday=0,
                  mount=0,
                  umount2=0,
                  swapon=0,
                  swapoff=0,
                  reboot=0,
                  sethostname=0,
                  setdomainname=0,
                  iopl=0,
                  ioperm=0,
                  create_module=0,
                  init_module=0,
                  delete_module=0,
                  get_kernel_syms=0,
                  query_module=0,
                  quotactl=0,
                  nfsservctl=0,
                  getpmsg=0,
                  putpmsg=0,
                  afs_syscall=0,
                  tuxcall=0,
                  security=0,
                  gettid=0,
                  readahead=0,
                  setxattr=0,
                  lsetxattr=0,
                  fsetxattr=0,
                  getxattr=0,
                  lgetxattr=0,
                  fgetxattr=0,
                  listxattr=0,
                  llistxattr=0,
                  flistxattr=0,
                  removexattr=0,
                  lremovexattr=0,
                  fremovexattr=0,
                  tkill=0,
                  time=0,
                  futex=0,
                  sched_setaffinity=0,
                  sched_getaffinity=0,
                  set_thread_area=0,
                  io_setup=0,
                  io_destroy=0,
                  io_getevents=0,
                  io_submit=0,
                  io_cancel=0,
                  get_thread_area=0,
                  lookup_dcookie=0,
                  epoll_create=0,
                  epoll_ctl_old=0,
                  epoll_wait_old=0,
                  remap_file_pages=0,
                  getdents64=0,
                  set_tid_address=0,
                  restart_syscall=0,
                  semtimedop=0,
                  fadvise64=0,
                  timer_create=0,
                  timer_settime=0,
                  timer_gettime=0,
                  timer_getoverrun=0,
                  timer_delete=0,
                  clock_settime=0,
                  clock_gettime=0,
                  clock_getres=0,
                  clock_nanosleep=0,
                  exit_group=0,
                  epoll_wait=0,
                  epoll_ctl=0,
                  tgkill=0,
                  utimes=0,
                  vserver=0,
                  mbind=0,
                  set_mempolicy=0,
                  get_mempolicy=0,
                  mq_open=0,
                  mq_unlink=0,
                  mq_timedsend=0,
                  mq_timedreceive=0,
                  mq_notify=0,
                  mq_getsetattr=0,
                  kexec_load=0,
                  waitid=0,
                  add_key=0,
                  request_key=0,
                  keyctl=0,
                  ioprio_set=0,
                  ioprio_get=0,
                  inotify_init=0,
                  inotify_add_watch=0,
                  inotify_rm_watch=0,
                  migrate_pages=0,
                  openat=0,
                  mkdirat=0,
                  mknodat=0,
                  fchownat=0,
                  futimesat=0,
                  newfstatat=0,
                  unlinkat=0,
                  renameat=0,
                  linkat=0,
                  symlinkat=0,
                  readlinkat=0,
                  fchmodat=0,
                  faccessat=0,
                  pselect6=0,
                  ppoll=0,
                  unshare=0,
                  set_robust_list=0,
                  get_robust_list=0,
                  splice=0,
                  tee=0,
                  sync_file_range=0,
                  vmsplice=0,
                  move_pages=0,
                  utimensat=0,
                  epoll_pwait=0,
                  signalfd=0,
                  timerfd_create=0,
                  eventfd=0,
                  fallocate=0,
                  timerfd_settime=0,
                  timerfd_gettime=0,
                  accept4=0,
                  signalfd4=0,
                  eventfd2=0,
                  epoll_create1=0,
                  dup3=0,
                  pipe2=0,
                  inotify_init1=0,
                  preadv=0,
                  pwritev=0,
                  rt_tgsigqueueinfo=0,
                  perf_event_open=0,
                  recvmmsg=0,
                  fanotify_init=0,
                  fanotify_mark=0,
                  prlimit64=0,
                  name_to_handle_at=0,
                  open_by_handle_at=0,
                  clock_adjtime=0,
                  syncfs=0,
                  sendmmsg=0,
                  setns=0,
                  getcpu=0,
                  process_vm_readv=0,
                  process_vm_writev=0,
                  kcmp=0,
                  finit_module=0,
                  sched_setattr=0,
                  sched_getattr=0,
                  renameat2=0,
                  seccomp=0,
                  getrandom=0,
                  memfd_create=0,
                  kexec_file_load=0,
                  bpf=0, )


# Callback Funktion des Ring Buffers. Erhält die aus dem Kernelspace übergebene PID und Syscall-Nummer
# Danach wird geprüft, ob die PID im Array steht, welches alle PID's des zu tracenden Binaries enthält.
# Nun wird mittels der eindeutigen System Call Nummer überprüft, welcher System Call aufgerufen wurde,
# die Häufigkeit dieses System Calls wird nun im Dictionary, welches die Häufigkeiten speichert, erhöht
def updateoccurences(cpu, data, size):
    data = b["events"].event(data)
    syscall = data.syscallnumber
    ringbufferpid = data.pid
    if localpids.__contains__(str(ringbufferpid)):
        if int(ringbufferpid) != 1:
            if syscall == 0:
                occurences['clone'] = occurences['clone'] + 1
                # print("Update für folgenden System Call Clone. Neue Häufigkeit: " + str(occurences['clone']))
            elif syscall == 1:
                occurences['open'] = occurences['open'] + 1
                # print("Update für folgenden System Call Open. Neue Häufigkeit: " + str(occurences['open']))
            elif syscall == 2:
                occurences['read'] = occurences['read'] + 1
                # print("Update für folgenden System Call Read. Neue Häufigkeit: " + str(occurences['read']))
            elif syscall == 3:
                occurences['write'] = occurences['write'] + 1
                # print("Update für folgenden System Call Write. Neue Häufigkeit: " + str(occurences['write']))
            elif syscall == 4:
                occurences['close'] = occurences['close'] + 1
                # print("Update für folgenden System Call Close. Neue Häufigkeit: " + str(occurences['close']))
            elif syscall == 5:
                occurences['stat'] = occurences['stat'] + 1
                # print("Update für folgenden System Call Stat. Neue Häufigkeit: " + str(occurences['stat']))
            elif syscall == 6:
                occurences['fstat'] = occurences['fstat'] + 1
                # print("Update für folgenden System Call fstat. Neue Häufigkeit: " + str(occurences['fstat']))
            elif syscall == 7:
                occurences['lstat'] = occurences['lstat'] + 1
                # print("Update für folgenden System Call lstat. Neue Häufigkeit: " + str(occurences['lstat']))
            elif syscall == 8:
                occurences['poll'] = occurences['poll'] + 1
                # print("Update für folgenden System Call poll. Neue Häufigkeit: " + str(occurences['poll']))
            elif syscall == 9:
                occurences['lseek'] = occurences['lseek'] + 1
                # print("Update für folgenden System Call lseek. Neue Häufigkeit: " + str(occurences['lseek']))
            elif syscall == 10:
                occurences['mmap'] = occurences['mmap'] + 1
                # print("Update für folgenden System Call mmap. Neue Häufigkeit: " + str(occurences['mmap']))
            elif syscall == 11:
                occurences['mprotect'] = occurences['mprotect'] + 1
                # print("Update für folgenden System Call mprotect. Neue Häufigkeit: " + str(occurences['mprotect']))
            elif syscall == 12:
                occurences['munmap'] = occurences['munmap'] + 1
                # print("Update für folgenden System Call munmap. Neue Häufigkeit: " + str(occurences['munmap']))
            elif syscall == 13:
                occurences['brk'] = occurences['brk'] + 1
                # print("Update für folgenden System Call brk. Neue Häufigkeit: " + str(occurences['brk']))
            elif syscall == 14:
                occurences['rt_sigaction'] = occurences['rt_sigaction'] + 1
                # print("Update für folgenden System Call rt_sigaction. Neue Häufigkeit: " + str(
                #    occurences['rt_sigaction']))
            elif syscall == 15:
                occurences['rt_sigprocmask'] = occurences['rt_sigprocmask'] + 1
                # print("Update für folgenden System Call rt_sigprocmask. Neue Häufigkeit: " + str(
                #    occurences['rt_sigprocmask']))
            elif syscall == 16:
                occurences['rt_sigreturn'] = occurences['rt_sigreturn'] + 1
                # print("Update für folgenden System Call rt_sigreturn. Neue Häufigkeit: " + str(
                # occurences['rt_sigreturn']))
            elif syscall == 17:
                occurences['ioctl'] = occurences['ioctl'] + 1
                # print("Update für folgenden System Call ioctl. Neue Häufigkeit: " + str(occurences['ioctl']))
            elif syscall == 18:
                occurences['pread64'] = occurences['pread64'] + 1
                # print("Update für folgenden System Call pread64. Neue Häufigkeit: " + str(occurences['pread64']))
            elif syscall == 19:
                occurences['pwrite64'] = occurences['pwrite64'] + 1
                # print("Update für folgenden System Call pwrite64. Neue Häufigkeit: " + str(occurences['pwrite64']))
            elif syscall == 20:
                occurences['readv'] = occurences['readv'] + 1
                # print("Update für folgenden System Call readv. Neue Häufigkeit: " + str(occurences['readv']))
            elif syscall == 21:
                occurences['writev'] = occurences['writev'] + 1
                # print("Update für folgenden System Call writev. Neue Häufigkeit: " + str(occurences['writev']))
            elif syscall == 22:
                occurences['access'] = occurences['access'] + 1
                # print("Update für folgenden System Call access. Neue Häufigkeit: " + str(occurences['access']))
            elif syscall == 23:
                occurences['pipe'] = occurences['pipe'] + 1
                # print("Update für folgenden System Call pipe. Neue Häufigkeit: " + str(occurences['pipe']))
            elif syscall == 24:
                occurences['select'] = occurences['select'] + 1
                # print("Update für folgenden System Call select. Neue Häufigkeit: " + str(occurences['select']))
            elif syscall == 25:
                occurences['mremap'] = occurences['mremap'] + 1
                # print("Update für folgenden System Call mremap. Neue Häufigkeit: " + str(occurences['mremap']))
            elif syscall == 26:
                occurences['sched_yield'] = occurences['sched_yield'] + 1
                # print(
                #    "Update für folgenden System Call: sched_yield. Neue Häufigkeit: " + str(occurences['sched_yield']))
            elif syscall == 27:
                occurences['msync'] = occurences['msync'] + 1
                # print("Update für folgenden System Call msync. Neue Häufigkeit: " + str(occurences['msync']))
            elif syscall == 28:
                occurences['mincore'] = occurences['mincore'] + 1
                # print("Update für folgenden System Call mincore. Neue Häufigkeit: " + str(occurences['mincore']))
            elif syscall == 29:
                occurences['madvise'] = occurences['madvise'] + 1
                # print("Update für folgenden System Call madvise. Neue Häufigkeit: " + str(occurences['madvise']))
            elif syscall == 30:
                occurences['shmget'] = occurences['shmget'] + 1
                # print("Update für folgenden System Call shmget. Neue Häufigkeit: " + str(occurences['shmget']))
            elif syscall == 31:
                occurences['shmat'] = occurences['shmat'] + 1
                # print("Update für folgenden System Call shmat. Neue Häufigkeit: " + str(occurences['shmat']))
            elif syscall == 32:
                occurences['shmctl'] = occurences['shmctl'] + 1
                # print("Update für folgenden System Call shmctl. Neue Häufigkeit: " + str(occurences['shmctl']))
            elif syscall == 33:
                occurences['dup'] = occurences['dup'] + 1
                # print("Update für folgenden System Call dup. Neue Häufigkeit: " + str(occurences['dup']))
            elif syscall == 34:
                occurences['dup2'] = occurences['dup2'] + 1
                # print("Update für folgenden System Call dup2. Neue Häufigkeit: " + str(occurences['dup2']))
            elif syscall == 35:
                occurences['pause'] = occurences['pause'] + 1
                # print("Update für folgenden System Call pause. Neue Häufigkeit: " + str(occurences['pause']))
            elif syscall == 36:
                occurences['nanosleep'] = occurences['nanosleep'] + 1
                # print("Update für folgenden System Call nanosleep. Neue Häufigkeit: " + str(occurences['nanosleep']))
            elif syscall == 37:
                occurences['getitimer'] = occurences['getitimer'] + 1
                # print("Update für folgenden System Call getitimer. Neue Häufigkeit: " + str(occurences['getitimer']))
            elif syscall == 38:
                occurences['alarm'] = occurences['alarm'] + 1
                # print("Update für folgenden System Call alarm. Neue Häufigkeit: " + str(occurences['alarm']))
            elif syscall == 39:
                occurences['setitimer'] = occurences['setitimer'] + 1
                # print("Update für folgenden System Call setitimer. Neue Häufigkeit: " + str(occurences['setitimer']))
            elif syscall == 40:
                occurences['getpid'] = occurences['getpid'] + 1
                # print("Update für folgenden System Call getpid. Neue Häufigkeit: " + str(occurences['getpid']))
            elif syscall == 41:
                occurences['sendfile'] = occurences['sendfile'] + 1
                # print("Update für folgenden System Call sendfile. Neue Häufigkeit: " + str(occurences['sendfile']))
            elif syscall == 42:
                occurences['socket'] = occurences['socket'] + 1
                # print("Update für folgenden System Call socket. Neue Häufigkeit: " + str(occurences['socket']))
            elif syscall == 43:
                occurences['connect'] = occurences['connect'] + 1
                # print("Update für folgenden System Call connect. Neue Häufigkeit: " + str(occurences['connect']))
            elif syscall == 44:
                occurences['accept'] = occurences['accept'] + 1
                # print("Update für folgenden System Call accept. Neue Häufigkeit: " + str(occurences['accept']))
            elif syscall == 45:
                occurences['sendto'] = occurences['sendto'] + 1
                # print("Update für folgenden System Call sendto. Neue Häufigkeit: " + str(occurences['sendto']))
            elif syscall == 46:
                occurences['recvfrom'] = occurences['recvfrom'] + 1
                # print("Update für folgenden System Call recvfrom. Neue Häufigkeit: " + str(occurences['recvfrom']))
            elif syscall == 47:
                occurences['sendmsg'] = occurences['sendmsg'] + 1
                # print("Update für folgenden System Call sendmsg. Neue Häufigkeit: " + str(occurences['sendmsg']))
            elif syscall == 48:
                occurences['recvmsg'] = occurences['recvmsg'] + 1
                # print("Update für folgenden System Call recvmsg. Neue Häufigkeit: " + str(occurences['recvmsg']))
            elif syscall == 49:
                occurences['shutdown'] = occurences['shutdown'] + 1
                # print("Update für folgenden System Call shutdown. Neue Häufigkeit: " + str(occurences['shutdown']))
            elif syscall == 50:
                occurences['bind'] = occurences['bind'] + 1
                # print("Update für folgenden System Call bind. Neue Häufigkeit: " + str(occurences['bind']))
            elif syscall == 51:
                occurences['listen'] = occurences['listen'] + 1
                # print("Update für folgenden System Call listen. Neue Häufigkeit: " + str(occurences['listen']))
            elif syscall == 52:
                occurences['getsockname'] = occurences['getsockname'] + 1
                # print(
                #     "Update für folgenden System Call: getsockname. Neue Häufigkeit: " + str(occurences['getsockname']))
            elif syscall == 53:
                occurences['getpeername'] = occurences['getpeername'] + 1
                # print(
                #     "Update für folgenden System Call: getpeername. Neue Häufigkeit: " + str(occurences['getpeername']))
            elif syscall == 54:
                occurences['socketpair'] = occurences['socketpair'] + 1
                # print("Update für folgenden System Call socketpair. Neue Häufigkeit: " + str(occurences['socketpair']))
            elif syscall == 55:
                occurences['setsockopt'] = occurences['setsockopt'] + 1
                # print("Update für folgenden System Call setsockopt. Neue Häufigkeit: " + str(occurences['setsockopt']))
            elif syscall == 56:
                occurences['getsockopt'] = occurences['getsockopt'] + 1
                # print("Update für folgenden System Call getsockopt. Neue Häufigkeit: " + str(occurences['getsockopt']))
            elif syscall == 57:
                occurences['fork'] = occurences['fork'] + 1
                # print("Update für folgenden System Call fork. Neue Häufigkeit: " + str(occurences['fork']))
            elif syscall == 58:
                occurences['vfork'] = occurences['vfork'] + 1
                # print("Update für folgenden System Call vfork. Neue Häufigkeit: " + str(occurences['vfork']))
            elif syscall == 59:
                occurences['execve'] = occurences['execve'] + 1
                # print("Update für folgenden System Call execve. Neue Häufigkeit: " + str(occurences['execve']))
            elif syscall == 60:
                occurences['exit'] = occurences['exit'] + 1
                # print("Update für folgenden System Call exit. Neue Häufigkeit: " + str(occurences['exit']))
            elif syscall == 61:
                occurences['wait4'] = occurences['wait4'] + 1
                # print("Update für folgenden System Call wait4. Neue Häufigkeit: " + str(occurences['wait4']))
            elif syscall == 62:
                occurences['kill'] = occurences['kill'] + 1
                # print("Update für folgenden System Call kill. Neue Häufigkeit: " + str(occurences['kill']))
            elif syscall == 63:
                occurences['uname'] = occurences['uname'] + 1
                # print("Update für folgenden System Call uname. Neue Häufigkeit: " + str(occurences['uname']))
            elif syscall == 64:
                occurences['semget'] = occurences['semget'] + 1
                # print("Update für folgenden System Call semget. Neue Häufigkeit: " + str(occurences['semget']))
            elif syscall == 65:
                occurences['semop'] = occurences['semop'] + 1
                # print("Update für folgenden System Call semop. Neue Häufigkeit: " + str(occurences['semop']))
            elif syscall == 66:
                occurences['semctl'] = occurences['semctl'] + 1
                # print("Update für folgenden System Call semctl. Neue Häufigkeit: " + str(occurences['semctl']))
            elif syscall == 67:
                occurences['shmdt'] = occurences['shmdt'] + 1
                # print("Update für folgenden System Call shmdt. Neue Häufigkeit: " + str(occurences['shmdt']))
            elif syscall == 68:
                occurences['msgget'] = occurences['msgget'] + 1
                # print("Update für folgenden System Call msgget. Neue Häufigkeit: " + str(occurences['msgget']))
            elif syscall == 69:
                occurences['msgsnd'] = occurences['msgsnd'] + 1
                # print("Update für folgenden System Call msgsnd. Neue Häufigkeit: " + str(occurences['msgsnd']))
            elif syscall == 70:
                occurences['msgrcv'] = occurences['msgrcv'] + 1
                # print("Update für folgenden System Call msgrcv. Neue Häufigkeit: " + str(occurences['msgrcv']))
            elif syscall == 71:
                occurences['msgctl'] = occurences['msgctl'] + 1
                # print("Update für folgenden System Call msgctl. Neue Häufigkeit: " + str(occurences['msgctl']))
            elif syscall == 72:
                occurences['fcntl'] = occurences['fcntl'] + 1
                # print("Update für folgenden System Call fcntl. Neue Häufigkeit: " + str(occurences['fcntl']))
            elif syscall == 73:
                occurences['flock'] = occurences['flock'] + 1
                # print("Update für folgenden System Call flock. Neue Häufigkeit: " + str(occurences['flock']))
            elif syscall == 74:
                occurences['fsync'] = occurences['fsync'] + 1
                # print("Update für folgenden System Call fsync. Neue Häufigkeit: " + str(occurences['fsync']))
            elif syscall == 75:
                occurences['fdatasync'] = occurences['fdatasync'] + 1
                # print("Update für folgenden System Call fdatasync. Neue Häufigkeit: " + str(occurences['fdatasync']))
            elif syscall == 76:
                occurences['truncate'] = occurences['truncate'] + 1
                # print("Update für folgenden System Call truncate. Neue Häufigkeit: " + str(occurences['truncate']))
            elif syscall == 77:
                occurences['ftruncate'] = occurences['ftruncate'] + 1
                # print("Update für folgenden System Call ftruncate. Neue Häufigkeit: " + str(occurences['ftruncate']))
            elif syscall == 78:
                occurences['getdents'] = occurences['getdents'] + 1
                # print("Update für folgenden System Call getdents. Neue Häufigkeit: " + str(occurences['getdents']))
            elif syscall == 79:
                occurences['getcwd'] = occurences['getcwd'] + 1
                # print("Update für folgenden System Call getcwd. Neue Häufigkeit: " + str(occurences['getcwd']))
            elif syscall == 80:
                occurences['chdir'] = occurences['chdir'] + 1
                # print("Update für folgenden System Call chdir. Neue Häufigkeit: " + str(occurences['chdir']))
            elif syscall == 81:
                occurences['fchdir'] = occurences['fchdir'] + 1
                # print("Update für folgenden System Call fchdir. Neue Häufigkeit: " + str(occurences['fchdir']))
            elif syscall == 82:
                occurences['rename'] = occurences['rename'] + 1
                # print("Update für folgenden System Call rename. Neue Häufigkeit: " + str(occurences['rename']))
            elif syscall == 83:
                occurences['mkdir'] = occurences['mkdir'] + 1
                # print("Update für folgenden System Call mkdir. Neue Häufigkeit: " + str(occurences['mkdir']))
            elif syscall == 84:
                occurences['rmdir'] = occurences['rmdir'] + 1
                # print("Update für folgenden System Call rmdir. Neue Häufigkeit: " + str(occurences['rmdir']))
            elif syscall == 85:
                occurences['creat'] = occurences['creat'] + 1
                # print("Update für folgenden System Call creat. Neue Häufigkeit: " + str(occurences['creat']))
            elif syscall == 86:
                occurences['link'] = occurences['link'] + 1
                # print("Update für folgenden System Call link. Neue Häufigkeit: " + str(occurences['link']))
            elif syscall == 87:
                occurences['unlink'] = occurences['unlink'] + 1
                # print("Update für folgenden System Call unlink. Neue Häufigkeit: " + str(occurences['unlink']))
            elif syscall == 88:
                occurences['symlink'] = occurences['symlink'] + 1
                # print("Update für folgenden System Call symlink. Neue Häufigkeit: " + str(occurences['symlink']))
            elif syscall == 89:
                occurences['readlink'] = occurences['readlink'] + 1
                # print("Update für folgenden System Call readlink. Neue Häufigkeit: " + str(occurences['readlink']))
            elif syscall == 90:
                occurences['chmod'] = occurences['chmod'] + 1
                # print("Update für folgenden System Call chmod. Neue Häufigkeit: " + str(occurences['chmod']))
            elif syscall == 91:
                occurences['fchmod'] = occurences['fchmod'] + 1
                # print("Update für folgenden System Call fchmod. Neue Häufigkeit: " + str(occurences['fchmod']))
            elif syscall == 92:
                occurences['chown'] = occurences['chown'] + 1
                # print("Update für folgenden System Call chown. Neue Häufigkeit: " + str(occurences['chown']))
            elif syscall == 93:
                occurences['fchown'] = occurences['fchown'] + 1
                # print("Update für folgenden System Call fchown. Neue Häufigkeit: " + str(occurences['fchown']))
            elif syscall == 94:
                occurences['lchown'] = occurences['lchown'] + 1
                # print("Update für folgenden System Call lchown. Neue Häufigkeit: " + str(occurences['lchown']))
            elif syscall == 95:
                occurences['umask'] = occurences['umask'] + 1
                # print("Update für folgenden System Call umask. Neue Häufigkeit: " + str(occurences['umask']))
            elif syscall == 96:
                occurences['gettimeofday'] = occurences['gettimeofday'] + 1
                # print("Update für folgenden System Call gettimeofday. Neue Häufigkeit: " + str(
                #    occurences['gettimeofday']))
            elif syscall == 97:
                occurences['getrlimit'] = occurences['getrlimit'] + 1
                # print("Update für folgenden System Call getrlimit. Neue Häufigkeit: " + str(occurences['getrlimit']))
            elif syscall == 98:
                occurences['getrusage'] = occurences['getrusage'] + 1
                # print("Update für folgenden System Call getrusage. Neue Häufigkeit: " + str(occurences['getrusage']))
            elif syscall == 99:
                occurences['sysinfo'] = occurences['sysinfo'] + 1
                # print("Update für folgenden System Call sysinfo. Neue Häufigkeit: " + str(occurences['sysinfo']))
            elif syscall == 100:
                occurences['times'] = occurences['times'] + 1
                # print("Update für folgenden System Call times. Neue Häufigkeit: " + str(occurences['times']))
            elif syscall == 102:
                occurences['ptrace'] = occurences['ptrace'] + 1
                # print("Update für folgenden System Call ptrace. Neue Häufigkeit: " + str(occurences['ptrace']))
            elif syscall == 103:
                occurences['getuid'] = occurences['getuid'] + 1
                # print("Update für folgenden System Call getuid. Neue Häufigkeit: " + str(occurences['getuid']))
            elif syscall == 104:
                occurences['syslog'] = occurences['syslog'] + 1
                # print("Update für folgenden System Call syslog. Neue Häufigkeit: " + str(occurences['syslog']))
            elif syscall == 105:
                occurences['getgid'] = occurences['getgid'] + 1
                # print("Update für folgenden System Call getgid. Neue Häufigkeit: " + str(occurences['getgid']))
            elif syscall == 106:
                occurences['setuid'] = occurences['setuid'] + 1
                # print("Update für folgenden System Call setuid. Neue Häufigkeit: " + str(occurences['setuid']))
            elif syscall == 107:
                occurences['setgid'] = occurences['setgid'] + 1
                # print("Update für folgenden System Call setgid. Neue Häufigkeit: " + str(occurences['setgid']))
            elif syscall == 108:
                occurences['geteuid'] = occurences['geteuid'] + 1
                # print("Update für folgenden System Call geteuid. Neue Häufigkeit: " + str(occurences['geteuid']))
            elif syscall == 109:
                occurences['getegid'] = occurences['getegid'] + 1
                # print("Update für folgenden System Call getegid. Neue Häufigkeit: " + str(occurences['getegid']))
            elif syscall == 110:
                occurences['setpgid'] = occurences['setpgid'] + 1
                # print("Update für folgenden System Call setpgid. Neue Häufigkeit: " + str(occurences['setpgid']))
            elif syscall == 111:
                occurences['getppid'] = occurences['getppid'] + 1
                # print("Update für folgenden System Call getppid. Neue Häufigkeit: " + str(occurences['getppid']))
            elif syscall == 112:
                occurences['getpgrp'] = occurences['getpgrp'] + 1
                # print("Update für folgenden System Call getpgrp. Neue Häufigkeit: " + str(occurences['getpgrp']))
            elif syscall == 113:
                occurences['setsid'] = occurences['setsid'] + 1
                # print("Update für folgenden System Call setsid. Neue Häufigkeit: " + str(occurences['setsid']))
            elif syscall == 114:
                occurences['setreuid'] = occurences['setreuid'] + 1
                # print("Update für folgenden System Call setreuid. Neue Häufigkeit: " + str(occurences['setreuid']))
            elif syscall == 115:
                occurences['setregid'] = occurences['setregid'] + 1
                # print("Update für folgenden System Call setregid. Neue Häufigkeit: " + str(occurences['setregid']))
            elif syscall == 116:
                occurences['getgroups'] = occurences['getgroups'] + 1
                # print("Update für folgenden System Call getgroups. Neue Häufigkeit: " + str(occurences['getgroups']))
            elif syscall == 117:
                occurences['setgroups'] = occurences['setgroups'] + 1
                # print("Update für folgenden System Call setgroups. Neue Häufigkeit: " + str(occurences['setgroups']))
            elif syscall == 118:
                occurences['setresuid'] = occurences['setresuid'] + 1
                # print("Update für folgenden System Call setresuid. Neue Häufigkeit: " + str(occurences['setresuid']))
            elif syscall == 119:
                occurences['getresuid'] = occurences['getresuid'] + 1
                # print("Update für folgenden System Call getresuid. Neue Häufigkeit: " + str(occurences['getresuid']))
            elif syscall == 120:
                occurences['setresgid'] = occurences['setresgid'] + 1
                # print("Update für folgenden System Call setresgid. Neue Häufigkeit: " + str(occurences['setresgid']))
            elif syscall == 121:
                occurences['getresgid'] = occurences['getresgid'] + 1
                # print("Update für folgenden System Call getresgid. Neue Häufigkeit: " + str(occurences['getresgid']))
            elif syscall == 122:
                occurences['getpgid'] = occurences['getpgid'] + 1
                # print("Update für folgenden System Call getpgid. Neue Häufigkeit: " + str(occurences['getpgid']))
            elif syscall == 123:
                occurences['setfsuid'] = occurences['setfsuid'] + 1
                # print("Update für folgenden System Call setfsuid. Neue Häufigkeit: " + str(occurences['setfsuid']))
            elif syscall == 124:
                occurences['setfsgid'] = occurences['setfsgid'] + 1
                # print("Update für folgenden System Call setfsgid. Neue Häufigkeit: " + str(occurences['setfsgid']))
            elif syscall == 125:
                occurences['getsid'] = occurences['getsid'] + 1
                # print("Update für folgenden System Call getsid. Neue Häufigkeit: " + str(occurences['getsid']))
            elif syscall == 126:
                occurences['capget'] = occurences['capget'] + 1
                # print("Update für folgenden System Call capget. Neue Häufigkeit: " + str(occurences['capget']))
            elif syscall == 127:
                occurences['capset'] = occurences['capset'] + 1
                # print("Update für folgenden System Call capset. Neue Häufigkeit: " + str(occurences['capset']))
            elif syscall == 128:
                occurences['rt_sigpending'] = occurences['rt_sigpending'] + 1
                # print("Update für folgenden System Call rt_sigpending. Neue Häufigkeit: " + str(
                #    occurences['rt_sigpending']))
            elif syscall == 129:
                occurences['rt_sigtimedwait'] = occurences['rt_sigtimedwait'] + 1
                # print("Update für folgenden System Call rt_sigtimedwait. Neue Häufigkeit: " + str(
                #    occurences['rt_sigtimedwait']))
            elif syscall == 130:
                occurences['rt_sigqueueinfo'] = occurences['rt_sigqueueinfo'] + 1
                # print("Update für folgenden System Call rt_sigqueueinfo. Neue Häufigkeit: " + str(
                #    occurences['rt_sigqueueinfo']))
            elif syscall == 131:
                occurences['rt_sigsuspend'] = occurences['rt_sigsuspend'] + 1
                # print("Update für folgenden System Call rt_sigsuspend. Neue Häufigkeit: " + str(
                #    occurences['rt_sigsuspend']))
            elif syscall == 132:
                occurences['sigaltstack'] = occurences['sigaltstack'] + 1
                # print(
                #     "Update für folgenden System Call: sigaltstack. Neue Häufigkeit: " + str(occurences['sigaltstack']))
            elif syscall == 133:
                occurences['utime'] = occurences['utime'] + 1
                # print("Update für folgenden System Call utime. Neue Häufigkeit: " + str(occurences['utime']))
            elif syscall == 134:
                occurences['mknod'] = occurences['mknod'] + 1
                # print("Update für folgenden System Call mknod. Neue Häufigkeit: " + str(occurences['mknod']))
            elif syscall == 135:
                occurences['uselib'] = occurences['uselib'] + 1
                # print("Update für folgenden System Call uselib. Neue Häufigkeit: " + str(occurences['uselib']))
            elif syscall == 136:
                occurences['personality'] = occurences['personality'] + 1
                print(
                    "Update für folgenden System Call: personality. Neue Häufigkeit: " + str(occurences['personality']))
            elif syscall == 137:
                occurences['ustat'] = occurences['ustat'] + 1
                # print("Update für folgenden System Call ustat. Neue Häufigkeit: " + str(occurences['ustat']))
            elif syscall == 138:
                occurences['statfs'] = occurences['statfs'] + 1
                # print("Update für folgenden System Call statfs. Neue Häufigkeit: " + str(occurences['statfs']))
            elif syscall == 139:
                occurences['fstatfs'] = occurences['fstatfs'] + 1
                # print("Update für folgenden System Call fstatfs. Neue Häufigkeit: " + str(occurences['fstatfs']))
            elif syscall == 140:
                occurences['sysfs'] = occurences['sysfs'] + 1
                # print("Update für folgenden System Call sysfs. Neue Häufigkeit: " + str(occurences['sysfs']))
            elif syscall == 141:
                occurences['getpriority'] = occurences['getpriority'] + 1
                # print(
                #     "Update für folgenden System Call: getpriority. Neue Häufigkeit: " + str(occurences['getpriority']))
            elif syscall == 142:
                occurences['setpriority'] = occurences['setpriority'] + 1
                # print(
                #     "Update für folgenden System Call: setpriority. Neue Häufigkeit: " + str(occurences['setpriority']))
            elif syscall == 143:
                occurences['sched_setparam'] = occurences['sched_setparam'] + 1
                # print("Update für folgenden System Call sched_setparam. Neue Häufigkeit: " + str(
                #    occurences['sched_setparam']))
            elif syscall == 144:
                occurences['sched_getparam'] = occurences['sched_getparam'] + 1
                # print("Update für folgenden System Call sched_getparam. Neue Häufigkeit: " + str(
                #    occurences['sched_getparam']))
            elif syscall == 145:
                occurences['sched_setscheduler'] = occurences['sched_setscheduler'] + 1
                # print("Update für folgenden System Call sched_setscheduler. Neue Häufigkeit: " + str(
                #    occurences['sched_setscheduler']))
            elif syscall == 146:
                occurences['sched_getscheduler'] = occurences['sched_getscheduler'] + 1
                # print("Update für folgenden System Call sched_getscheduler. Neue Häufigkeit: " + str(
                #    occurences['sched_getscheduler']))
            elif syscall == 147:
                occurences['sched_get_priority_max'] = occurences['sched_get_priority_max'] + 1
                # print("Update für folgenden System Call sched_get_priority_max. Neue Häufigkeit: " + str(
                #    occurences['sched_get_priority_max']))
            elif syscall == 148:
                occurences['sched_get_priority_min'] = occurences['sched_get_priority_min'] + 1
                # print("Update für folgenden System Call sched_get_priority_min. Neue Häufigkeit: " + str(
                #    occurences['sched_get_priority_min']))
            elif syscall == 149:
                occurences['sched_rr_get_interval'] = occurences['sched_rr_get_interval'] + 1
                # print("Update für folgenden System Call sched_rr_get_interval. Neue Häufigkeit: " + str(
                #    occurences['sched_rr_get_interval']))
            elif syscall == 150:
                occurences['mlock'] = occurences['mlock'] + 1
                # print("Update für folgenden System Call mlock. Neue Häufigkeit: " + str(occurences['mlock']))
            elif syscall == 151:
                occurences['munlock'] = occurences['munlock'] + 1
                # print("Update für folgenden System Call munlock. Neue Häufigkeit: " + str(occurences['munlock']))
            elif syscall == 152:
                occurences['mlockall'] = occurences['mlockall'] + 1
                # print("Update für folgenden System Call mlockall. Neue Häufigkeit: " + str(occurences['mlockall']))
            elif syscall == 153:
                occurences['munlockall'] = occurences['munlockall'] + 1
                # print("Update für folgenden System Call munlockall. Neue Häufigkeit: " + str(occurences['munlockall']))
            elif syscall == 154:
                occurences['vhangup'] = occurences['vhangup'] + 1
                # print("Update für folgenden System Call vhangup. Neue Häufigkeit: " + str(occurences['vhangup']))
            elif syscall == 155:
                occurences['modify_ldt'] = occurences['modify_ldt'] + 1
                # print("Update für folgenden System Call modify_ldt. Neue Häufigkeit: " + str(occurences['modify_ldt']))
            elif syscall == 156:
                occurences['pivot_root'] = occurences['pivot_root'] + 1
                # print("Update für folgenden System Call pivot_root. Neue Häufigkeit: " + str(occurences['pivot_root']))
            elif syscall == 157:
                occurences['sysctl'] = occurences['sysctl'] + 1
                # print("Update für folgenden System Call sysctl. Neue Häufigkeit: " + str(occurences['sysctl']))
            elif syscall == 158:
                occurences['prctl'] = occurences['prctl'] + 1
                # print("Update für folgenden System Call prctl. Neue Häufigkeit: " + str(occurences['prctl']))
            elif syscall == 159:
                occurences['arch_prctl'] = occurences['arch_prctl'] + 1
                # print("Update für folgenden System Call arch_prctl. Neue Häufigkeit: " + str(occurences['arch_prctl']))
            elif syscall == 160:
                occurences['adjtimex'] = occurences['adjtimex'] + 1
                # print("Update für folgenden System Call adjtimex. Neue Häufigkeit: " + str(occurences['adjtimex']))
            elif syscall == 161:
                occurences['setrlimit'] = occurences['setrlimit'] + 1
                # print("Update für folgenden System Call setrlimit. Neue Häufigkeit: " + str(occurences['setrlimit']))
            elif syscall == 162:
                occurences['chroot'] = occurences['chroot'] + 1
                # print("Update für folgenden System Call chroot. Neue Häufigkeit: " + str(occurences['chroot']))
            elif syscall == 163:
                occurences['sync'] = occurences['sync'] + 1
                # print("Update für folgenden System Call sync. Neue Häufigkeit: " + str(occurences['sync']))
            elif syscall == 164:
                occurences['acct'] = occurences['acct'] + 1
                # print("Update für folgenden System Call acct. Neue Häufigkeit: " + str(occurences['acct']))
            elif syscall == 165:
                occurences['settimeofday'] = occurences['settimeofday'] + 1
                # print("Update für folgenden System Call settimeofday. Neue Häufigkeit: " + str(
                #    occurences['settimeofday']))
            elif syscall == 166:
                occurences['mount'] = occurences['mount'] + 1
                # print("Update für folgenden System Call mount. Neue Häufigkeit: " + str(occurences['mount']))
            elif syscall == 167:
                occurences['umount2'] = occurences['umount2'] + 1
                # print("Update für folgenden System Call umount2. Neue Häufigkeit: " + str(occurences['umount2']))
            elif syscall == 168:
                occurences['swapon'] = occurences['swapon'] + 1
                # print("Update für folgenden System Call swapon. Neue Häufigkeit: " + str(occurences['swapon']))
            elif syscall == 169:
                occurences['swapoff'] = occurences['swapoff'] + 1
                # print("Update für folgenden System Call swapoff. Neue Häufigkeit: " + str(occurences['swapoff']))
            elif syscall == 170:
                occurences['reboot'] = occurences['reboot'] + 1
                # print("Update für folgenden System Call reboot. Neue Häufigkeit: " + str(occurences['reboot']))
            elif syscall == 171:
                occurences['sethostname'] = occurences['sethostname'] + 1
                # print(
                #     "Update für folgenden System Call: sethostname. Neue Häufigkeit: " + str(occurences['sethostname']))
            elif syscall == 172:
                occurences['setdomainname'] = occurences['setdomainname'] + 1
                # print("Update für folgenden System Call setdomainname. Neue Häufigkeit: " + str(
                #    occurences['setdomainname']))
            elif syscall == 173:
                occurences['iopl'] = occurences['iopl'] + 1
                # print("Update für folgenden System Call iopl. Neue Häufigkeit: " + str(occurences['iopl']))
            elif syscall == 174:
                occurences['ioperm'] = occurences['ioperm'] + 1
                # print("Update für folgenden System Call ioperm. Neue Häufigkeit: " + str(occurences['ioperm']))
            elif syscall == 175:
                occurences['create_module'] = occurences['create_module'] + 1
                # print("Update für folgenden System Call create_module. Neue Häufigkeit: " + str(
                #    occurences['create_module']))
            elif syscall == 176:
                occurences['init_module'] = occurences['init_module'] + 1
                # print(
                #     "Update für folgenden System Call: init_module. Neue Häufigkeit: " + str(occurences['init_module']))
            elif syscall == 177:
                occurences['delete_module'] = occurences['delete_module'] + 1
                # print("Update für folgenden System Call delete_module. Neue Häufigkeit: " + str(
                #    occurences['delete_module']))
            elif syscall == 178:
                occurences['get_kernel_syms'] = occurences['get_kernel_syms'] + 1
                # print("Update für folgenden System Call get_kernel_syms. Neue Häufigkeit: " + str(
                #    occurences['get_kernel_syms']))
            elif syscall == 179:
                occurences['query_module'] = occurences['query_module'] + 1
                # print("Update für folgenden System Call query_module. Neue Häufigkeit: " + str(
                #    occurences['query_module']))
            elif syscall == 180:
                occurences['quotactl'] = occurences['quotactl'] + 1
                # print("Update für folgenden System Call quotactl. Neue Häufigkeit: " + str(occurences['quotactl']))
            elif syscall == 181:
                occurences['nfsservctl'] = occurences['nfsservctl'] + 1
                # print("Update für folgenden System Call nfsservctl. Neue Häufigkeit: " + str(occurences['nfsservctl']))
            elif syscall == 182:
                occurences['getpmsg'] = occurences['getpmsg'] + 1
                # print("Update für folgenden System Call getpmsg. Neue Häufigkeit: " + str(occurences['getpmsg']))
            elif syscall == 183:
                occurences['putpmsg'] = occurences['putpmsg'] + 1
                # print("Update für folgenden System Call putpmsg. Neue Häufigkeit: " + str(occurences['putpmsg']))
            elif syscall == 184:
                occurences['afs_syscall'] = occurences['afs_syscall'] + 1
                # print(
                #     "Update für folgenden System Call: afs_syscall. Neue Häufigkeit: " + str(occurences['afs_syscall']))
            elif syscall == 185:
                occurences['tuxcall'] = occurences['tuxcall'] + 1
                # print("Update für folgenden System Call tuxcall. Neue Häufigkeit: " + str(occurences['tuxcall']))
            elif syscall == 186:
                occurences['security'] = occurences['security'] + 1
                # print("Update für folgenden System Call security. Neue Häufigkeit: " + str(occurences['security']))
            elif syscall == 187:
                occurences['gettid'] = occurences['gettid'] + 1
                # print("Update für folgenden System Call gettid. Neue Häufigkeit: " + str(occurences['gettid']))
            elif syscall == 188:
                occurences['readahead'] = occurences['readahead'] + 1
                # print("Update für folgenden System Call readahead. Neue Häufigkeit: " + str(occurences['readahead']))
            elif syscall == 189:
                occurences['setxattr'] = occurences['setxattr'] + 1
                # print("Update für folgenden System Call setxattr. Neue Häufigkeit: " + str(occurences['setxattr']))
            elif syscall == 190:
                occurences['lsetxattr'] = occurences['lsetxattr'] + 1
                # print("Update für folgenden System Call lsetxattr. Neue Häufigkeit: " + str(occurences['lsetxattr']))
            elif syscall == 191:
                occurences['fsetxattr'] = occurences['fsetxattr'] + 1
                # print("Update für folgenden System Call fsetxattr. Neue Häufigkeit: " + str(occurences['fsetxattr']))
            elif syscall == 192:
                occurences['getxattr'] = occurences['getxattr'] + 1
                # print("Update für folgenden System Call getxattr. Neue Häufigkeit: " + str(occurences['getxattr']))
            # elif syscall == 192:
            #     occurences['lgetxattr'] = occurences['lgetxattr'] + 1
            #     # print("Update für folgenden System Call lgetxattr. Neue Häufigkeit: " + str(occurences['lgetxattr']))
            elif syscall == 193:
                occurences['fgetxattr'] = occurences['fgetxattr'] + 1
                # print("Update für folgenden System Call fgetxattr. Neue Häufigkeit: " + str(occurences['fgetxattr']))
            elif syscall == 194:
                occurences['listxattr'] = occurences['listxattr'] + 1
                # print("Update für folgenden System Call listxattr. Neue Häufigkeit: " + str(occurences['listxattr']))
            elif syscall == 195:
                occurences['llistxattr'] = occurences['llistxattr'] + 1
                # print("Update für folgenden System Call llistxattr. Neue Häufigkeit: " + str(occurences['llistxattr']))
            elif syscall == 196:
                occurences['flistxattr'] = occurences['flistxattr'] + 1
                # print("Update für folgenden System Call flistxattr. Neue Häufigkeit: " + str(occurences['flistxattr']))
            elif syscall == 197:
                occurences['removexattr'] = occurences['removexattr'] + 1
                print(
                    "Update für folgenden System Call: removexattr. Neue Häufigkeit: " + str(occurences['removexattr']))
            elif syscall == 198:
                occurences['lremovexattr'] = occurences['lremovexattr'] + 1
                # print("Update für folgenden System Call lremovexattr. Neue Häufigkeit: " + str(
                #    occurences['lremovexattr']))
            elif syscall == 199:
                occurences['fremovexattr'] = occurences['fremovexattr'] + 1
                # print("Update für folgenden System Call fremovexattr. Neue Häufigkeit: " + str(
                #    occurences['fremovexattr']))
            elif syscall == 200:
                occurences['tkill'] = occurences['tkill'] + 1
                # print("Update für folgenden System Call tkill. Neue Häufigkeit: " + str(occurences['tkill']))
            elif syscall == 201:
                occurences['time'] = occurences['time'] + 1
                # print("Update für folgenden System Call time. Neue Häufigkeit: " + str(occurences['time']))
            elif syscall == 202:
                occurences['futex'] = occurences['futex'] + 1
                # print("Update für folgenden System Call futex. Neue Häufigkeit: " + str(occurences['futex']))
            elif syscall == 203:
                occurences['sched_setaffinity'] = occurences['sched_setaffinity'] + 1
                # print("Update für folgenden System Call sched_setaffinity. Neue Häufigkeit: " + str(
                #    occurences['sched_setaffinity']))
            elif syscall == 204:
                occurences['sched_getaffinity'] = occurences['sched_getaffinity'] + 1
                # print("Update für folgenden System Call sched_getaffinity. Neue Häufigkeit: " + str(
                #    occurences['sched_getaffinity']))
            elif syscall == 205:
                occurences['set_thread_area'] = occurences['set_thread_area'] + 1
                # print("Update für folgenden System Call set_thread_area. Neue Häufigkeit: " + str(
                #    occurences['set_thread_area']))
            elif syscall == 206:
                occurences['io_setup'] = occurences['io_setup'] + 1
                # print("Update für folgenden System Call io_setup. Neue Häufigkeit: " + str(occurences['io_setup']))
            elif syscall == 207:
                occurences['io_destroy'] = occurences['io_destroy'] + 1
                # print("Update für folgenden System Call io_destroy. Neue Häufigkeit: " + str(occurences['io_destroy']))
            elif syscall == 208:
                occurences['io_getevents'] = occurences['io_getevents'] + 1
                # print("Update für folgenden System Call io_getevents. Neue Häufigkeit: " + str(
                #    occurences['io_getevents']))
            elif syscall == 209:
                occurences['io_submit'] = occurences['io_submit'] + 1
                # print("Update für folgenden System Call io_submit. Neue Häufigkeit: " + str(occurences['io_submit']))
            elif syscall == 210:
                occurences['io_cancel'] = occurences['io_cancel'] + 1
                # print("Update für folgenden System Call io_cancel. Neue Häufigkeit: " + str(occurences['io_cancel']))
            elif syscall == 211:
                occurences['get_thread_area'] = occurences['get_thread_area'] + 1
                # print("Update für folgenden System Call get_thread_area. Neue Häufigkeit: " + str(
                #    occurences['get_thread_area']))
            elif syscall == 212:
                occurences['lookup_dcookie'] = occurences['lookup_dcookie'] + 1
                # print("Update für folgenden System Call lookup_dcookie. Neue Häufigkeit: " + str(
                #    occurences['lookup_dcookie']))
            elif syscall == 213:
                occurences['epoll_create'] = occurences['epoll_create'] + 1
                # print("Update für folgenden System Call epoll_create. Neue Häufigkeit: " + str(
                #    occurences['epoll_create']))
            elif syscall == 214:
                occurences['epoll_ctl_old'] = occurences['epoll_ctl_old'] + 1
                # print("Update für folgenden System Call epoll_ctl_old. Neue Häufigkeit: " + str(
                #    occurences['epoll_ctl_old']))
            elif syscall == 215:
                occurences['epoll_wait_old'] = occurences['epoll_wait_old'] + 1
                # print("Update für folgenden System Call epoll_wait_old. Neue Häufigkeit: " + str(
                #    occurences['epoll_wait_old']))
            elif syscall == 216:
                occurences['remap_file_pages'] = occurences['remap_file_pages'] + 1
                # print("Update für folgenden System Call remap_file_pages. Neue Häufigkeit: " + str(
                #    occurences['remap_file_pages']))
            elif syscall == 217:
                occurences['getdents64'] = occurences['getdents64'] + 1
                # print("Update für folgenden System Call getdents64. Neue Häufigkeit: " + str(occurences['getdents64']))
            elif syscall == 218:
                occurences['set_tid_address'] = occurences['set_tid_address'] + 1
                # print("Update für folgenden System Call set_tid_address. Neue Häufigkeit: " + str(
                #    occurences['set_tid_address']))
            elif syscall == 219:
                occurences['restart_syscall'] = occurences['restart_syscall'] + 1
                # print("Update für folgenden System Call restart_syscall. Neue Häufigkeit: " + str(
                #    occurences['restart_syscall']))
            elif syscall == 220:
                occurences['semtimedop'] = occurences['semtimedop'] + 1
                # print("Update für folgenden System Call semtimedop. Neue Häufigkeit: " + str(occurences['semtimedop']))
            elif syscall == 221:
                occurences['fadvise64'] = occurences['fadvise64'] + 1
                # print("Update für folgenden System Call fadvise64. Neue Häufigkeit: " + str(occurences['fadvise64']))
            elif syscall == 222:
                occurences['timer_create'] = occurences['timer_create'] + 1
                # print("Update für folgenden System Call timer_create. Neue Häufigkeit: " + str(
                #    occurences['timer_create']))
            elif syscall == 223:
                occurences['timer_settime'] = occurences['timer_settime'] + 1
                # print("Update für folgenden System Call timer_settime. Neue Häufigkeit: " + str(
                #    occurences['timer_settime']))
            elif syscall == 224:
                occurences['timer_gettime'] = occurences['timer_gettime'] + 1
                # print("Update für folgenden System Call timer_gettime. Neue Häufigkeit: " + str(
                #    occurences['timer_gettime']))
            elif syscall == 225:
                occurences['timer_getoverrun'] = occurences['timer_getoverrun'] + 1
                # print("Update für folgenden System Call timer_getoverrun. Neue Häufigkeit: " + str(
                #    occurences['timer_getoverrun']))
            elif syscall == 226:
                occurences['timer_delete'] = occurences['timer_delete'] + 1
                # print("Update für folgenden System Call timer_delete. Neue Häufigkeit: " + str(
                #    occurences['timer_delete']))
            elif syscall == 227:
                occurences['clock_settime'] = occurences['clock_settime'] + 1
                # print("Update für folgenden System Call clock_settime. Neue Häufigkeit: " + str(
                #    occurences['clock_settime']))
            elif syscall == 228:
                occurences['clock_gettime'] = occurences['clock_gettime'] + 1
                # print("Update für folgenden System Call clock_gettime. Neue Häufigkeit: " + str(
                #    occurences['clock_gettime']))
            elif syscall == 229:
                occurences['clock_getres'] = occurences['clock_getres'] + 1
                # print("Update für folgenden System Call clock_getres. Neue Häufigkeit: " + str(
                #    occurences['clock_getres']))
            elif syscall == 230:
                occurences['clock_nanosleep'] = occurences['clock_nanosleep'] + 1
                # print("Update für folgenden System Call clock_nanosleep. Neue Häufigkeit: " + str(
                #    occurences['clock_nanosleep']))
            elif syscall == 231:
                occurences['exit_group'] = occurences['exit_group'] + 1
                # print("Update für folgenden System Call exit_group. Neue Häufigkeit: " + str(occurences['exit_group']))
            elif syscall == 232:
                occurences['epoll_wait'] = occurences['epoll_wait'] + 1
                # print("Update für folgenden System Call epoll_wait. Neue Häufigkeit: " + str(occurences['epoll_wait']))
            elif syscall == 233:
                occurences['epoll_ctl'] = occurences['epoll_ctl'] + 1
                # print("Update für folgenden System Call epoll_ctl. Neue Häufigkeit: " + str(occurences['epoll_ctl']))
            elif syscall == 234:
                occurences['tgkill'] = occurences['tgkill'] + 1
                # print("Update für folgenden System Call tgkill. Neue Häufigkeit: " + str(occurences['tgkill']))
            elif syscall == 235:
                occurences['utimes'] = occurences['utimes'] + 1
                # print("Update für folgenden System Call utimes. Neue Häufigkeit: " + str(occurences['utimes']))
            elif syscall == 236:
                occurences['vserver'] = occurences['vserver'] + 1
                # print("Update für folgenden System Call vserver. Neue Häufigkeit: " + str(occurences['vserver']))
            elif syscall == 237:
                occurences['mbind'] = occurences['mbind'] + 1
                # print("Update für folgenden System Call mbind. Neue Häufigkeit: " + str(occurences['mbind']))
            elif syscall == 238:
                occurences['set_mempolicy'] = occurences['set_mempolicy'] + 1
                # print("Update für folgenden System Call set_mempolicy. Neue Häufigkeit: " + str(
            #     occurences['set_mempolicy']))
            elif syscall == 239:
                occurences['get_mempolicy'] = occurences['get_mempolicy'] + 1
                # print("Update für folgenden System Call get_mempolicy. Neue Häufigkeit: " + str(
                #    occurences['get_mempolicy']))
            elif syscall == 240:
                occurences['mq_open'] = occurences['mq_open'] + 1
                # print("Update für folgenden System Call mq_open. Neue Häufigkeit: " + str(occurences['mq_open']))
            elif syscall == 241:
                occurences['mq_unlink'] = occurences['mq_unlink'] + 1
                # print("Update für folgenden System Call mq_unlink. Neue Häufigkeit: " + str(occurences['mq_unlink']))
            elif syscall == 242:
                occurences['mq_timedsend'] = occurences['mq_timedsend'] + 1
                # print("Update für folgenden System Call mq_timedsend. Neue Häufigkeit: " + str(
                #    occurences['mq_timedsend']))
            elif syscall == 243:
                occurences['mq_timedreceive'] = occurences['mq_timedreceive'] + 1
                # print("Update für folgenden System Call mq_timedreceive. Neue Häufigkeit: " + str(
                #    occurences['mq_timedreceive']))
            elif syscall == 244:
                occurences['mq_notify'] = occurences['mq_notify'] + 1
                # print("Update für folgenden System Call mq_notify. Neue Häufigkeit: " + str(occurences['mq_notify']))
            elif syscall == 245:
                occurences['mq_getsetattr'] = occurences['mq_getsetattr'] + 1
                # print("Update für folgenden System Call mq_getsetattr. Neue Häufigkeit: " + str(
                #    occurences['mq_getsetattr']))
            elif syscall == 246:
                occurences['kexec_load'] = occurences['kexec_load'] + 1
                # print("Update für folgenden System Call kexec_load. Neue Häufigkeit: " + str(occurences['kexec_load']))
            elif syscall == 247:
                occurences['waitid'] = occurences['waitid'] + 1
                # print("Update für folgenden System Call waitid. Neue Häufigkeit: " + str(occurences['waitid']))
            elif syscall == 248:
                occurences['add_key'] = occurences['add_key'] + 1
                # print("Update für folgenden System Call add_key. Neue Häufigkeit: " + str(occurences['add_key']))
            elif syscall == 249:
                occurences['request_key'] = occurences['request_key'] + 1
                # print(
                #     "Update für folgenden System Call: request_key. Neue Häufigkeit: " + str(occurences['request_key']))
            elif syscall == 250:
                occurences['keyctl'] = occurences['keyctl'] + 1
                # print("Update für folgenden System Call keyctl. Neue Häufigkeit: " + str(occurences['keyctl']))
            elif syscall == 251:
                occurences['ioprio_set'] = occurences['ioprio_set'] + 1
                # print("Update für folgenden System Call ioprio_set. Neue Häufigkeit: " + str(occurences['ioprio_set']))
            elif syscall == 252:
                occurences['ioprio_get'] = occurences['ioprio_get'] + 1
                # print("Update für folgenden System Call ioprio_get. Neue Häufigkeit: " + str(occurences['ioprio_get']))
            elif syscall == 253:
                occurences['inotify_init'] = occurences['inotify_init'] + 1
                # print("Update für folgenden System Call inotify_init. Neue Häufigkeit: " + str(
                #    occurences['inotify_init']))
            elif syscall == 254:
                occurences['inotify_add_watch'] = occurences['inotify_add_watch'] + 1
                # print("Update für folgenden System Call inotify_add_watch. Neue Häufigkeit: " + str(
                #    occurences['inotify_add_watch']))
            elif syscall == 255:
                occurences['inotify_rm_watch'] = occurences['inotify_rm_watch'] + 1
                # print("Update für folgenden System Call inotify_rm_watch. Neue Häufigkeit: " + str(
                #    occurences['inotify_rm_watch']))
            elif syscall == 256:
                occurences['migrate_pages'] = occurences['migrate_pages'] + 1
                # print("Update für folgenden System Call migrate_pages. Neue Häufigkeit: " + str(
                #    occurences['migrate_pages']))
            elif syscall == 257:
                occurences['openat'] = occurences['openat'] + 1
                # print("Update für folgenden System Call openat. Neue Häufigkeit: " + str(occurences['openat']))
            elif syscall == 258:
                occurences['mkdirat'] = occurences['mkdirat'] + 1
                # print("Update für folgenden System Call mkdirat. Neue Häufigkeit: " + str(occurences['mkdirat']))
            elif syscall == 259:
                occurences['mknodat'] = occurences['mknodat'] + 1
                # print("Update für folgenden System Call mknodat. Neue Häufigkeit: " + str(occurences['mknodat']))
            elif syscall == 260:
                occurences['fchownat'] = occurences['fchownat'] + 1
                # print("Update für folgenden System Call fchownat. Neue Häufigkeit: " + str(occurences['fchownat']))
            elif syscall == 261:
                occurences['futimesat'] = occurences['futimesat'] + 1
                # print("Update für folgenden System Call futimesat. Neue Häufigkeit: " + str(occurences['futimesat']))
            elif syscall == 262:
                occurences['newfstatat'] = occurences['newfstatat'] + 1
                # print("Update für folgenden System Call newfstatat. Neue Häufigkeit: " + str(occurences['newfstatat']))
            elif syscall == 263:
                occurences['unlinkat'] = occurences['unlinkat'] + 1
                # print("Update für folgenden System Call unlinkat. Neue Häufigkeit: " + str(occurences['unlinkat']))
            elif syscall == 264:
                occurences['renameat'] = occurences['renameat'] + 1
                # print("Update für folgenden System Call renameat. Neue Häufigkeit: " + str(occurences['renameat']))
            elif syscall == 265:
                occurences['linkat'] = occurences['linkat'] + 1
                # print("Update für folgenden System Call linkat. Neue Häufigkeit: " + str(occurences['linkat']))
            elif syscall == 266:
                occurences['symlinkat'] = occurences['symlinkat'] + 1
                # print("Update für folgenden System Call symlinkat. Neue Häufigkeit: " + str(occurences['symlinkat']))
            elif syscall == 267:
                occurences['readlinkat'] = occurences['readlinkat'] + 1
                # print("Update für folgenden System Call readlinkat. Neue Häufigkeit: " + str(occurences['readlinkat']))
            elif syscall == 268:
                occurences['fchmodat'] = occurences['fchmodat'] + 1
                # print("Update für folgenden System Call fchmodat. Neue Häufigkeit: " + str(occurences['fchmodat']))
            elif syscall == 269:
                occurences['faccessat'] = occurences['faccessat'] + 1
                # print("Update für folgenden System Call faccessat. Neue Häufigkeit: " + str(occurences['faccessat']))
            elif syscall == 270:
                occurences['pselect6'] = occurences['pselect6'] + 1
                # print("Update für folgenden System Call pselect6. Neue Häufigkeit: " + str(occurences['pselect6']))
            elif syscall == 271:
                occurences['ppoll'] = occurences['ppoll'] + 1
                # print("Update für folgenden System Call ppoll. Neue Häufigkeit: " + str(occurences['ppoll']))
            elif syscall == 272:
                occurences['unshare'] = occurences['unshare'] + 1
                # print("Update für folgenden System Call unshare. Neue Häufigkeit: " + str(occurences['unshare']))
            elif syscall == 273:
                occurences['set_robust_list'] = occurences['set_robust_list'] + 1
                # print("Update für folgenden System Call set_robust_list. Neue Häufigkeit: " + str(
                #    occurences['set_robust_list']))
            elif syscall == 274:
                occurences['get_robust_list'] = occurences['get_robust_list'] + 1
                # print("Update für folgenden System Call get_robust_list. Neue Häufigkeit: " + str(
                #    occurences['get_robust_list']))
            elif syscall == 275:
                occurences['splice'] = occurences['splice'] + 1
                # print("Update für folgenden System Call splice. Neue Häufigkeit: " + str(occurences['splice']))
            elif syscall == 276:
                occurences['tee'] = occurences['tee'] + 1
                # print("Update für folgenden System Call tee. Neue Häufigkeit: " + str(occurences['tee']))
            elif syscall == 277:
                occurences['sync_file_range'] = occurences['sync_file_range'] + 1
                # print("Update für folgenden System Call sync_file_range. Neue Häufigkeit: " + str(
                #    occurences['sync_file_range']))
            elif syscall == 278:
                occurences['vmsplice'] = occurences['vmsplice'] + 1
                # print("Update für folgenden System Call vmsplice. Neue Häufigkeit: " + str(occurences['vmsplice']))
            elif syscall == 279:
                occurences['move_pages'] = occurences['move_pages'] + 1
                # print("Update für folgenden System Call move_pages. Neue Häufigkeit: " + str(occurences['move_pages']))
            elif syscall == 280:
                occurences['utimensat'] = occurences['utimensat'] + 1
                # print("Update für folgenden System Call utimensat. Neue Häufigkeit: " + str(occurences['utimensat']))
            elif syscall == 281:
                occurences['epoll_pwait'] = occurences['epoll_pwait'] + 1
                # print(
                #     "Update für folgenden System Call: epoll_pwait. Neue Häufigkeit: " + str(occurences['epoll_pwait']))
            elif syscall == 282:
                occurences['signalfd'] = occurences['signalfd'] + 1
                # print("Update für folgenden System Call signalfd. Neue Häufigkeit: " + str(occurences['utimensat']))
            elif syscall == 283:
                occurences['timerfd_create'] = occurences['timerfd_create'] + 1
                # print("Update für folgenden System Call timerfd_create. Neue Häufigkeit: " + str(
                #    occurences['timerfd_create']))
            elif syscall == 284:
                occurences['eventfd'] = occurences['eventfd'] + 1
                # print("Update für folgenden System Call eventfd. Neue Häufigkeit: " + str(occurences['eventfd']))
            elif syscall == 285:
                occurences['fallocate'] = occurences['fallocate'] + 1
                # print("Update für folgenden System Call fallocate. Neue Häufigkeit: " + str(occurences['fallocate']))
            elif syscall == 286:
                occurences['timerfd_settime'] = occurences['timerfd_settime'] + 1
                # print("Update für folgenden System Call timerfd_settime. Neue Häufigkeit: " + str(
                #    occurences['timerfd_settime']))
            elif syscall == 287:
                occurences['timerfd_gettime'] = occurences['timerfd_gettime'] + 1
                # print("Update für folgenden System Call timerfd_gettime. Neue Häufigkeit: " + str(
                #    occurences['timerfd_gettime']))
            elif syscall == 288:
                occurences['accept4'] = occurences['accept4'] + 1
                # print("Update für folgenden System Call accept4. Neue Häufigkeit: " + str(occurences['accept4']))
            elif syscall == 289:
                occurences['signalfd4'] = occurences['signalfd4'] + 1
                # print("Update für folgenden System Call signalfd4. Neue Häufigkeit: " + str(occurences['signalfd4']))
            elif syscall == 290:
                occurences['eventfd2'] = occurences['eventfd2'] + 1
                # print("Update für folgenden System Call eventfd2. Neue Häufigkeit: " + str(occurences['eventfd2']))
            elif syscall == 291:
                occurences['epoll_create1'] = occurences['epoll_create1'] + 1
                # print("Update für folgenden System Call epoll_create1. Neue Häufigkeit: " + str(
                #    occurences['epoll_create1']))
            elif syscall == 292:
                occurences['dup3'] = occurences['dup3'] + 1
                # print("Update für folgenden System Call dup3. Neue Häufigkeit: " + str(occurences['eventfd2']))
            elif syscall == 293:
                occurences['pipe2'] = occurences['pipe2'] + 1
                # print("Update für folgenden System Call pipe2. Neue Häufigkeit: " + str(occurences['pipe2']))
            elif syscall == 294:
                occurences['inotify_init1'] = occurences['inotify_init1'] + 1
                # print("Update für folgenden System Call inotify_init1. Neue Häufigkeit: " + str(
                #    occurences['inotify_init1']))
            elif syscall == 295:
                occurences['preadv'] = occurences['preadv'] + 1
                # print("Update für folgenden System Call preadv. Neue Häufigkeit: " + str(occurences['preadv']))
            elif syscall == 296:
                occurences['pwritev'] = occurences['pwritev'] + 1
                # print("Update für folgenden System Call pwritev. Neue Häufigkeit: " + str(occurences['pwritev']))
            elif syscall == 297:
                occurences['rt_tgsigqueueinfo'] = occurences['rt_tgsigqueueinfo'] + 1
                # print("Update für folgenden System Call rt_tgsigqueueinfo. Neue Häufigkeit: " + str(
                #    occurences['rt_tgsigqueueinfo']))
            elif syscall == 298:
                occurences['perf_event_open'] = occurences['perf_event_open'] + 1
                # print("Update für folgenden System Call perf_event_open. Neue Häufigkeit: " + str(
                #    occurences['perf_event_open']))
            elif syscall == 299:
                occurences['recvmmsg'] = occurences['recvmmsg'] + 1
                # print("Update für folgenden System Call recvmmsg. Neue Häufigkeit: " + str(occurences['recvmmsg']))
            elif syscall == 300:
                occurences['fanotify_init'] = occurences['fanotify_init'] + 1
                # print("Update für folgenden System Call fanotify_init. Neue Häufigkeit: " + str(
                #    occurences['fanotify_init']))
            elif syscall == 301:
                occurences['fanotify_mark'] = occurences['fanotify_mark'] + 1
                # print("Update für folgenden System Call fanotify_mark. Neue Häufigkeit: " + str(
                #    occurences['fanotify_mark']))
            elif syscall == 302:
                occurences['prlimit64'] = occurences['prlimit64'] + 1
                # print("Update für folgenden System Call prlimit64. Neue Häufigkeit: " + str(occurences['prlimit64']))
            elif syscall == 303:
                occurences['name_to_handle_at'] = occurences['name_to_handle_at'] + 1
                # print("Update für folgenden System Call name_to_handle_at. Neue Häufigkeit: " + str(
                #    occurences['name_to_handle_at']))
            elif syscall == 304:
                occurences['open_by_handle_at'] = occurences['open_by_handle_at'] + 1
                # print("Update für folgenden System Call open_by_handle_at. Neue Häufigkeit: " + str(
                #    occurences['open_by_handle_at']))
            elif syscall == 305:
                occurences['clock_adjtime'] = occurences['clock_adjtime'] + 1
                # print("Update für folgenden System Call clock_adjtime. Neue Häufigkeit: " + str(
                #    occurences['clock_adjtime']))
            elif syscall == 306:
                occurences['syncfs'] = occurences['syncfs'] + 1
                # print("Update für folgenden System Call syncfs. Neue Häufigkeit: " + str(occurences['syncfs']))
            elif syscall == 307:
                occurences['sendmmsg'] = occurences['sendmmsg'] + 1
                # print("Update für folgenden System Call sendmmsg. Neue Häufigkeit: " + str(occurences['sendmmsg']))
            elif syscall == 308:
                occurences['setns'] = occurences['setns'] + 1
                # print("Update für folgenden System Call setns. Neue Häufigkeit: " + str(occurences['setns']))
            elif syscall == 309:
                occurences['getcpu'] = occurences['getcpu'] + 1
                # print("Update für folgenden System Call getcpu. Neue Häufigkeit: " + str(occurences['getcpu']))
            elif syscall == 310:
                occurences['process_vm_readv'] = occurences['process_vm_readv'] + 1
                # print("Update für folgenden System Call process_vm_readv. Neue Häufigkeit: " + str(
                #    occurences['process_vm_readv']))
            elif syscall == 311:
                occurences['process_vm_writev'] = occurences['process_vm_writev'] + 1
                # print("Update für folgenden System Call process_vm_writev. Neue Häufigkeit: " + str(
                #    occurences['process_vm_writev']))
            elif syscall == 312:
                occurences['kcmp'] = occurences['kcmp'] + 1
                # print("Update für folgenden System Call kcmp. Neue Häufigkeit: " + str(occurences['kcmp']))
            elif syscall == 313:
                occurences['finit_module'] = occurences['finit_module'] + 1
                # print("Update für folgenden System Call finit_module. Neue Häufigkeit: " + str(
                #    occurences['finit_module']))
            elif syscall == 314:
                occurences['sched_setattr'] = occurences['sched_setattr'] + 1
                # print("Update für folgenden System Call sched_setattr. Neue Häufigkeit: " + str(
                #    occurences['sched_setattr']))
            elif syscall == 315:
                occurences['sched_getattr'] = occurences['sched_getattr'] + 1
                # print("Update für folgenden System Call sched_getattr. Neue Häufigkeit: " + str(
                #    occurences['sched_getattr']))
            elif syscall == 316:
                occurences['renameat2'] = occurences['renameat2'] + 1
                # print("Update für folgenden System Call renameat2. Neue Häufigkeit: " + str(occurences['renameat2']))
            elif syscall == 317:
                occurences['seccomp'] = occurences['seccomp'] + 1
                # print("Update für folgenden System Call seccomp. Neue Häufigkeit: " + str(occurences['seccomp']))
            elif syscall == 318:
                occurences['getrandom'] = occurences['getrandom'] + 1
                # print("Update für folgenden System Call getrandom. Neue Häufigkeit: " + str(occurences['getrandom']))
            elif syscall == 319:
                occurences['memfd_create'] = occurences['memfd_create'] + 1
                # print("Update für folgenden System Call memfd_create. Neue Häufigkeit: " + str(
                #    occurences['memfd_create']))
            elif syscall == 320:
                occurences['kexec_file_load'] = occurences['kexec_file_load'] + 1
                # print("Update für folgenden System Call kexec_file_load. Neue Häufigkeit: " + str(
                #    occurences['kexec_file_load']))
            elif syscall == 321:
                occurences['bpf'] = occurences['bpf'] + 1
                # print("Update für folgenden System Call bpf. Neue Häufigkeit: " + str(occurences['process_vm_readv']))

# Funktion zum Auslesen der events im Kernel Ring Buffer. Dabei wird für jeden Eintrag im Ring Buffer die
# Callback Funktion aufgerufen
def getringbuffer():
    uptime = 0
    b["events"].open_perf_buffer(updateoccurences, page_cnt=256)
    while True:
        try:
            b.perf_buffer_poll(timeout=10 * 1000)
            uptime+=1
            time.sleep(1)
        except KeyboardInterrupt:
            res = {key: val for key, val in sorted(occurences.items(), key=lambda ele: ele[0])}
            res2 = {key: val for key, val in sorted(res.items(), key=lambda ele: ele[1], reverse=True)}
            # https: // www.geeksforgeeks.org / python - sort - a - dictionary /
            print("\n")
            for syscall, occurence in res2.items():
                print("syscall: %-*s Häufigkeit: %s" % (25, str(syscall), str(occurence)))
            print("\n" + ibinary + " got traced for " + str(uptime) + " seconds.")


            try:
                gesamt = sum(occurences.values())

                # Prozentuale Verteilung der Häufigkeiten berechnen
                prozentuale_verteilung = {k: v / gesamt * 100 for k, v in occurences.items()}

                # Ergebnis ausgeben
                print("Prozentuale Verteilung der Häufigkeiten:")
                sorted_verteilung = sorted(prozentuale_verteilung.items(), key=lambda x: x[1], reverse=True)
                for k, v in sorted_verteilung:
                    print(f"{k}: {v:.2f}%")
            except ZeroDivisionError:
                print(
                    "Die Gesamtsumme der Häufigkeiten ist 0, daher kann die prozentuale Verteilung nicht berechnet werden.")
                signal_handler(signal.SIGINT, signal_handler)


# Funktion für Signal Handler
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
