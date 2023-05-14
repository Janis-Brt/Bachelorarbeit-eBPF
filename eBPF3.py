from bcc import BPF
import os
import time
import signal
import sys

# Die Lokale Variable speichert den eBPF C-Code.
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/pid_namespace.h>

// Datenstruktur für den Ring Buffer
struct data_t {
    int syscallnumber;
    u32 pid;
    unsigned int inum;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
    data.pid = id >> 32;
    data.syscallnumber = 95;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgettimeofday(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 96;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetrlimit(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
    data.pid = id >> 32;
    data.syscallnumber = 132;
    events.perf_submit(ctx, &data, sizeof(data));
    int x = 0;
    return 0;
}
int sutime(struct pt_regs *ctx) {
    if(PT_REGS_RC(ctx) < 0){
        return 0;
    }
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.inum = inum_ring;
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


syscalls = []


sequencesswithtpid = {}
sequencesswithttid = {}


# Callback Funktion des Ring Buffers. Erhält die aus dem Kernelspace übergebene PID und Syscall-Nummer
# Danach wird geprüft, ob die PID im Array steht, welches alle PID's des zu tracenden Binaries enthält.
# Nun wird mittels der eindeutigen System Call Nummer überprüft, welcher System Call aufgerufen wurde,
# die Häufigkeit dieses System Calls wird nun im Dictionary, welches die Häufigkeiten speichert, erhöht
def updatesequence(cpu, data, size):
    data = b["events"].event(data)
    syscall_number = data.syscallnumber
    ringbufferpid = data.pid
    inum_ring = data.inum
    tid = 1 # dummy wert. Hier kommt noch die korrekte tid rein
    if str(inum_ring) == str(4026532483):
        # if int(ringbufferpid) != 1:
        if syscall_number == 0:
            syscalls.append("clone")
            add_to_pid_dict(ringbufferpid, "clone", tid)
        elif syscall_number == 1:
            syscalls.append("open")
            add_to_pid_dict(ringbufferpid, "open", tid)
        elif syscall_number == 2:
            syscalls.append("read")
            add_to_pid_dict(ringbufferpid, "read", tid)
        elif syscall_number == 3:
            syscalls.append("write")
            add_to_pid_dict(ringbufferpid, "write", tid)
        elif syscall_number == 4:
            syscalls.append("close")
            add_to_pid_dict(ringbufferpid, "close", tid)
        elif syscall_number == 5:
            syscalls.append("stat")
            add_to_pid_dict(ringbufferpid, "stat", tid)
        elif syscall_number == 6:
            syscalls.append("fstat")
            add_to_pid_dict(ringbufferpid, "fstat", tid)
        elif syscall_number == 7:
            syscalls.append("lstat")
            add_to_pid_dict(ringbufferpid, "lstat", tid)
        elif syscall_number == 8:
            syscalls.append("poll")
            add_to_pid_dict(ringbufferpid, "poll", tid)
        elif syscall_number == 9:
            syscalls.append("lseek")
            add_to_pid_dict(ringbufferpid, "lseek", tid)
        elif syscall_number == 10:
            syscalls.append("mmap")
            add_to_pid_dict(ringbufferpid, "mmap", tid)
        elif syscall_number == 11:
            syscalls.append("mprotext")
            add_to_pid_dict(ringbufferpid, "mprotext", tid)
        elif syscall_number == 12:
            syscalls.append("munmap")
            add_to_pid_dict(ringbufferpid, "munmap", tid)
        elif syscall_number == 13:
            syscalls.append("brk")
            add_to_pid_dict(ringbufferpid, "brk", tid)
        elif syscall_number == 14:
            syscalls.append("rt_sigaction")
            add_to_pid_dict(ringbufferpid, "rt_sigaction", tid)
        elif syscall_number == 15:
            syscalls.append("rt_sigprocmask")
            add_to_pid_dict(ringbufferpid, "rt_sigprocmask", tid)
        elif syscall_number == 16:
            syscalls.append("rt_sigreturn")
            add_to_pid_dict(ringbufferpid, "rt_sigreturn", tid)
        elif syscall_number == 17:
            syscalls.append("ioctl")
            add_to_pid_dict(ringbufferpid, "ioctl", tid)
        elif syscall_number == 18:
            syscalls.append("pread64")
            add_to_pid_dict(ringbufferpid, "pread64", tid)
        elif syscall_number == 19:
            syscalls.append("pwrite64")
            add_to_pid_dict(ringbufferpid, "pwrite64", tid)
        elif syscall_number == 20:
            syscalls.append("readv")
            add_to_pid_dict(ringbufferpid, "readv", tid)
        elif syscall_number == 21:
            syscalls.append("writev")
            add_to_pid_dict(ringbufferpid, "writev", tid)
        elif syscall_number == 22:
            syscalls.append("access")
            add_to_pid_dict(ringbufferpid, "access", tid)
        elif syscall_number == 23:
            syscalls.append("pipe")
            add_to_pid_dict(ringbufferpid, "pipe", tid)
        elif syscall_number == 24:
            syscalls.append("select")
            add_to_pid_dict(ringbufferpid, "select", tid)
        elif syscall_number == 25:
            syscalls.append("mremap")
            add_to_pid_dict(ringbufferpid, "mremap", tid)
        elif syscall_number == 26:
            syscalls.append("sched_yield")
            add_to_pid_dict(ringbufferpid, "sched_yield", tid)
        elif syscall_number == 27:
            syscalls.append("msync")
            add_to_pid_dict(ringbufferpid, "msync", tid)
        elif syscall_number == 28:
            syscalls.append("mincore")
            add_to_pid_dict(ringbufferpid, "mincore", tid)
        elif syscall_number == 29:
            syscalls.append("madvise")
            add_to_pid_dict(ringbufferpid, "madvise", tid)
        elif syscall_number == 30:
            syscalls.append("shmget")
            add_to_pid_dict(ringbufferpid, "shmget", tid)
        elif syscall_number == 31:
            syscalls.append("shmat")
            add_to_pid_dict(ringbufferpid, "shmat", tid)
        elif syscall_number == 32:
            syscalls.append("shmctl")
            add_to_pid_dict(ringbufferpid, "shmctl", tid)
        elif syscall_number == 33:
            syscalls.append("dup")
            add_to_pid_dict(ringbufferpid, "dup", tid)
        elif syscall_number == 34:
            syscalls.append("dup2")
            add_to_pid_dict(ringbufferpid, "dup2", tid)
        elif syscall_number == 35:
            syscalls.append("pause")
            add_to_pid_dict(ringbufferpid, "pause", tid)
        elif syscall_number == 36:
            syscalls.append("nanosleep")
            add_to_pid_dict(ringbufferpid, "nanosleep", tid)
        elif syscall_number == 37:
            syscalls.append("getitimer")
            add_to_pid_dict(ringbufferpid, "getitimer", tid)
        elif syscall_number == 38:
            syscalls.append("alarm")
            add_to_pid_dict(ringbufferpid, "alarm", tid)
        elif syscall_number == 39:
            syscalls.append("setitimer")
            add_to_pid_dict(ringbufferpid, "setitimer", tid)
        elif syscall_number == 40:
            syscalls.append("getpid")
            add_to_pid_dict(ringbufferpid, "getpid", tid)
        elif syscall_number == 41:
            syscalls.append("sendfile")
            add_to_pid_dict(ringbufferpid, "sendfile", tid)
        elif syscall_number == 42:
            syscalls.append("socket")
            add_to_pid_dict(ringbufferpid, "socket", tid)
        elif syscall_number == 43:
            syscalls.append("connect")
            add_to_pid_dict(ringbufferpid, "connect", tid)
        elif syscall_number == 44:
            syscalls.append("accept")
            add_to_pid_dict(ringbufferpid, "accept", tid)
        elif syscall_number == 45:
            syscalls.append("sendto")
            add_to_pid_dict(ringbufferpid, "sendto", tid)
        elif syscall_number == 46:
            syscalls.append("recvfrom")
            add_to_pid_dict(ringbufferpid, "recvfrom", tid)
        elif syscall_number == 47:
            syscalls.append("sendmsg")
            add_to_pid_dict(ringbufferpid, "sendmsg", tid)
        elif syscall_number == 48:
            syscalls.append("recvmsg")
            add_to_pid_dict(ringbufferpid, "recvmsg", tid)
        elif syscall_number == 49:
            syscalls.append("shutdown")
            add_to_pid_dict(ringbufferpid, "shutdown", tid)
        elif syscall_number == 50:
            syscalls.append("bind")
            add_to_pid_dict(ringbufferpid, "bind", tid)
        elif syscall_number == 51:
            syscalls.append("listen")
            add_to_pid_dict(ringbufferpid, "listen", tid)
        elif syscall_number == 52:
            syscalls.append("getsockname")
            add_to_pid_dict(ringbufferpid, "getsockname", tid)
        elif syscall_number == 53:
            syscalls.append("getpeername")
            add_to_pid_dict(ringbufferpid, "getpeername", tid)
        elif syscall_number == 54:
            syscalls.append("socketpair")
            add_to_pid_dict(ringbufferpid, "socketpair", tid)
        elif syscall_number == 55:
            syscalls.append("setsockopt")
            add_to_pid_dict(ringbufferpid, "setsockopt", tid)
        elif syscall_number == 56:
            syscalls.append("getsockopt")
            add_to_pid_dict(ringbufferpid, "getsockopt", tid)
        elif syscall_number == 57:
            syscalls.append("fork")
            add_to_pid_dict(ringbufferpid, "fork", tid)
        elif syscall_number == 58:
            syscalls.append("vfork")
            add_to_pid_dict(ringbufferpid, "vfork", tid)
        elif syscall_number == 59:
            syscalls.append("execve")
            add_to_pid_dict(ringbufferpid, "execve", tid)
        elif syscall_number == 60:
            syscalls.append("exit")
            add_to_pid_dict(ringbufferpid, "exit", tid)
        elif syscall_number == 61:
            syscalls.append("wait4")
            add_to_pid_dict(ringbufferpid, "wait4", tid)
        elif syscall_number == 62:
            syscalls.append("kill")
            add_to_pid_dict(ringbufferpid, "kill", tid)
        elif syscall_number == 63:
            syscalls.append("uname")
            add_to_pid_dict(ringbufferpid, "uname", tid)
        elif syscall_number == 64:
            syscalls.append("semget")
            add_to_pid_dict(ringbufferpid, "semget", tid)
        elif syscall_number == 65:
            syscalls.append("semop")
            add_to_pid_dict(ringbufferpid, "semop", tid)
        elif syscall_number == 66:
            syscalls.append("semctl")
            add_to_pid_dict(ringbufferpid, "semctl", tid)
        elif syscall_number == 67:
            syscalls.append("shmdt")
            add_to_pid_dict(ringbufferpid, "shmdt", tid)
        elif syscall_number == 68:
            syscalls.append("msgget")
            add_to_pid_dict(ringbufferpid, "msgget", tid)
        elif syscall_number == 69:
            syscalls.append("msgsnd")
            add_to_pid_dict(ringbufferpid, "msgsnd", tid)
        elif syscall_number == 70:
            syscalls.append("msgrcv")
            add_to_pid_dict(ringbufferpid, "msgrcv", tid)
        elif syscall_number == 71:
            syscalls.append("msgctl")
            add_to_pid_dict(ringbufferpid, "msgctl", tid)
        elif syscall_number == 72:
            syscalls.append("fcntl")
            add_to_pid_dict(ringbufferpid, "fcntl", tid)
        elif syscall_number == 73:
            syscalls.append("flock")
            add_to_pid_dict(ringbufferpid, "flock", tid)
        elif syscall_number == 74:
            syscalls.append("fsync")
            add_to_pid_dict(ringbufferpid, "fsync", tid)
        elif syscall_number == 75:
            syscalls.append("fdatasync")
            add_to_pid_dict(ringbufferpid, "fdatasync", tid)
        elif syscall_number == 76:
            syscalls.append("truncate")
            add_to_pid_dict(ringbufferpid, "truncate", tid)
        elif syscall_number == 77:
            syscalls.append("ftruncate")
            add_to_pid_dict(ringbufferpid, "ftruncate", tid)
        elif syscall_number == 78:
            syscalls.append("getdents")
            add_to_pid_dict(ringbufferpid, "getdents", tid)
        elif syscall_number == 79:
            syscalls.append("getcwd")
            add_to_pid_dict(ringbufferpid, "getcwd", tid)
        elif syscall_number == 80:
            syscalls.append("chdir")
            add_to_pid_dict(ringbufferpid, "chdir", tid)
        elif syscall_number == 81:
            syscalls.append("fchdir")
            add_to_pid_dict(ringbufferpid, "fchdir", tid)
        elif syscall_number == 82:
            syscalls.append("rename")
            add_to_pid_dict(ringbufferpid, "rename", tid)
        elif syscall_number == 83:
            syscalls.append("mkdir")
            add_to_pid_dict(ringbufferpid, "mkdir", tid)
        elif syscall_number == 84:
            syscalls.append("rmdir")
            add_to_pid_dict(ringbufferpid, "rmdir", tid)
        elif syscall_number == 85:
            syscalls.append("creat")
            add_to_pid_dict(ringbufferpid, "creat", tid)
        elif syscall_number == 86:
            syscalls.append("link")
            add_to_pid_dict(ringbufferpid, "link", tid)
        elif syscall_number == 87:
            syscalls.append("unlink")
            add_to_pid_dict(ringbufferpid, "unlink", tid)
        elif syscall_number == 88:
            syscalls.append("symlink")
            add_to_pid_dict(ringbufferpid, "symlink", tid)
        elif syscall_number == 89:
            syscalls.append("readlink")
            add_to_pid_dict(ringbufferpid, "readlink", tid)
        elif syscall_number == 90:
            syscalls.append("chmod")
            add_to_pid_dict(ringbufferpid, "chmod", tid)
        elif syscall_number == 91:
            syscalls.append("fchmod")
            add_to_pid_dict(ringbufferpid, "fchmod", tid)
        elif syscall_number == 92:
            syscalls.append("chown")
            add_to_pid_dict(ringbufferpid, "chown", tid)
        elif syscall_number == 93:
            syscalls.append("fchown")
            add_to_pid_dict(ringbufferpid, "fchown", tid)
        elif syscall_number == 94:
            syscalls.append("lchown")
            add_to_pid_dict(ringbufferpid, "lchown", tid)
        elif syscall_number == 95:
            syscalls.append("umask")
            add_to_pid_dict(ringbufferpid, "umask", tid)
        elif syscall_number == 96:
            syscalls.append("gettimeofday")
            add_to_pid_dict(ringbufferpid, "gettimeofday", tid)
        elif syscall_number == 97:
            syscalls.append("getrlimit")
            add_to_pid_dict(ringbufferpid, "getrlimit", tid)
        elif syscall_number == 98:
            syscalls.append("getrusage")
            add_to_pid_dict(ringbufferpid, "getrusage", tid)
        elif syscall_number == 99:
            syscalls.append("sysinfo")
            add_to_pid_dict(ringbufferpid, "sysinfo", tid)
        elif syscall_number == 100:
            syscalls.append("times")
            add_to_pid_dict(ringbufferpid, "times", tid)
        elif syscall_number == 102:
            occurences['ptrace'] = occurences['ptrace'] + 1
            syscalls.append("ptrace")
            add_to_pid_dict(ringbufferpid, "ptrace", tid)
            # print("Update für folgenden System Call ptrace. Neue Häufigkeit: " + str(occurences['ptrace']))
        elif syscall_number == 103:
            occurences['getuid'] = occurences['getuid'] + 1
            syscalls.append("getuid")
            add_to_pid_dict(ringbufferpid, "getuid", tid)
            # print("Update für folgenden System Call getuid. Neue Häufigkeit: " + str(occurences['getuid']))
        elif syscall_number == 104:
            occurences['syslog'] = occurences['syslog'] + 1
            syscalls.append("syslog")
            add_to_pid_dict(ringbufferpid, "syslog", tid)
            # print("Update für folgenden System Call syslog. Neue Häufigkeit: " + str(occurences['syslog']))
        elif syscall_number == 105:
            occurences['getgid'] = occurences['getgid'] + 1
            syscalls.append("getgid")
            add_to_pid_dict(ringbufferpid, "getgid", tid)
            # print("Update für folgenden System Call getgid. Neue Häufigkeit: " + str(occurences['getgid']))
        elif syscall_number == 106:
            occurences['setuid'] = occurences['setuid'] + 1
            syscalls.append("setuid")
            add_to_pid_dict(ringbufferpid, "setuid", tid)
            # print("Update für folgenden System Call setuid. Neue Häufigkeit: " + str(occurences['setuid']))
        elif syscall_number == 107:
            occurences['setgid'] = occurences['setgid'] + 1
            syscalls.append("setgid")
            add_to_pid_dict(ringbufferpid, "setgid", tid)
            # print("Update für folgenden System Call setgid. Neue Häufigkeit: " + str(occurences['setgid']))
        elif syscall_number == 108:
            occurences['geteuid'] = occurences['geteuid'] + 1
            syscalls.append("geteuid")
            add_to_pid_dict(ringbufferpid, "geteuid", tid)
            # print("Update für folgenden System Call geteuid. Neue Häufigkeit: " + str(occurences['geteuid']))
        elif syscall_number == 109:
            occurences['getegid'] = occurences['getegid'] + 1
            syscalls.append("getegid")
            add_to_pid_dict(ringbufferpid, "getegid", tid)
            # print("Update für folgenden System Call getegid. Neue Häufigkeit: " + str(occurences['getegid']))
        elif syscall_number == 110:
            occurences['setpgid'] = occurences['setpgid'] + 1
            syscalls.append("setpgid")
            add_to_pid_dict(ringbufferpid, "setpgid", tid)
            # print("Update für folgenden System Call setpgid. Neue Häufigkeit: " + str(occurences['setpgid']))
        elif syscall_number == 111:
            occurences['getppid'] = occurences['getppid'] + 1
            syscalls.append("getppid")
            add_to_pid_dict(ringbufferpid, "getppid", tid)
            # print("Update für folgenden System Call getppid. Neue Häufigkeit: " + str(occurences['getppid']))
        elif syscall_number == 112:
            occurences['getpgrp'] = occurences['getpgrp'] + 1
            syscalls.append("getpgrp")
            add_to_pid_dict(ringbufferpid, "getpgrp", tid)
            # print("Update für folgenden System Call getpgrp. Neue Häufigkeit: " + str(occurences['getpgrp']))
        elif syscall_number == 113:
            occurences['setsid'] = occurences['setsid'] + 1
            syscalls.append("setsid")
            add_to_pid_dict(ringbufferpid, "setsid", tid)
            # print("Update für folgenden System Call setsid. Neue Häufigkeit: " + str(occurences['setsid']))
        elif syscall_number == 114:
            occurences['setreuid'] = occurences['setreuid'] + 1
            syscalls.append("setreuid")
            add_to_pid_dict(ringbufferpid, "setreuid", tid)
            # print("Update für folgenden System Call setreuid. Neue Häufigkeit: " + str(occurences['setreuid']))
        elif syscall_number == 115:
            occurences['setregid'] = occurences['setregid'] + 1
            syscalls.append("setregid")
            add_to_pid_dict(ringbufferpid, "setregid", tid)
            # print("Update für folgenden System Call setregid. Neue Häufigkeit: " + str(occurences['setregid']))
        elif syscall_number == 116:
            occurences['getgroups'] = occurences['getgroups'] + 1
            syscalls.append("getgroups")
            add_to_pid_dict(ringbufferpid, "getgroups", tid)
            # print("Update für folgenden System Call getgroups. Neue Häufigkeit: " + str(occurences['getgroups']))
        elif syscall_number == 117:
            occurences['setgroups'] = occurences['setgroups'] + 1
            syscalls.append("setgroups")
            add_to_pid_dict(ringbufferpid, "setgroups", tid)
            # print("Update für folgenden System Call setgroups. Neue Häufigkeit: " + str(occurences['setgroups']))
        elif syscall_number == 118:
            occurences['setresuid'] = occurences['setresuid'] + 1
            syscalls.append("setresuid")
            add_to_pid_dict(ringbufferpid, "setresuid", tid)
            # print("Update für folgenden System Call setresuid. Neue Häufigkeit: " + str(occurences['setresuid']))
        elif syscall_number == 119:
            occurences['getresuid'] = occurences['getresuid'] + 1
            syscalls.append("getresuid")
            add_to_pid_dict(ringbufferpid, "getresuid", tid)
            # print("Update für folgenden System Call getresuid. Neue Häufigkeit: " + str(occurences['getresuid']))
        elif syscall_number == 120:
            occurences['setresgid'] = occurences['setresgid'] + 1
            syscalls.append("setresgid")
            add_to_pid_dict(ringbufferpid, "setresgid", tid)
            # print("Update für folgenden System Call setresgid. Neue Häufigkeit: " + str(occurences['setresgid']))
        elif syscall_number == 121:
            occurences['getresgid'] = occurences['getresgid'] + 1
            syscalls.append("getresgid")
            add_to_pid_dict(ringbufferpid, "getresgid", tid)
            # print("Update für folgenden System Call getresgid. Neue Häufigkeit: " + str(occurences['getresgid']))
        elif syscall_number == 122:
            occurences['getpgid'] = occurences['getpgid'] + 1
            syscalls.append("getpgid")
            add_to_pid_dict(ringbufferpid, "getpgid", tid)
            # print("Update für folgenden System Call getpgid. Neue Häufigkeit: " + str(occurences['getpgid']))
        elif syscall_number == 123:
            occurences['setfsuid'] = occurences['setfsuid'] + 1
            syscalls.append("setfsuid")
            add_to_pid_dict(ringbufferpid, "setfsuid", tid)
            # print("Update für folgenden System Call setfsuid. Neue Häufigkeit: " + str(occurences['setfsuid']))
        elif syscall_number == 124:
            occurences['setfsgid'] = occurences['setfsgid'] + 1
            syscalls.append("setfsgid")
            add_to_pid_dict(ringbufferpid, "setfsgid", tid)
            # print("Update für folgenden System Call setfsgid. Neue Häufigkeit: " + str(occurences['setfsgid']))
        elif syscall_number == 125:
            occurences['getsid'] = occurences['getsid'] + 1
            syscalls.append("getsid")
            add_to_pid_dict(ringbufferpid, "getsid", tid)
            # print("Update für folgenden System Call getsid. Neue Häufigkeit: " + str(occurences['getsid']))
        elif syscall_number == 126:
            occurences['capget'] = occurences['capget'] + 1
            syscalls.append("capget")
            add_to_pid_dict(ringbufferpid, "capget", tid)
            # print("Update für folgenden System Call capget. Neue Häufigkeit: " + str(occurences['capget']))
        elif syscall_number == 127:
            occurences['capset'] = occurences['capset'] + 1
            syscalls.append("capset")
            add_to_pid_dict(ringbufferpid, "capset", tid)
            # print("Update für folgenden System Call capset. Neue Häufigkeit: " + str(occurences['capset']))
        elif syscall_number == 128:
            occurences['rt_sigpending'] = occurences['rt_sigpending'] + 1
            syscalls.append("rt_sigpending")
            add_to_pid_dict(ringbufferpid, "rt_sigpending", tid)
            # print("Update für folgenden System Call rt_sigpending. Neue Häufigkeit: " + str(
            #    occurences['rt_sigpending']))
        elif syscall_number == 129:
            occurences['rt_sigtimedwait'] = occurences['rt_sigtimedwait'] + 1
            syscalls.append("rt_sigtimedwait")
            add_to_pid_dict(ringbufferpid, "rt_sigtimedwait", tid)
            # print("Update für folgenden System Call rt_sigtimedwait. Neue Häufigkeit: " + str(
            #    occurences['rt_sigtimedwait']))
        elif syscall_number == 130:
            occurences['rt_sigqueueinfo'] = occurences['rt_sigqueueinfo'] + 1
            syscalls.append("rt_sigqueueinfo")
            add_to_pid_dict(ringbufferpid, "rt_sigqueueinfo", tid)
            # print("Update für folgenden System Call rt_sigqueueinfo. Neue Häufigkeit: " + str(
            #    occurences['rt_sigqueueinfo']))
        elif syscall_number == 131:
            occurences['rt_sigsuspend'] = occurences['rt_sigsuspend'] + 1
            syscalls.append("rt_sigsuspend")
            add_to_pid_dict(ringbufferpid, "rt_sigsuspend", tid)
            # print("Update für folgenden System Call rt_sigsuspend. Neue Häufigkeit: " + str(
            #    occurences['rt_sigsuspend']))
        elif syscall_number == 132:
            occurences['sigaltstack'] = occurences['sigaltstack'] + 1
            syscalls.append("sigaltstack")
            add_to_pid_dict(ringbufferpid, "sigaltstack", tid)
            # print(
            #     "Update für folgenden System Call: sigaltstack. Neue Häufigkeit: " + str(occurences['sigaltstack']))
        elif syscall_number == 133:
            occurences['utime'] = occurences['utime'] + 1
            syscalls.append("utime")
            add_to_pid_dict(ringbufferpid, "utime", tid)
            # print("Update für folgenden System Call utime. Neue Häufigkeit: " + str(occurences['utime']))
        elif syscall_number == 134:
            occurences['mknod'] = occurences['mknod'] + 1
            syscalls.append("mknod")
            add_to_pid_dict(ringbufferpid, "mknod", tid)
            # print("Update für folgenden System Call mknod. Neue Häufigkeit: " + str(occurences['mknod']))
        elif syscall_number == 135:
            occurences['uselib'] = occurences['uselib'] + 1
            syscalls.append("uselib")
            add_to_pid_dict(ringbufferpid, "uselib", tid)
            # print("Update für folgenden System Call uselib. Neue Häufigkeit: " + str(occurences['uselib']))
        elif syscall_number == 136:
            occurences['personality'] = occurences['personality'] + 1
            syscalls.append("personality")
            add_to_pid_dict(ringbufferpid, "personality", tid)
            # print(
            #     "Update für folgenden System Call: personality. Neue Häufigkeit: " + str(occurences['personality']))
        elif syscall_number == 137:
            occurences['ustat'] = occurences['ustat'] + 1
            syscalls.append("ustat")
            add_to_pid_dict(ringbufferpid, "ustat", tid)
            # print("Update für folgenden System Call ustat. Neue Häufigkeit: " + str(occurences['ustat']))
        elif syscall_number == 138:
            occurences['statfs'] = occurences['statfs'] + 1
            syscalls.append("statfs")
            add_to_pid_dict(ringbufferpid, "statfs", tid)
            # print("Update für folgenden System Call statfs. Neue Häufigkeit: " + str(occurences['statfs']))
        elif syscall_number == 139:
            occurences['fstatfs'] = occurences['fstatfs'] + 1
            syscalls.append("fstatfs")
            add_to_pid_dict(ringbufferpid, "fstatfs", tid)
            # print("Update für folgenden System Call fstatfs. Neue Häufigkeit: " + str(occurences['fstatfs']))
        elif syscall_number == 140:
            occurences['sysfs'] = occurences['sysfs'] + 1
            syscalls.append("sysfs")
            add_to_pid_dict(ringbufferpid, "sysfs", tid)
            # print("Update für folgenden System Call sysfs. Neue Häufigkeit: " + str(occurences['sysfs']))
        elif syscall_number == 141:
            occurences['getpriority'] = occurences['getpriority'] + 1
            syscalls.append("getpriority")
            add_to_pid_dict(ringbufferpid, "getpriority", tid)
            # print(
            #     "Update für folgenden System Call: getpriority. Neue Häufigkeit: " + str(occurences['getpriority']))
        elif syscall_number == 142:
            occurences['setpriority'] = occurences['setpriority'] + 1
            syscalls.append("setpriority")
            add_to_pid_dict(ringbufferpid, "setpriority", tid)
            # print(
            #     "Update für folgenden System Call: setpriority. Neue Häufigkeit: " + str(occurences['setpriority']))
        elif syscall_number == 143:
            occurences['sched_setparam'] = occurences['sched_setparam'] + 1
            syscalls.append("sched_setparam")
            add_to_pid_dict(ringbufferpid, "sched_setparam", tid)
            # print("Update für folgenden System Call sched_setparam. Neue Häufigkeit: " + str(
            #    occurences['sched_setparam']))
        elif syscall_number == 144:
            occurences['sched_getparam'] = occurences['sched_getparam'] + 1
            syscalls.append("sched_getparam")
            add_to_pid_dict(ringbufferpid, "sched_getparam", tid)
            # print("Update für folgenden System Call sched_getparam. Neue Häufigkeit: " + str(
            #    occurences['sched_getparam']))
        elif syscall_number == 145:
            occurences['sched_setscheduler'] = occurences['sched_setscheduler'] + 1
            syscalls.append("sched_setscheduler")
            add_to_pid_dict(ringbufferpid, "sched_setscheduler", tid)
            # print("Update für folgenden System Call sched_setscheduler. Neue Häufigkeit: " + str(
            #    occurences['sched_setscheduler']))
        elif syscall_number == 146:
            occurences['sched_getscheduler'] = occurences['sched_getscheduler'] + 1
            syscalls.append("sched_getscheduler")
            add_to_pid_dict(ringbufferpid, "sched_getscheduler", tid)
            # print("Update für folgenden System Call sched_getscheduler. Neue Häufigkeit: " + str(
            #    occurences['sched_getscheduler']))
        elif syscall_number == 147:
            occurences['sched_get_priority_max'] = occurences['sched_get_priority_max'] + 1
            syscalls.append("sched_get_priority_max")
            add_to_pid_dict(ringbufferpid, "sched_get_priority_max", tid)
            # print("Update für folgenden System Call sched_get_priority_max. Neue Häufigkeit: " + str(
            #    occurences['sched_get_priority_max']))
        elif syscall_number == 148:
            occurences['sched_get_priority_min'] = occurences['sched_get_priority_min'] + 1
            syscalls.append("sched_get_priority_min")
            add_to_pid_dict(ringbufferpid, "sched_get_priority_min", tid)
            # print("Update für folgenden System Call sched_get_priority_min. Neue Häufigkeit: " + str(
            #    occurences['sched_get_priority_min']))
        elif syscall_number == 149:
            occurences['sched_rr_get_interval'] = occurences['sched_rr_get_interval'] + 1
            syscalls.append("sched_rr_get_interval")
            add_to_pid_dict(ringbufferpid, "sched_rr_get_interval", tid)
            # print("Update für folgenden System Call sched_rr_get_interval. Neue Häufigkeit: " + str(
            #    occurences['sched_rr_get_interval']))
        elif syscall_number == 150:
            occurences['mlock'] = occurences['mlock'] + 1
            syscalls.append("mlock")
            add_to_pid_dict(ringbufferpid, "mlock", tid)
            # print("Update für folgenden System Call mlock. Neue Häufigkeit: " + str(occurences['mlock']))
        elif syscall_number == 151:
            occurences['munlock'] = occurences['munlock'] + 1
            syscalls.append("munlock")
            add_to_pid_dict(ringbufferpid, "munlock", tid)
            # print("Update für folgenden System Call munlock. Neue Häufigkeit: " + str(occurences['munlock']))
        elif syscall_number == 152:
            occurences['mlockall'] = occurences['mlockall'] + 1
            syscalls.append("mlockall")
            add_to_pid_dict(ringbufferpid, "mlockall", tid)
            # print("Update für folgenden System Call mlockall. Neue Häufigkeit: " + str(occurences['mlockall']))
        elif syscall_number == 153:
            occurences['munlockall'] = occurences['munlockall'] + 1
            syscalls.append("munlockall")
            add_to_pid_dict(ringbufferpid, "munlockall", tid)
            # print("Update für folgenden System Call munlockall. Neue Häufigkeit: " + str(occurences['munlockall']))
        elif syscall_number == 154:
            occurences['vhangup'] = occurences['vhangup'] + 1
            syscalls.append("vhangup")
            add_to_pid_dict(ringbufferpid, "vhangup", tid)
            # print("Update für folgenden System Call vhangup. Neue Häufigkeit: " + str(occurences['vhangup']))
        elif syscall_number == 155:
            occurences['modify_ldt'] = occurences['modify_ldt'] + 1
            syscalls.append("modify_ldt")
            add_to_pid_dict(ringbufferpid, "modify_ldt", tid)
            # print("Update für folgenden System Call modify_ldt. Neue Häufigkeit: " + str(occurences['modify_ldt']))
        elif syscall_number == 156:
            occurences['pivot_root'] = occurences['pivot_root'] + 1
            syscalls.append("pivot_root")
            add_to_pid_dict(ringbufferpid, "pivot_root", tid)
            # print("Update für folgenden System Call pivot_root. Neue Häufigkeit: " + str(occurences['pivot_root']))
        elif syscall_number == 157:
            occurences['sysctl'] = occurences['sysctl'] + 1
            syscalls.append("sysctl")
            add_to_pid_dict(ringbufferpid, "sysctl", tid)
            # print("Update für folgenden System Call sysctl. Neue Häufigkeit: " + str(occurences['sysctl']))
        elif syscall_number == 158:
            occurences['prctl'] = occurences['prctl'] + 1
            syscalls.append("prctl")
            add_to_pid_dict(ringbufferpid, "prctl", tid)
            # print("Update für folgenden System Call prctl. Neue Häufigkeit: " + str(occurences['prctl']))
        elif syscall_number == 159:
            occurences['arch_prctl'] = occurences['arch_prctl'] + 1
            syscalls.append("arch_prctl")
            add_to_pid_dict(ringbufferpid, "arch_prctl", tid)
            # print("Update für folgenden System Call arch_prctl. Neue Häufigkeit: " + str(occurences['arch_prctl']))
        elif syscall_number == 160:
            occurences['adjtimex'] = occurences['adjtimex'] + 1
            syscalls.append("adjtimex")
            add_to_pid_dict(ringbufferpid, "adjtimex", tid)
            # print("Update für folgenden System Call adjtimex. Neue Häufigkeit: " + str(occurences['adjtimex']))
        elif syscall_number == 161:
            occurences['setrlimit'] = occurences['setrlimit'] + 1
            syscalls.append("setrlimit")
            add_to_pid_dict(ringbufferpid, "setrlimit", tid)
            # print("Update für folgenden System Call setrlimit. Neue Häufigkeit: " + str(occurences['setrlimit']))
        elif syscall_number == 162:
            occurences['chroot'] = occurences['chroot'] + 1
            syscalls.append("chroot")
            add_to_pid_dict(ringbufferpid, "chroot", tid)
            # print("Update für folgenden System Call chroot. Neue Häufigkeit: " + str(occurences['chroot']))
        elif syscall_number == 163:
            occurences['sync'] = occurences['sync'] + 1
            syscalls.append("sync")
            add_to_pid_dict(ringbufferpid, "sync", tid)
            # print("Update für folgenden System Call sync. Neue Häufigkeit: " + str(occurences['sync']))
        elif syscall_number == 164:
            occurences['acct'] = occurences['acct'] + 1
            syscalls.append("acct")
            add_to_pid_dict(ringbufferpid, "acct", tid)
            # print("Update für folgenden System Call acct. Neue Häufigkeit: " + str(occurences['acct']))
        elif syscall_number == 165:
            occurences['settimeofday'] = occurences['settimeofday'] + 1
            syscalls.append("settimeofday")
            add_to_pid_dict(ringbufferpid, "settimeofday", tid)
            # print("Update für folgenden System Call settimeofday. Neue Häufigkeit: " + str(
            #    occurences['settimeofday']))
        elif syscall_number == 166:
            occurences['mount'] = occurences['mount'] + 1
            syscalls.append("mount")
            add_to_pid_dict(ringbufferpid, "mount", tid)
            # print("Update für folgenden System Call mount. Neue Häufigkeit: " + str(occurences['mount']))
        elif syscall_number == 167:
            occurences['umount2'] = occurences['umount2'] + 1
            syscalls.append("umount2")
            add_to_pid_dict(ringbufferpid, "umount2", tid)
            # print("Update für folgenden System Call umount2. Neue Häufigkeit: " + str(occurences['umount2']))
        elif syscall_number == 168:
            occurences['swapon'] = occurences['swapon'] + 1
            syscalls.append("swapon")
            add_to_pid_dict(ringbufferpid, "swapon", tid)
            # print("Update für folgenden System Call swapon. Neue Häufigkeit: " + str(occurences['swapon']))
        elif syscall_number == 169:
            occurences['swapoff'] = occurences['swapoff'] + 1
            syscalls.append("swapoff")
            add_to_pid_dict(ringbufferpid, "swapoff", tid)
            # print("Update für folgenden System Call swapoff. Neue Häufigkeit: " + str(occurences['swapoff']))
        elif syscall_number == 170:
            occurences['reboot'] = occurences['reboot'] + 1
            syscalls.append("reboot")
            add_to_pid_dict(ringbufferpid, "reboot", tid)
            # print("Update für folgenden System Call reboot. Neue Häufigkeit: " + str(occurences['reboot']))
        elif syscall_number == 171:
            occurences['sethostname'] = occurences['sethostname'] + 1
            syscalls.append("sethostname")
            add_to_pid_dict(ringbufferpid, "sethostname", tid)
            # print(
            #     "Update für folgenden System Call: sethostname. Neue Häufigkeit: " + str(occurences['sethostname']))
        elif syscall_number == 172:
            occurences['setdomainname'] = occurences['setdomainname'] + 1
            syscalls.append("setdomainname")
            add_to_pid_dict(ringbufferpid, "setdomainname", tid)
            # print("Update für folgenden System Call setdomainname. Neue Häufigkeit: " + str(
            #    occurences['setdomainname']))
        elif syscall_number == 173:
            occurences['iopl'] = occurences['iopl'] + 1
            syscalls.append("iopl")
            add_to_pid_dict(ringbufferpid, "iopl", tid)
            # print("Update für folgenden System Call iopl. Neue Häufigkeit: " + str(occurences['iopl']))
        elif syscall_number == 174:
            occurences['ioperm'] = occurences['ioperm'] + 1
            syscalls.append("ioperm")
            add_to_pid_dict(ringbufferpid, "ioperm", tid)
            # print("Update für folgenden System Call ioperm. Neue Häufigkeit: " + str(occurences['ioperm']))
        elif syscall_number == 175:
            occurences['create_module'] = occurences['create_module'] + 1
            syscalls.append("create_module")
            add_to_pid_dict(ringbufferpid, "create_module", tid)
            # print("Update für folgenden System Call create_module. Neue Häufigkeit: " + str(
            #    occurences['create_module']))
        elif syscall_number == 176:
            occurences['init_module'] = occurences['init_module'] + 1
            syscalls.append("init_module")
            add_to_pid_dict(ringbufferpid, "init_module", tid)
            # print(
            #     "Update für folgenden System Call: init_module. Neue Häufigkeit: " + str(occurences['init_module']))
        elif syscall_number == 177:
            occurences['delete_module'] = occurences['delete_module'] + 1
            syscalls.append("delete_module")
            add_to_pid_dict(ringbufferpid, "delete_module", tid)
            # print("Update für folgenden System Call delete_module. Neue Häufigkeit: " + str(
            #    occurences['delete_module']))
        elif syscall_number == 178:
            occurences['get_kernel_syms'] = occurences['get_kernel_syms'] + 1
            syscalls.append("get_kernel_syms")
            add_to_pid_dict(ringbufferpid, "get_kernel_syms", tid)
            # print("Update für folgenden System Call get_kernel_syms. Neue Häufigkeit: " + str(
            #    occurences['get_kernel_syms']))
        elif syscall_number == 179:
            occurences['query_module'] = occurences['query_module'] + 1
            syscalls.append("query_module")
            add_to_pid_dict(ringbufferpid, "query_module", tid)
            # print("Update für folgenden System Call query_module. Neue Häufigkeit: " + str(
            #    occurences['query_module']))
        elif syscall_number == 180:
            occurences['quotactl'] = occurences['quotactl'] + 1
            syscalls.append("quotactl")
            add_to_pid_dict(ringbufferpid, "quotactl", tid)
            # print("Update für folgenden System Call quotactl. Neue Häufigkeit: " + str(occurences['quotactl']))
        elif syscall_number == 181:
            occurences['nfsservctl'] = occurences['nfsservctl'] + 1
            syscalls.append("nfsservctl")
            add_to_pid_dict(ringbufferpid, "nfsservctl", tid)
            # print("Update für folgenden System Call nfsservctl. Neue Häufigkeit: " + str(occurences['nfsservctl']))
        elif syscall_number == 182:
            occurences['getpmsg'] = occurences['getpmsg'] + 1
            syscalls.append("getpmsg")
            add_to_pid_dict(ringbufferpid, "getpmsg", tid)
            # print("Update für folgenden System Call getpmsg. Neue Häufigkeit: " + str(occurences['getpmsg']))
        elif syscall_number == 183:
            occurences['putpmsg'] = occurences['putpmsg'] + 1
            syscalls.append("putpmsg")
            add_to_pid_dict(ringbufferpid, "putpmsg", tid)
            # print("Update für folgenden System Call putpmsg. Neue Häufigkeit: " + str(occurences['putpmsg']))
        elif syscall_number == 184:
            occurences['afs_syscall'] = occurences['afs_syscall'] + 1
            syscalls.append("afs_syscall")
            add_to_pid_dict(ringbufferpid, "afs_syscall", tid)# print(
            #     "Update für folgenden System Call: afs_syscall. Neue Häufigkeit: " + str(occurences['afs_syscall']))
        elif syscall_number == 185:
            occurences['tuxcall'] = occurences['tuxcall'] + 1
            syscalls.append("tuxcall")
            add_to_pid_dict(ringbufferpid, "tuxcall", tid)
            # print("Update für folgenden System Call tuxcall. Neue Häufigkeit: " + str(occurences['tuxcall']))
        elif syscall_number == 186:
            occurences['security'] = occurences['security'] + 1
            syscalls.append("security")
            add_to_pid_dict(ringbufferpid, "security", tid)
            # print("Update für folgenden System Call security. Neue Häufigkeit: " + str(occurences['security']))
        elif syscall_number == 187:
            occurences['gettid'] = occurences['gettid'] + 1
            syscalls.append("gettid")
            add_to_pid_dict(ringbufferpid, "gettid", tid)
            # print("Update für folgenden System Call gettid. Neue Häufigkeit: " + str(occurences['gettid']))
        elif syscall_number == 188:
            occurences['readahead'] = occurences['readahead'] + 1
            syscalls.append("readahead")
            add_to_pid_dict(ringbufferpid, "readahead", tid)
            # print("Update für folgenden System Call readahead. Neue Häufigkeit: " + str(occurences['readahead']))
        elif syscall_number == 189:
            occurences['setxattr'] = occurences['setxattr'] + 1
            syscalls.append("setxattr")
            add_to_pid_dict(ringbufferpid, "setxattr", tid)
            # print("Update für folgenden System Call setxattr. Neue Häufigkeit: " + str(occurences['setxattr']))
        elif syscall_number == 190:
            occurences['lsetxattr'] = occurences['lsetxattr'] + 1
            syscalls.append("lsetxattr")
            add_to_pid_dict(ringbufferpid, "lsetxattr", tid)
            # print("Update für folgenden System Call lsetxattr. Neue Häufigkeit: " + str(occurences['lsetxattr']))
        elif syscall_number == 191:
            occurences['fsetxattr'] = occurences['fsetxattr'] + 1
            syscalls.append("fsetxattr")
            add_to_pid_dict(ringbufferpid, "fsetxattr", tid)
            # print("Update für folgenden System Call fsetxattr. Neue Häufigkeit: " + str(occurences['fsetxattr']))
        elif syscall_number == 192:
            occurences['getxattr'] = occurences['getxattr'] + 1
            syscalls.append("getxattr")
            add_to_pid_dict(ringbufferpid, "getxattr", tid)
            # print("Update für folgenden System Call getxattr. Neue Häufigkeit: " + str(occurences['getxattr']))
        # elif syscall == 192:
        #     occurences['lgetxattr'] = occurences['lgetxattr'] + 1
        #     # print("Update für folgenden System Call lgetxattr. Neue Häufigkeit: " + str(occurences['lgetxattr']))
        elif syscall_number == 193:
            occurences['fgetxattr'] = occurences['fgetxattr'] + 1
            syscalls.append("fgetxattr")
            add_to_pid_dict(ringbufferpid, "fgetxattr", tid)
            # print("Update für folgenden System Call fgetxattr. Neue Häufigkeit: " + str(occurences['fgetxattr']))
        elif syscall_number == 194:
            occurences['listxattr'] = occurences['listxattr'] + 1
            syscalls.append("listxattr")
            add_to_pid_dict(ringbufferpid, "listxattr", tid)
            # print("Update für folgenden System Call listxattr. Neue Häufigkeit: " + str(occurences['listxattr']))
        elif syscall_number == 195:
            occurences['llistxattr'] = occurences['llistxattr'] + 1
            syscalls.append("llistxattr")
            add_to_pid_dict(ringbufferpid, "llistxattr", tid)
            # print("Update für folgenden System Call llistxattr. Neue Häufigkeit: " + str(occurences['llistxattr']))
        elif syscall_number == 196:
            occurences['flistxattr'] = occurences['flistxattr'] + 1
            syscalls.append("flistxattr")
            add_to_pid_dict(ringbufferpid, "llistxattr", tid)
            # print("Update für folgenden System Call flistxattr. Neue Häufigkeit: " + str(occurences['flistxattr']))
        elif syscall_number == 197:
            occurences['removexattr'] = occurences['removexattr'] + 1
            syscalls.append("removexattr")
            add_to_pid_dict(ringbufferpid, "removexattr", tid)
            # print(
            #     "Update für folgenden System Call: removexattr. Neue Häufigkeit: " + str(occurences['removexattr']))
        elif syscall_number == 198:
            occurences['lremovexattr'] = occurences['lremovexattr'] + 1
            syscalls.append("lremovexattr")
            add_to_pid_dict(ringbufferpid, "lremovexattr", tid)
            # print("Update für folgenden System Call lremovexattr. Neue Häufigkeit: " + str(
            #    occurences['lremovexattr']))
        elif syscall_number == 199:
            occurences['fremovexattr'] = occurences['fremovexattr'] + 1
            syscalls.append("fremovexattr")
            add_to_pid_dict(ringbufferpid, "fremovexattr", tid)
            # print("Update für folgenden System Call fremovexattr. Neue Häufigkeit: " + str(
            #    occurences['fremovexattr']))
        elif syscall_number == 200:
            occurences['tkill'] = occurences['tkill'] + 1
            syscalls.append("tkill")
            add_to_pid_dict(ringbufferpid, "tkill", tid)
            # print("Update für folgenden System Call tkill. Neue Häufigkeit: " + str(occurences['tkill']))
        elif syscall_number == 201:
            occurences['time'] = occurences['time'] + 1
            syscalls.append("time")
            add_to_pid_dict(ringbufferpid, "time", tid)
            # print("Update für folgenden System Call time. Neue Häufigkeit: " + str(occurences['time']))
        elif syscall_number == 202:
            occurences['futex'] = occurences['futex'] + 1
            syscalls.append("futex")
            add_to_pid_dict(ringbufferpid, "futex", tid)
            # print("Update für folgenden System Call futex. Neue Häufigkeit: " + str(occurences['futex']))
        elif syscall_number == 203:
            occurences['sched_setaffinity'] = occurences['sched_setaffinity'] + 1
            syscalls.append("sched_setaffinity")
            add_to_pid_dict(ringbufferpid, "sched_setaffinity", tid)
            # print("Update für folgenden System Call sched_setaffinity. Neue Häufigkeit: " + str(
            #    occurences['sched_setaffinity']))
        elif syscall_number == 204:
            occurences['sched_getaffinity'] = occurences['sched_getaffinity'] + 1
            syscalls.append("sched_getaffinity")
            add_to_pid_dict(ringbufferpid, "sched_getaffinity", tid)
            # print("Update für folgenden System Call sched_getaffinity. Neue Häufigkeit: " + str(
            #    occurences['sched_getaffinity']))
        elif syscall_number == 205:
            occurences['set_thread_area'] = occurences['set_thread_area'] + 1
            syscalls.append("set_thread_area")
            add_to_pid_dict(ringbufferpid, "set_thread_area", tid)
            # print("Update für folgenden System Call set_thread_area. Neue Häufigkeit: " + str(
            #    occurences['set_thread_area']))
        elif syscall_number == 206:
            occurences['io_setup'] = occurences['io_setup'] + 1
            syscalls.append("io_setup")
            add_to_pid_dict(ringbufferpid, "io_setup", tid)
            # print("Update für folgenden System Call io_setup. Neue Häufigkeit: " + str(occurences['io_setup']))
        elif syscall_number == 207:
            occurences['io_destroy'] = occurences['io_destroy'] + 1
            syscalls.append("io_destroy")
            add_to_pid_dict(ringbufferpid, "io_destroy", tid)
            # print("Update für folgenden System Call io_destroy. Neue Häufigkeit: " + str(occurences['io_destroy']))
        elif syscall_number == 208:
            occurences['io_getevents'] = occurences['io_getevents'] + 1
            syscalls.append("io_getevents")
            add_to_pid_dict(ringbufferpid, "io_getevents", tid)
            # print("Update für folgenden System Call io_getevents. Neue Häufigkeit: " + str(
            #    occurences['io_getevents']))
        elif syscall_number == 209:
            occurences['io_submit'] = occurences['io_submit'] + 1
            syscalls.append("io_submit")
            add_to_pid_dict(ringbufferpid, "io_submit", tid)
            # print("Update für folgenden System Call io_submit. Neue Häufigkeit: " + str(occurences['io_submit']))
        elif syscall_number == 210:
            occurences['io_cancel'] = occurences['io_cancel'] + 1
            syscalls.append("io_cancel")
            add_to_pid_dict(ringbufferpid, "io_cancel", tid)
            # print("Update für folgenden System Call io_cancel. Neue Häufigkeit: " + str(occurences['io_cancel']))
        elif syscall_number == 211:
            occurences['get_thread_area'] = occurences['get_thread_area'] + 1
            syscalls.append("get_thread_area")
            add_to_pid_dict(ringbufferpid, "get_thread_area", tid)
            # print("Update für folgenden System Call get_thread_area. Neue Häufigkeit: " + str(
            #    occurences['get_thread_area']))
        elif syscall_number == 212:
            occurences['lookup_dcookie'] = occurences['lookup_dcookie'] + 1
            syscalls.append("lookup_dcookie")
            add_to_pid_dict(ringbufferpid, "lookup_dcookie", tid)
            # print("Update für folgenden System Call lookup_dcookie. Neue Häufigkeit: " + str(
            #    occurences['lookup_dcookie']))
        elif syscall_number == 213:
            occurences['epoll_create'] = occurences['epoll_create'] + 1
            syscalls.append("epoll_create")
            add_to_pid_dict(ringbufferpid, "epoll_create", tid)
            # print("Update für folgenden System Call epoll_create. Neue Häufigkeit: " + str(
            #    occurences['epoll_create']))
        elif syscall_number == 214:
            occurences['epoll_ctl_old'] = occurences['epoll_ctl_old'] + 1
            syscalls.append("epoll_ctl_old")
            add_to_pid_dict(ringbufferpid, "epoll_ctl_old", tid)
            # print("Update für folgenden System Call epoll_ctl_old. Neue Häufigkeit: " + str(
            #    occurences['epoll_ctl_old']))
        elif syscall_number == 215:
            occurences['epoll_wait_old'] = occurences['epoll_wait_old'] + 1
            syscalls.append("epoll_wait_old")
            add_to_pid_dict(ringbufferpid, "epoll_wait_old", tid)
            # print("Update für folgenden System Call epoll_wait_old. Neue Häufigkeit: " + str(
            #    occurences['epoll_wait_old']))
        elif syscall_number == 216:
            occurences['remap_file_pages'] = occurences['remap_file_pages'] + 1
            syscalls.append("remap_file_pages")
            add_to_pid_dict(ringbufferpid, "remap_file_pages", tid)
            # print("Update für folgenden System Call remap_file_pages. Neue Häufigkeit: " + str(
            #    occurences['remap_file_pages']))
        elif syscall_number == 217:
            occurences['getdents64'] = occurences['getdents64'] + 1
            syscalls.append("getdents64")
            add_to_pid_dict(ringbufferpid, "getdents64", tid)
            # print("Update für folgenden System Call getdents64. Neue Häufigkeit: " + str(occurences['getdents64']))
        elif syscall_number == 218:
            occurences['set_tid_address'] = occurences['set_tid_address'] + 1
            syscalls.append("set_tid_address")
            add_to_pid_dict(ringbufferpid, "set_tid_address", tid)
            # print("Update für folgenden System Call set_tid_address. Neue Häufigkeit: " + str(
            #    occurences['set_tid_address']))
        elif syscall_number == 219:
            occurences['restart_syscall'] = occurences['restart_syscall'] + 1
            syscalls.append("restart_syscall")
            add_to_pid_dict(ringbufferpid, "restart_syscall", tid)
            # print("Update für folgenden System Call restart_syscall. Neue Häufigkeit: " + str(
            #    occurences['restart_syscall']))
        elif syscall_number == 220:
            occurences['semtimedop'] = occurences['semtimedop'] + 1
            syscalls.append("semtimedop")
            add_to_pid_dict(ringbufferpid, "semtimedop", tid)
            # print("Update für folgenden System Call semtimedop. Neue Häufigkeit: " + str(occurences['semtimedop']))
        elif syscall_number == 221:
            occurences['fadvise64'] = occurences['fadvise64'] + 1
            syscalls.append("fadvise64")
            add_to_pid_dict(ringbufferpid, "fadvise64", tid)
            # print("Update für folgenden System Call fadvise64. Neue Häufigkeit: " + str(occurences['fadvise64']))
        elif syscall_number == 222:
            occurences['timer_create'] = occurences['timer_create'] + 1
            syscalls.append("timer_create")
            add_to_pid_dict(ringbufferpid, "fadvise64", tid)
            # print("Update für folgenden System Call timer_create. Neue Häufigkeit: " + str(
            #    occurences['timer_create']))
        elif syscall_number == 223:
            occurences['timer_settime'] = occurences['timer_settime'] + 1
            syscalls.append("timer_settime")
            add_to_pid_dict(ringbufferpid, "timer_settime", tid)
            # print("Update für folgenden System Call timer_settime. Neue Häufigkeit: " + str(
            #    occurences['timer_settime']))
        elif syscall_number == 224:
            occurences['timer_gettime'] = occurences['timer_gettime'] + 1
            syscalls.append("timer_gettime")
            add_to_pid_dict(ringbufferpid, "timer_gettime", tid)
            # print("Update für folgenden System Call timer_gettime. Neue Häufigkeit: " + str(
            #    occurences['timer_gettime']))
        elif syscall_number == 225:
            occurences['timer_getoverrun'] = occurences['timer_getoverrun'] + 1
            syscalls.append("timer_getoverrun")
            add_to_pid_dict(ringbufferpid, "timer_getoverrun", tid)
            # print("Update für folgenden System Call timer_getoverrun. Neue Häufigkeit: " + str(
            #    occurences['timer_getoverrun']))
        elif syscall_number == 226:
            occurences['timer_delete'] = occurences['timer_delete'] + 1
            syscalls.append("timer_delete")
            add_to_pid_dict(ringbufferpid, "timer_delete", tid)
            # print("Update für folgenden System Call timer_delete. Neue Häufigkeit: " + str(
            #    occurences['timer_delete']))
        elif syscall_number == 227:
            occurences['clock_settime'] = occurences['clock_settime'] + 1
            syscalls.append("clock_settime")
            add_to_pid_dict(ringbufferpid, "clock_settime", tid)
            # print("Update für folgenden System Call clock_settime. Neue Häufigkeit: " + str(
            #    occurences['clock_settime']))
        elif syscall_number == 228:
            occurences['clock_gettime'] = occurences['clock_gettime'] + 1
            syscalls.append("clock_gettime")
            add_to_pid_dict(ringbufferpid, "clock_gettime", tid)
            # print("Update für folgenden System Call clock_gettime. Neue Häufigkeit: " + str(
            #    occurences['clock_gettime']))
        elif syscall_number == 229:
            occurences['clock_getres'] = occurences['clock_getres'] + 1
            syscalls.append("clock_getres")
            add_to_pid_dict(ringbufferpid, "clock_getres", tid)
            # print("Update für folgenden System Call clock_getres. Neue Häufigkeit: " + str(
            #    occurences['clock_getres']))
        elif syscall_number == 230:
            occurences['clock_nanosleep'] = occurences['clock_nanosleep'] + 1
            syscalls.append("clock_nanosleep")
            add_to_pid_dict(ringbufferpid, "clock_nanosleep", tid)
            # print("Update für folgenden System Call clock_nanosleep. Neue Häufigkeit: " + str(
            #    occurences['clock_nanosleep']))
        elif syscall_number == 231:
            occurences['exit_group'] = occurences['exit_group'] + 1
            syscalls.append("exit_group")
            add_to_pid_dict(ringbufferpid, "exit_group", tid)
            # print("Update für folgenden System Call exit_group. Neue Häufigkeit: " + str(occurences['exit_group']))
        elif syscall_number == 232:
            occurences['epoll_wait'] = occurences['epoll_wait'] + 1
            syscalls.append("epoll_wait")
            add_to_pid_dict(ringbufferpid, "epoll_wait", tid)
            # print("Update für folgenden System Call epoll_wait. Neue Häufigkeit: " + str(occurences['epoll_wait']))
        elif syscall_number == 233:
            occurences['epoll_ctl'] = occurences['epoll_ctl'] + 1
            syscalls.append("epoll_ctl")
            add_to_pid_dict(ringbufferpid, "epoll_ctl", tid)
            # print("Update für folgenden System Call epoll_ctl. Neue Häufigkeit: " + str(occurences['epoll_ctl']))
        elif syscall_number == 234:
            occurences['tgkill'] = occurences['tgkill'] + 1
            syscalls.append("tgkill")
            add_to_pid_dict(ringbufferpid, "tgkill", tid)
            # print("Update für folgenden System Call tgkill. Neue Häufigkeit: " + str(occurences['tgkill']))
        elif syscall_number == 235:
            occurences['utimes'] = occurences['utimes'] + 1
            syscalls.append("utimes")
            add_to_pid_dict(ringbufferpid, "utimes", tid)
            # print("Update für folgenden System Call utimes. Neue Häufigkeit: " + str(occurences['utimes']))
        elif syscall_number == 236:
            occurences['vserver'] = occurences['vserver'] + 1
            syscalls.append("vserver")
            add_to_pid_dict(ringbufferpid, "vserver", tid)
            # print("Update für folgenden System Call vserver. Neue Häufigkeit: " + str(occurences['vserver']))
        elif syscall_number == 237:
            occurences['mbind'] = occurences['mbind'] + 1
            syscalls.append("mbind")
            add_to_pid_dict(ringbufferpid, "mbind", tid)
            # print("Update für folgenden System Call mbind. Neue Häufigkeit: " + str(occurences['mbind']))
        elif syscall_number == 238:
            occurences['set_mempolicy'] = occurences['set_mempolicy'] + 1
            syscalls.append("set_mempolicy")
            add_to_pid_dict(ringbufferpid, "set_mempolicy", tid)
            # print("Update für folgenden System Call set_mempolicy. Neue Häufigkeit: " + str(
        #     occurences['set_mempolicy']))
        elif syscall_number == 239:
            occurences['get_mempolicy'] = occurences['get_mempolicy'] + 1
            syscalls.append("get_mempolicy")
            add_to_pid_dict(ringbufferpid, "get_mempolicy", tid)
            # print("Update für folgenden System Call get_mempolicy. Neue Häufigkeit: " + str(
            #    occurences['get_mempolicy']))
        elif syscall_number == 240:
            occurences['mq_open'] = occurences['mq_open'] + 1
            syscalls.append("mq_open")
            add_to_pid_dict(ringbufferpid, "mq_open", tid)
            # print("Update für folgenden System Call mq_open. Neue Häufigkeit: " + str(occurences['mq_open']))
        elif syscall_number == 241:
            occurences['mq_unlink'] = occurences['mq_unlink'] + 1
            syscalls.append("mq_unlink")
            add_to_pid_dict(ringbufferpid, "mq_unlink", tid)
            # print("Update für folgenden System Call mq_unlink. Neue Häufigkeit: " + str(occurences['mq_unlink']))
        elif syscall_number == 242:
            occurences['mq_timedsend'] = occurences['mq_timedsend'] + 1
            syscalls.append("mq_timedsend")
            add_to_pid_dict(ringbufferpid, "mq_timedsend", tid)
            # print("Update für folgenden System Call mq_timedsend. Neue Häufigkeit: " + str(
            #    occurences['mq_timedsend']))
        elif syscall_number == 243:
            occurences['mq_timedreceive'] = occurences['mq_timedreceive'] + 1
            syscalls.append("mq_timedreceive")
            add_to_pid_dict(ringbufferpid, "mq_timedreceive", tid)
            # print("Update für folgenden System Call mq_timedreceive. Neue Häufigkeit: " + str(
            #    occurences['mq_timedreceive']))
        elif syscall_number == 244:
            occurences['mq_notify'] = occurences['mq_notify'] + 1
            syscalls.append("mq_notify")
            add_to_pid_dict(ringbufferpid, "mq_notify", tid)
            # print("Update für folgenden System Call mq_notify. Neue Häufigkeit: " + str(occurences['mq_notify']))
        elif syscall_number == 245:
            occurences['mq_getsetattr'] = occurences['mq_getsetattr'] + 1
            syscalls.append("mq_getsetattr")
            add_to_pid_dict(ringbufferpid, "mq_getsetattr", tid)
            # print("Update für folgenden System Call mq_getsetattr. Neue Häufigkeit: " + str(
            #    occurences['mq_getsetattr']))
        elif syscall_number == 246:
            occurences['kexec_load'] = occurences['kexec_load'] + 1
            syscalls.append("kexec_load")
            add_to_pid_dict(ringbufferpid, "kexec_load", tid)
            # print("Update für folgenden System Call kexec_load. Neue Häufigkeit: " + str(occurences['kexec_load']))
        elif syscall_number == 247:
            occurences['waitid'] = occurences['waitid'] + 1
            syscalls.append("waitid")
            add_to_pid_dict(ringbufferpid, "waitid", tid)
            # print("Update für folgenden System Call waitid. Neue Häufigkeit: " + str(occurences['waitid']))
        elif syscall_number == 248:
            occurences['add_key'] = occurences['add_key'] + 1
            syscalls.append("add_key")
            add_to_pid_dict(ringbufferpid, "add_key", tid)
            # print("Update für folgenden System Call add_key. Neue Häufigkeit: " + str(occurences['add_key']))
        elif syscall_number == 249:
            occurences['request_key'] = occurences['request_key'] + 1
            syscalls.append("request_key")
            add_to_pid_dict(ringbufferpid, "request_key", tid)
            # print(
            #     "Update für folgenden System Call: request_key. Neue Häufigkeit: " + str(occurences['request_key']))
        elif syscall_number == 250:
            occurences['keyctl'] = occurences['keyctl'] + 1
            syscalls.append("keyctl")
            add_to_pid_dict(ringbufferpid, "keyctl", tid)
            # print("Update für folgenden System Call keyctl. Neue Häufigkeit: " + str(occurences['keyctl']))
        elif syscall_number == 251:
            occurences['ioprio_set'] = occurences['ioprio_set'] + 1
            syscalls.append("ioprio_set")
            add_to_pid_dict(ringbufferpid, "ioprio_set", tid)
            # print("Update für folgenden System Call ioprio_set. Neue Häufigkeit: " + str(occurences['ioprio_set']))
        elif syscall_number == 252:
            occurences['ioprio_get'] = occurences['ioprio_get'] + 1
            syscalls.append("ioprio_get")
            add_to_pid_dict(ringbufferpid, "ioprio_get", tid)
            # print("Update für folgenden System Call ioprio_get. Neue Häufigkeit: " + str(occurences['ioprio_get']))
        elif syscall_number == 253:
            occurences['inotify_init'] = occurences['inotify_init'] + 1
            syscalls.append("inotify_init")
            add_to_pid_dict(ringbufferpid, "inotify_init", tid)
            # print("Update für folgenden System Call inotify_init. Neue Häufigkeit: " + str(
            #    occurences['inotify_init']))
        elif syscall_number == 254:
            occurences['inotify_add_watch'] = occurences['inotify_add_watch'] + 1
            syscalls.append("inotify_add_watch")
            add_to_pid_dict(ringbufferpid, "inotify_add_watch", tid)
            # print("Update für folgenden System Call inotify_add_watch. Neue Häufigkeit: " + str(
            #    occurences['inotify_add_watch']))
        elif syscall_number == 255:
            occurences['inotify_rm_watch'] = occurences['inotify_rm_watch'] + 1
            syscalls.append("inotify_rm_watch")
            add_to_pid_dict(ringbufferpid, "inotify_rm_watch", tid)
            # print("Update für folgenden System Call inotify_rm_watch. Neue Häufigkeit: " + str(
            #    occurences['inotify_rm_watch']))
        elif syscall_number == 256:
            occurences['migrate_pages'] = occurences['migrate_pages'] + 1
            syscalls.append("migrate_pages")
            add_to_pid_dict(ringbufferpid, "migrate_pages", tid)
            # print("Update für folgenden System Call migrate_pages. Neue Häufigkeit: " + str(
            #    occurences['migrate_pages']))
        elif syscall_number == 257:
            occurences['openat'] = occurences['openat'] + 1
            syscalls.append("openat")
            add_to_pid_dict(ringbufferpid, "openat", tid)
            # print("Update für folgenden System Call openat. Neue Häufigkeit: " + str(occurences['openat']))
        elif syscall_number == 258:
            occurences['mkdirat'] = occurences['mkdirat'] + 1
            syscalls.append("mkdirat")
            add_to_pid_dict(ringbufferpid, "mkdirat", tid)
            # print("Update für folgenden System Call mkdirat. Neue Häufigkeit: " + str(occurences['mkdirat']))
        elif syscall_number == 259:
            occurences['mknodat'] = occurences['mknodat'] + 1
            syscalls.append("mknodat")
            add_to_pid_dict(ringbufferpid, "mknodat", tid)
            # print("Update für folgenden System Call mknodat. Neue Häufigkeit: " + str(occurences['mknodat']))
        elif syscall_number == 260:
            occurences['fchownat'] = occurences['fchownat'] + 1
            syscalls.append("fchownat")
            add_to_pid_dict(ringbufferpid, "fchownat", tid)
            # print("Update für folgenden System Call fchownat. Neue Häufigkeit: " + str(occurences['fchownat']))
        elif syscall_number == 261:
            occurences['futimesat'] = occurences['futimesat'] + 1
            syscalls.append("futimesat")
            add_to_pid_dict(ringbufferpid, "futimesat", tid)
            # print("Update für folgenden System Call futimesat. Neue Häufigkeit: " + str(occurences['futimesat']))
        elif syscall_number == 262:
            occurences['newfstatat'] = occurences['newfstatat'] + 1
            syscalls.append("newfstatat")
            add_to_pid_dict(ringbufferpid, "newfstatat", tid)
            # print("Update für folgenden System Call newfstatat. Neue Häufigkeit: " + str(occurences['newfstatat']))
        elif syscall_number == 263:
            occurences['unlinkat'] = occurences['unlinkat'] + 1
            syscalls.append("unlinkat")
            add_to_pid_dict(ringbufferpid, "unlinkat", tid)
            # print("Update für folgenden System Call unlinkat. Neue Häufigkeit: " + str(occurences['unlinkat']))
        elif syscall_number == 264:
            occurences['renameat'] = occurences['renameat'] + 1
            syscalls.append("renameat")
            add_to_pid_dict(ringbufferpid, "renameat", tid)
            # print("Update für folgenden System Call renameat. Neue Häufigkeit: " + str(occurences['renameat']))
        elif syscall_number == 265:
            occurences['linkat'] = occurences['linkat'] + 1
            syscalls.append("linkat")
            add_to_pid_dict(ringbufferpid, "linkat", tid)
            # print("Update für folgenden System Call linkat. Neue Häufigkeit: " + str(occurences['linkat']))
        elif syscall_number == 266:
            occurences['symlinkat'] = occurences['symlinkat'] + 1
            syscalls.append("symlinkat")
            add_to_pid_dict(ringbufferpid, "symlinkat", tid)
            # print("Update für folgenden System Call symlinkat. Neue Häufigkeit: " + str(occurences['symlinkat']))
        elif syscall_number == 267:
            occurences['readlinkat'] = occurences['readlinkat'] + 1
            syscalls.append("readlinkat")
            add_to_pid_dict(ringbufferpid, "readlinkat", tid)
            # print("Update für folgenden System Call readlinkat. Neue Häufigkeit: " + str(occurences['readlinkat']))
        elif syscall_number == 268:
            occurences['fchmodat'] = occurences['fchmodat'] + 1
            syscalls.append("fchmodat")
            add_to_pid_dict(ringbufferpid, "fchmodat", tid)
            # print("Update für folgenden System Call fchmodat. Neue Häufigkeit: " + str(occurences['fchmodat']))
        elif syscall_number == 269:
            occurences['faccessat'] = occurences['faccessat'] + 1
            syscalls.append("faccessat")
            add_to_pid_dict(ringbufferpid, "faccessat", tid)
            # print("Update für folgenden System Call faccessat. Neue Häufigkeit: " + str(occurences['faccessat']))
        elif syscall_number == 270:
            occurences['pselect6'] = occurences['pselect6'] + 1
            syscalls.append("pselect6")
            add_to_pid_dict(ringbufferpid, "pselect6", tid)
            # print("Update für folgenden System Call pselect6. Neue Häufigkeit: " + str(occurences['pselect6']))
        elif syscall_number == 271:
            occurences['ppoll'] = occurences['ppoll'] + 1
            syscalls.append("ppoll")
            add_to_pid_dict(ringbufferpid, "ppoll", tid)
            # print("Update für folgenden System Call ppoll. Neue Häufigkeit: " + str(occurences['ppoll']))
        elif syscall_number == 272:
            occurences['unshare'] = occurences['unshare'] + 1
            syscalls.append("unshare")
            add_to_pid_dict(ringbufferpid, "unshare", tid)
            # print("Update für folgenden System Call unshare. Neue Häufigkeit: " + str(occurences['unshare']))
        elif syscall_number == 273:
            occurences['set_robust_list'] = occurences['set_robust_list'] + 1
            syscalls.append("set_robust_list")
            add_to_pid_dict(ringbufferpid, "set_robust_list", tid)
            # print("Update für folgenden System Call set_robust_list. Neue Häufigkeit: " + str(
            #    occurences['set_robust_list']))
        elif syscall_number == 274:
            occurences['get_robust_list'] = occurences['get_robust_list'] + 1
            syscalls.append("get_robust_list")
            add_to_pid_dict(ringbufferpid, "get_robust_list", tid)
            # print("Update für folgenden System Call get_robust_list. Neue Häufigkeit: " + str(
            #    occurences['get_robust_list']))
        elif syscall_number == 275:
            occurences['splice'] = occurences['splice'] + 1
            syscalls.append("splice")
            add_to_pid_dict(ringbufferpid, "splice", tid)
            # print("Update für folgenden System Call splice. Neue Häufigkeit: " + str(occurences['splice']))
        elif syscall_number == 276:
            occurences['tee'] = occurences['tee'] + 1
            syscalls.append("tee")
            add_to_pid_dict(ringbufferpid, "tee", tid)
            # print("Update für folgenden System Call tee. Neue Häufigkeit: " + str(occurences['tee']))
        elif syscall_number == 277:
            occurences['sync_file_range'] = occurences['sync_file_range'] + 1
            syscalls.append("sync_file_range")
            add_to_pid_dict(ringbufferpid, "sync_file_range", tid)
            # print("Update für folgenden System Call sync_file_range. Neue Häufigkeit: " + str(
            #    occurences['sync_file_range']))
        elif syscall_number == 278:
            occurences['vmsplice'] = occurences['vmsplice'] + 1
            syscalls.append("vmsplice")
            add_to_pid_dict(ringbufferpid, "vmsplice", tid)
            # print("Update für folgenden System Call vmsplice. Neue Häufigkeit: " + str(occurences['vmsplice']))
        elif syscall_number == 279:
            occurences['move_pages'] = occurences['move_pages'] + 1
            syscalls.append("move_pages")
            add_to_pid_dict(ringbufferpid, "move_pages", tid)
            # print("Update für folgenden System Call move_pages. Neue Häufigkeit: " + str(occurences['move_pages']))
        elif syscall_number == 280:
            occurences['utimensat'] = occurences['utimensat'] + 1
            syscalls.append("utimensat")
            add_to_pid_dict(ringbufferpid, "utimensat", tid)
            # print("Update für folgenden System Call utimensat. Neue Häufigkeit: " + str(occurences['utimensat']))
        elif syscall_number == 281:
            occurences['epoll_pwait'] = occurences['epoll_pwait'] + 1
            syscalls.append("epoll_pwait")
            add_to_pid_dict(ringbufferpid, "epoll_pwait", tid)
            # print(
            #     "Update für folgenden System Call: epoll_pwait. Neue Häufigkeit: " + str(occurences['epoll_pwait']))
        elif syscall_number == 282:
            occurences['signalfd'] = occurences['signalfd'] + 1
            syscalls.append("signalfd")
            add_to_pid_dict(ringbufferpid, "signalfd", tid)
            # print("Update für folgenden System Call signalfd. Neue Häufigkeit: " + str(occurences['utimensat']))
        elif syscall_number == 283:
            occurences['timerfd_create'] = occurences['timerfd_create'] + 1
            syscalls.append("timerfd_create")
            add_to_pid_dict(ringbufferpid, "timerfd_create", tid)
            # print("Update für folgenden System Call timerfd_create. Neue Häufigkeit: " + str(
            #    occurences['timerfd_create']))
        elif syscall_number == 284:
            occurences['eventfd'] = occurences['eventfd'] + 1
            syscalls.append("eventfd")
            add_to_pid_dict(ringbufferpid, "eventfd", tid)
            # print("Update für folgenden System Call eventfd. Neue Häufigkeit: " + str(occurences['eventfd']))
        elif syscall_number == 285:
            occurences['fallocate'] = occurences['fallocate'] + 1
            syscalls.append("fallocate")
            add_to_pid_dict(ringbufferpid, "fallocate", tid)
            # print("Update für folgenden System Call fallocate. Neue Häufigkeit: " + str(occurences['fallocate']))
        elif syscall_number == 286:
            occurences['timerfd_settime'] = occurences['timerfd_settime'] + 1
            syscalls.append("timerfd_settime")
            add_to_pid_dict(ringbufferpid, "timerfd_settime", tid)
            # print("Update für folgenden System Call timerfd_settime. Neue Häufigkeit: " + str(
            #    occurences['timerfd_settime']))
        elif syscall_number == 287:
            occurences['timerfd_gettime'] = occurences['timerfd_gettime'] + 1
            syscalls.append("timerfd_gettime")
            add_to_pid_dict(ringbufferpid, "timerfd_gettime", tid)
            # print("Update für folgenden System Call timerfd_gettime. Neue Häufigkeit: " + str(
            #    occurences['timerfd_gettime']))
        elif syscall_number == 288:
            occurences['accept4'] = occurences['accept4'] + 1
            syscalls.append("accept4")
            add_to_pid_dict(ringbufferpid, "accept4", tid)
            # print("Update für folgenden System Call accept4. Neue Häufigkeit: " + str(occurences['accept4']))
        elif syscall_number == 289:
            occurences['signalfd4'] = occurences['signalfd4'] + 1
            syscalls.append("signalfd4")
            add_to_pid_dict(ringbufferpid, "signalfd4", tid)
            # print("Update für folgenden System Call signalfd4. Neue Häufigkeit: " + str(occurences['signalfd4']))
        elif syscall_number == 290:
            occurences['eventfd2'] = occurences['eventfd2'] + 1
            syscalls.append("eventfd2")
            add_to_pid_dict(ringbufferpid, "eventfd2", tid)
            # print("Update für folgenden System Call eventfd2. Neue Häufigkeit: " + str(occurences['eventfd2']))
        elif syscall_number == 291:
            occurences['epoll_create1'] = occurences['epoll_create1'] + 1
            syscalls.append("epoll_create1")
            add_to_pid_dict(ringbufferpid, "epoll_create1", tid)
            # print("Update für folgenden System Call epoll_create1. Neue Häufigkeit: " + str(
            #    occurences['epoll_create1']))
        elif syscall_number == 292:
            occurences['dup3'] = occurences['dup3'] + 1
            syscalls.append("dup3")
            add_to_pid_dict(ringbufferpid, "dup3", tid)
            # print("Update für folgenden System Call dup3. Neue Häufigkeit: " + str(occurences['eventfd2']))
        elif syscall_number == 293:
            occurences['pipe2'] = occurences['pipe2'] + 1
            syscalls.append("pipe2")
            add_to_pid_dict(ringbufferpid, "pipe2", tid)
            # print("Update für folgenden System Call pipe2. Neue Häufigkeit: " + str(occurences['pipe2']))
        elif syscall_number == 294:
            occurences['inotify_init1'] = occurences['inotify_init1'] + 1
            syscalls.append("inotify_init1")
            add_to_pid_dict(ringbufferpid, "inotify_init1", tid)
            # print("Update für folgenden System Call inotify_init1. Neue Häufigkeit: " + str(
            #    occurences['inotify_init1']))
        elif syscall_number == 295:
            occurences['preadv'] = occurences['preadv'] + 1
            syscalls.append("preadv")
            add_to_pid_dict(ringbufferpid, "preadv", tid)
            # print("Update für folgenden System Call preadv. Neue Häufigkeit: " + str(occurences['preadv']))
        elif syscall_number == 296:
            occurences['pwritev'] = occurences['pwritev'] + 1
            syscalls.append("pwritev")
            add_to_pid_dict(ringbufferpid, "pwritev", tid)
            # print("Update für folgenden System Call pwritev. Neue Häufigkeit: " + str(occurences['pwritev']))
        elif syscall_number == 297:
            occurences['rt_tgsigqueueinfo'] = occurences['rt_tgsigqueueinfo'] + 1
            syscalls.append("rt_tgsigqueueinfo")
            add_to_pid_dict(ringbufferpid, "rt_tgsigqueueinfo", tid)
            # print("Update für folgenden System Call rt_tgsigqueueinfo. Neue Häufigkeit: " + str(
            #    occurences['rt_tgsigqueueinfo']))
        elif syscall_number == 298:
            occurences['perf_event_open'] = occurences['perf_event_open'] + 1
            syscalls.append("perf_event_open")
            add_to_pid_dict(ringbufferpid, "perf_event_open", tid)
            # print("Update für folgenden System Call perf_event_open. Neue Häufigkeit: " + str(
            #    occurences['perf_event_open']))
        elif syscall_number == 299:
            occurences['recvmmsg'] = occurences['recvmmsg'] + 1
            syscalls.append("recvmmsg")
            add_to_pid_dict(ringbufferpid, "recvmmsg", tid)
            # print("Update für folgenden System Call recvmmsg. Neue Häufigkeit: " + str(occurences['recvmmsg']))
        elif syscall_number == 300:
            occurences['fanotify_init'] = occurences['fanotify_init'] + 1
            syscalls.append("fanotify_init")
            add_to_pid_dict(ringbufferpid, "fanotify_init", tid)
            # print("Update für folgenden System Call fanotify_init. Neue Häufigkeit: " + str(
            #    occurences['fanotify_init']))
        elif syscall_number == 301:
            occurences['fanotify_mark'] = occurences['fanotify_mark'] + 1
            syscalls.append("fanotify_mark")
            add_to_pid_dict(ringbufferpid, "fanotify_mark", tid)
            # print("Update für folgenden System Call fanotify_mark. Neue Häufigkeit: " + str(
            #    occurences['fanotify_mark']))
        elif syscall_number == 302:
            occurences['prlimit64'] = occurences['prlimit64'] + 1
            syscalls.append("prlimit64")
            add_to_pid_dict(ringbufferpid, "prlimit64", tid)
            # print("Update für folgenden System Call prlimit64. Neue Häufigkeit: " + str(occurences['prlimit64']))
        elif syscall_number == 303:
            occurences['name_to_handle_at'] = occurences['name_to_handle_at'] + 1
            syscalls.append("name_to_handle_at")
            add_to_pid_dict(ringbufferpid, "name_to_handle_at", tid)
            # print("Update für folgenden System Call name_to_handle_at. Neue Häufigkeit: " + str(
            #    occurences['name_to_handle_at']))
        elif syscall_number == 304:
            occurences['open_by_handle_at'] = occurences['open_by_handle_at'] + 1
            syscalls.append("open_by_handle_at")
            add_to_pid_dict(ringbufferpid, "open_by_handle_at", tid)
            # print("Update für folgenden System Call open_by_handle_at. Neue Häufigkeit: " + str(
            #    occurences['open_by_handle_at']))
        elif syscall_number == 305:
            occurences['clock_adjtime'] = occurences['clock_adjtime'] + 1
            syscalls.append("clock_adjtime")
            add_to_pid_dict(ringbufferpid, "clock_adjtime", tid)
            # print("Update für folgenden System Call clock_adjtime. Neue Häufigkeit: " + str(
            #    occurences['clock_adjtime']))
        elif syscall_number == 306:
            occurences['syncfs'] = occurences['syncfs'] + 1
            syscalls.append("syncfs")
            add_to_pid_dict(ringbufferpid, "syncfs", tid)
            # print("Update für folgenden System Call syncfs. Neue Häufigkeit: " + str(occurences['syncfs']))
        elif syscall_number == 307:
            occurences['sendmmsg'] = occurences['sendmmsg'] + 1
            syscalls.append("sendmmsg")
            add_to_pid_dict(ringbufferpid, "sendmmsg", tid)
            # print("Update für folgenden System Call sendmmsg. Neue Häufigkeit: " + str(occurences['sendmmsg']))
        elif syscall_number == 308:
            occurences['setns'] = occurences['setns'] + 1
            syscalls.append("setns")
            add_to_pid_dict(ringbufferpid, "setns", tid)
            # print("Update für folgenden System Call setns. Neue Häufigkeit: " + str(occurences['setns']))
        elif syscall_number == 309:
            occurences['getcpu'] = occurences['getcpu'] + 1
            syscalls.append("getcpu")
            add_to_pid_dict(ringbufferpid, "getcpu", tid)
            # print("Update für folgenden System Call getcpu. Neue Häufigkeit: " + str(occurences['getcpu']))
        elif syscall_number == 310:
            occurences['process_vm_readv'] = occurences['process_vm_readv'] + 1
            syscalls.append("process_vm_readv")
            add_to_pid_dict(ringbufferpid, "process_vm_readv", tid)
            # print("Update für folgenden System Call process_vm_readv. Neue Häufigkeit: " + str(
            #    occurences['process_vm_readv']))
        elif syscall_number == 311:
            occurences['process_vm_writev'] = occurences['process_vm_writev'] + 1
            syscalls.append("process_vm_writev")
            add_to_pid_dict(ringbufferpid, "process_vm_writev", tid)
            # print("Update für folgenden System Call process_vm_writev. Neue Häufigkeit: " + str(
            #    occurences['process_vm_writev']))
        elif syscall_number == 312:
            occurences['kcmp'] = occurences['kcmp'] + 1
            syscalls.append("kcmp")
            add_to_pid_dict(ringbufferpid, "kcmp", tid)
            # print("Update für folgenden System Call kcmp. Neue Häufigkeit: " + str(occurences['kcmp']))
        elif syscall_number == 313:
            occurences['finit_module'] = occurences['finit_module'] + 1
            syscalls.append("finit_module")
            add_to_pid_dict(ringbufferpid, "finit_module", tid)
            # print("Update für folgenden System Call finit_module. Neue Häufigkeit: " + str(
            #    occurences['finit_module']))
        elif syscall_number == 314:
            occurences['sched_setattr'] = occurences['sched_setattr'] + 1
            syscalls.append("sched_setattr")
            add_to_pid_dict(ringbufferpid, "sched_setattr", tid)
            # print("Update für folgenden System Call sched_setattr. Neue Häufigkeit: " + str(
            #    occurences['sched_setattr']))
        elif syscall_number == 315:
            occurences['sched_getattr'] = occurences['sched_getattr'] + 1
            syscalls.append("sched_getattr")
            add_to_pid_dict(ringbufferpid, "sched_getattr", tid)
            # print("Update für folgenden System Call sched_getattr. Neue Häufigkeit: " + str(
            #    occurences['sched_getattr']))
        elif syscall_number == 316:
            occurences['renameat2'] = occurences['renameat2'] + 1
            syscalls.append("renameat2")
            add_to_pid_dict(ringbufferpid, "renameat2", tid)
            # print("Update für folgenden System Call renameat2. Neue Häufigkeit: " + str(occurences['renameat2']))
        elif syscall_number == 317:
            occurences['seccomp'] = occurences['seccomp'] + 1
            syscalls.append("seccomp")
            add_to_pid_dict(ringbufferpid, "seccomp", tid)
            # print("Update für folgenden System Call seccomp. Neue Häufigkeit: " + str(occurences['seccomp']))
        elif syscall_number == 318:
            occurences['getrandom'] = occurences['getrandom'] + 1
            syscalls.append("getrandom")
            add_to_pid_dict(ringbufferpid, "getrandom", tid)
            # print("Update für folgenden System Call getrandom. Neue Häufigkeit: " + str(occurences['getrandom']))
        elif syscall_number == 319:
            occurences['memfd_create'] = occurences['memfd_create'] + 1
            syscalls.append("memfd_create")
            add_to_pid_dict(ringbufferpid, "memfd_create", tid)
            # print("Update für folgenden System Call memfd_create. Neue Häufigkeit: " + str(
            #    occurences['memfd_create']))
        elif syscall_number == 320:
            occurences['kexec_file_load'] = occurences['kexec_file_load'] + 1
            syscalls.append("kexec_file_load")
            add_to_pid_dict(ringbufferpid, "kexec_file_load", tid)
            # print("Update für folgenden System Call kexec_file_load. Neue Häufigkeit: " + str(
            #    occurences['kexec_file_load']))
        elif syscall_number == 321:
            occurences['bpf'] = occurences['bpf'] + 1
            syscalls.append("bpf")
            add_to_pid_dict(ringbufferpid, "bpf", tid)
            # print("Update für folgenden System Call bpf. Neue Häufigkeit: " + str(occurences['process_vm_readv']))


# Funktion zum Auslesen der events im Kernel Ring Buffer. Dabei wird für jeden neuen Eintrag im Ring Buffer die
# Callback Funktion aufgerufen. Wird das Programm vom Benutzer mit STRG + C beendet, gibt das Programm das sortierte
# Dictionary mit den Häufigkeiten aus. Anschließend wird noch die Häufigkeit prozentual ausgegeben, bevor das Programm
# terminiert
def getringbuffer():
    b["events"].open_perf_buffer(updatesequence, page_cnt=256)
    while True:
        try:
            b.perf_buffer_poll(timeout=10 * 1000)
            time.sleep(1)
        except KeyboardInterrupt:
            for pid, pattern in sequencesswithtpid.items():
                print("\nPID: %-*s Pattern: %s" % (5, str(pid), str(pattern)))

            print("\n++++++++++++++++++++++++++++")
            for pid, pattern in sequencesswithttid.items():
                print("\nTID: %-*s Pattern: %s" % (5, str(pid), str(pattern)))
            return


# todo
def signal_handler(sig, frame):
    print('Exited with Keyboard Interrupt')
    sys.exit(0)



# todo
def add_to_pid_dict(key, value, tid):
    if key in sequencesswithtpid:
        sequencesswithtpid[key].append(value)
    else:
        sequencesswithtpid[key] = [value]
    if tid in sequencesswithttid:
        sequencesswithttid[tid].append(value)
    else:
        sequencesswithttid[tid] = [value]


# Die Funktion gibt die PID-Namespace Nummer des Host Systems zurück
def getinum():
    # Führe den Befehl aus und lese die Ausgabe
    result = os.popen("ls -la /proc/self/ns").read()

    # Splitten der Ausgabe an den Leerzeichen
    # Beispiel-Ausgabe: "total 0\nlrwxrwxrwx 1 user user 0 Apr 20 10:00 pid -> 'pid:[4026531836]'\n"
    parts = result.split(" ")

    # Suche nach der Zeichenkette "'pid:[...]'"
    pid_ns_id = None
    for part in parts:
        if part.__contains__("pid:["):  # and part.endswith("]'\n"):
            # Extrahiere die ID aus der Zeichenkette
            pid_ns_id = part[5:-12]
            break
    print("PID-Namespace ID des Host Systems: " + str(pid_ns_id))
    return pid_ns_id


# Eingabe des zu tracenden Binaries.
# ibinary = input("Input Binary: ")
# localpids = getpids(ibinary)
print("Getting Host-PID-NS")
getinum()
print("attaching to kretprobes")
attachkretprobe()
print("attachment ready" + "\n" + "now tracing! \npress CTRL + C to stop tracing.")
getringbuffer()
