import os
import signal
import sys

from bcc import BPF

prog = """ 

#include <linux/pid_namespace.h>

struct data_t {
    int syscallnumber;
    unsigned int inum;
};

BPF_PERF_OUTPUT(events);

int sclone(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 0;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;

}
int sopen(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 1;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sread(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 2;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int swrite(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 3;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclose(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 4;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sstat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 5;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfstat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 6;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slstat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 7;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spoll(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 8;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slseek(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 9;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smmap(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 10;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smprotect(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 11;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smunmap(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 12;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sbrk(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 13;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigaction(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 14;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigprocmask(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 15;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srt_sigreturn(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 16;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 17;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spread64(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 18;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spwrite64(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 19;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadv(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 20;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int swritev(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 21;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int saccess(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 22;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spipe(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 23;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sselect(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 24;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_yield(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 25;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smremap(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 26;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsync(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 27;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smincore(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 28;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smadvise(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 29;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshmget(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 30;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int sshmat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 31;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshmctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 32;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sdup(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 33;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sdup2(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 34;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spause(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 35;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int snanosleep(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 36;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetitimer(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 37;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int salarm(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 38;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetitimer(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 39;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 40;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int ssendfile(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 41;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssocket(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 42;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sconnect(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 43;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int saccept(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 44;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssendto(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 45;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srecvfrom(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 46;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssendmsg(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 47;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srecvmsg(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 48;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshutdown(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 49;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sbind(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 50;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int slisten(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 51;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetsockname(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 52;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpeername(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 53;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssocketpair(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 54;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetsockopt(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 55;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetsockopt(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 56;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfork(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 57;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int svfork(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 58;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sexecve(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 59;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sexit(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 60;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int swait4(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 61;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skill(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 62;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int suname(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 63;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemget(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 64;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemop(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 65;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 66;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sshmdt(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 67;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsgget(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 68;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsgsnd(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 69;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsgrcv(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 70;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smsgctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 71;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfcntl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 72;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sflock(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 73;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfsync(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 74;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfdatasync(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 75;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int struncate(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 76;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sftruncate(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 77;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetdents(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 78;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetcwd(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 79;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int schdir(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 80;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchdir(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 81;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srename(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 82;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smkdir(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 83;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srmdir(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 84;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int screat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 85;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slink(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 86;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sunlink(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 87;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssymlink(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 88;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadlink(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 89;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int schmod(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 90;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int sfchmod(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 91;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int schown(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 92;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchown(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 93;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int slchown(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 94;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sumask(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 95;
    data.inum = inum_ring;
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
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 97;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetrusage(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 98;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssysinfo(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 99;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int stimes(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 100;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sptrace(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 101;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 102;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssyslog(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 103;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 104;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 105;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 106;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgeteuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 107;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetegid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 108;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetpgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 109;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetppid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 110;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetpgrp(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 111;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetsid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 112;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetreuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 113;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetregid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 114;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetgroups(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 115;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetgroups(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 116;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetresuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 117;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetresuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 118;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetresgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 119;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetresgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 120;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetpgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 121;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetfsuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 122;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetfsgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 123;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetsid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 124;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int scapget(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 125;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int scapset(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 126;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int srt_sigpending(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 127;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int srt_sigtimedwait(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 128;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int srt_sigqueueinfo(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 129;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int srt_sigsuspend(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 130;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssigaltstack(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 131;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sutime(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 132;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int smknod(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 133;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int suselib(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 134;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int spersonality(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 135;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sustat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 136;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sstatfs(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 137;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sfstatfs(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 138;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssysfs(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 139;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sgetpriority(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 140;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetpriority(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 141;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssched_setparam(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 142;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssched_getparam(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 143;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssched_setscheduler(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 144;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssched_getscheduler(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 145;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssched_get_priority_max(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 146;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssched_get_priority_min(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 147;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssched_rr_get_interval(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 148;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int smlock(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 149;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int smunlock(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 150;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int smlockall(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 151;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int smunlockall(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 152;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int svhangup(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 153;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int smodify_ldt(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 154;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int spivot_root(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 155;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssysctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 156;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sprctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 157;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sarch_prctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 158;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sadjtimex(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 159;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssetrlimit(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 160;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int schroot(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 161;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssync(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 162;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sacct(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 163;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssettimeofday(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 164;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int smount(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 165;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sumount2(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 166;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sswapon(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 167;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sswapoff(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 168;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int sreboot(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 169;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    
}
int ssethostname(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 170;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetdomainname(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 171;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int siopl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 172;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioperm(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 173;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int screate_module(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 174;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinit_module(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 175;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sdelete_module(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 176;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_kernel_syms(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 177;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int squery_module(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 178;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int squotactl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 179;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int snfsservctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 180;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetpmsg(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 181;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sputpmsg(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 182;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int safs_syscall(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 183;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stuxcall(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 184;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssecurity(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 185;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgettid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 186;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadahead(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 187;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssetxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 188;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slsetxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 189;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfsetxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 190;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 191;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slgetxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 192;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfgetxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 193;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slistxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 194;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sllistxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 195;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sflistxattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 196;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sremovexattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 197;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slremovexattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 198;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfremovexattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 199;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stkill(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 200;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stime(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 201;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfutex(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 202;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_setaffinity(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 203;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssched_getaffinity(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 204;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_thread_area(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 205;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_setup(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 206;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_destroy(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 207;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_getevents(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 208;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_submit(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 209;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sio_cancel(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 210;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_thread_area(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 211;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slookup_dcookie(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 212;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_create(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 213;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_ctl_old(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 214;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_wait_old(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 215;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sremap_file_pages(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 216;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sgetdents64(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 217;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_tid_address(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 218;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srestart_syscall(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 219;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssemtimedop(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 220;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfadvise64(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 221;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_create(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 222;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_settime(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 223;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_gettime(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 224;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_getoverrun(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 225;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stimer_delete(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 226;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_settime(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 227;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_gettime(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 228;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_getres(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 229;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclock_nanosleep(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 230;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sexit_group(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 231;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_wait(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 232;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sepoll_ctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 233;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stgkill(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 234;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sutimes(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 235;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int svserver(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 236;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smbind(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 237;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_mempolicy(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 238;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_mempolicy(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 239;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_open(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 240;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_unlink(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 241;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_timedsend(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 242;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_timedreceive(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 243;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_notify(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 244;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smq_getsetattr(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 245;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skexec_load(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 246;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int swaitid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 247;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sadd_key(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 248;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srequest_key(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 249;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int skeyctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 250;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioprio_set(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 251;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sioprio_get(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 252;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinotify_init(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 253;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinotify_add_watch(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 254;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sinotify_rm_watch(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 255;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smigrate_pages(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 256;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sopenat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 257;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smkdirat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 258;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smknodat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 259;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchownat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 260;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfutimesat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 261;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int snewfstatat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 262;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sunlinkat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 263;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int srenameat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 264;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slinkat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 265;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssymlinkat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 266;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sreadlinkat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 267;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfchmodat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 268;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfaccessat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 269;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spselect6(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 270;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sppoll(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 271;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sunshare(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 272;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sset_robust_list(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 273;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sget_robust_list(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 274;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssplice(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 275;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int stee(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 276;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int ssync_file_range(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 277;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int svmsplice(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 278;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smove_pages(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 279;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sutimensat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 280;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""
b = BPF(text=prog)


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
    b.attach_kretprobe(event=b.get_syscall_fnname("setdomainname"), fn_name="ssetdomainname")
    b.attach_kretprobe(event=b.get_syscall_fnname("iopl"), fn_name="siopl")
    b.attach_kretprobe(event=b.get_syscall_fnname("ioperm"), fn_name="sioperm")
    # b.attach_kretprobe(event=b.get_syscall_fnname("create_module"), fn_name="screate_module") not traceable
    b.attach_kretprobe(event=b.get_syscall_fnname("init_module"), fn_name="sinit_module")
    b.attach_kretprobe(event=b.get_syscall_fnname("delete_module"), fn_name="sdelete_module")
    # b.attach_kretprobe(event=b.get_syscall_fnname("get_kernel_syms"), fn_name="sget_kernel_syms") not traceable, removed from Linux Kernel
    # b.attach_kretprobe(event=b.get_syscall_fnname("query_module"), fn_name="squery_module") not traceable
    b.attach_kretprobe(event=b.get_syscall_fnname("quotactl"), fn_name="squotactl")
    # b.attach_kretprobe(event=b.get_syscall_fnname("nfsservctl"), fn_name="snfsservctl") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("getpmsg"), fn_name="sgetpmsg") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("putpmsg"), fn_name="sputpmsg") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("afs_syscall"), fn_name="safs_syscall") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("tuxcall"), fn_name="stuxcall") not traceable
    # b.attach_kretprobe(event=b.get_syscall_fnname("security"), fn_name="ssecurity") not traceable
    b.attach_kretprobe(event=b.get_syscall_fnname("gettid"), fn_name="sgettid")
    b.attach_kretprobe(event=b.get_syscall_fnname("readahead"), fn_name="sreadahead")
    b.attach_kretprobe(event=b.get_syscall_fnname("setxattr"), fn_name="ssetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("lsetxattr"), fn_name="slsetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("fsetxattr"), fn_name="sfsetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("getxattr"), fn_name="sgetxattr")
    b.attach_kretprobe(event=b.get_syscall_fnname("lgetxattr"), fn_name="slgetxattr")
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
    # b.attach_kretprobe(event=b.get_syscall_fnname("vserver"), fn_name="svserver") not traceable
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
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_pwait"), fn_name="sepoll_pwait")
    # b.attach_kretprobe(event=b.get_syscall_fnname("signalfd"), fn_name="ssignalfd")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timerfd_create"), fn_name="stimerfd_create")
    # b.attach_kretprobe(event=b.get_syscall_fnname("eventfd"), fn_name="seventfd")
    # b.attach_kretprobe(event=b.get_syscall_fnname("fallocate"), fn_name="sfallocate")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timerfd_settime"), fn_name="stimerfd_settime")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timerfd_gettime"), fn_name="stimerfd_gettime")
    # b.attach_kretprobe(event=b.get_syscall_fnname("accept4"), fn_name="saccept4")
    # b.attach_kretprobe(event=b.get_syscall_fnname("signalfd4"), fn_name="ssignalfd4")
    # b.attach_kretprobe(event=b.get_syscall_fnname("eventfd2"), fn_name="seventfd2")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_create1"), fn_name="sepoll_create1")
    # b.attach_kretprobe(event=b.get_syscall_fnname("dup3"), fn_name="sdup3")
    # b.attach_kretprobe(event=b.get_syscall_fnname("pipe2"), fn_name="spipe2")
    # b.attach_kretprobe(event=b.get_syscall_fnname("inotify_init1"), fn_name="sinotify_init1")
    # b.attach_kretprobe(event=b.get_syscall_fnname("preadv"), fn_name="spreadv")
    # b.attach_kretprobe(event=b.get_syscall_fnname("pwritev"), fn_name="spwritev")
    # b.attach_kretprobe(event=b.get_syscall_fnname("rt_tgsigqueueinfo"), fn_name="srt_tgsigqueueinfo")
    # b.attach_kretprobe(event=b.get_syscall_fnname("perf_event_open"), fn_name="sperf_event_open")
    # b.attach_kretprobe(event=b.get_syscall_fnname("recvmmsg"), fn_name="srecvmmsg")
    # b.attach_kretprobe(event=b.get_syscall_fnname("fanotify_init"), fn_name="sfanotify_init")
    # b.attach_kretprobe(event=b.get_syscall_fnname("fanotify_mark"), fn_name="sfanotify_mark")
    # b.attach_kretprobe(event=b.get_syscall_fnname("prlimit64"), fn_name="sprlimit64")
    # b.attach_kretprobe(event=b.get_syscall_fnname("name_to_handle_at"), fn_name="sname_to_handle_at")
    # b.attach_kretprobe(event=b.get_syscall_fnname("open_by_handle_at"), fn_name="sopen_by_handle_at")
    # b.attach_kretprobe(event=b.get_syscall_fnname("clock_adjtime"), fn_name="sclock_adjtime")
    # b.attach_kretprobe(event=b.get_syscall_fnname("syncfs"), fn_name="ssyncfs")
    # b.attach_kretprobe(event=b.get_syscall_fnname("sendmmsg"), fn_name="ssendmmsg")
    # b.attach_kretprobe(event=b.get_syscall_fnname("setns"), fn_name="ssetns")
    # b.attach_kretprobe(event=b.get_syscall_fnname("getcpu"), fn_name="sgetcpu")
    # b.attach_kretprobe(event=b.get_syscall_fnname("process_vm_readv"), fn_name="sprocess_vm_readv")
    # b.attach_kretprobe(event=b.get_syscall_fnname("process_vm_writev"), fn_name="sprocess_vm_writev")
    # b.attach_kretprobe(event=b.get_syscall_fnname("kcmp"), fn_name="skcmp")
    # b.attach_kretprobe(event=b.get_syscall_fnname("finit_module"), fn_name="sfinit_module")
    # b.attach_kretprobe(event=b.get_syscall_fnname("sched_setattr"), fn_name="ssched_setattr")
    # b.attach_kretprobe(event=b.get_syscall_fnname("sched_getattr"), fn_name="ssched_getattr")
    # b.attach_kretprobe(event=b.get_syscall_fnname("renameat2"), fn_name="srenameat2")
    # b.attach_kretprobe(event=b.get_syscall_fnname("seccomp"), fn_name="sseccomp")
    # b.attach_kretprobe(event=b.get_syscall_fnname("getrandom"), fn_name="sgetrandom")
    # b.attach_kretprobe(event=b.get_syscall_fnname("memfd_create"), fn_name="smemfd_create")
    # b.attach_kretprobe(event=b.get_syscall_fnname("kexec_file_load"), fn_name="skexec_file_load")
    # b.attach_kretprobe(event=b.get_syscall_fnname("bpf"), fn_name="sbpf")


patterns = []


def detectpatterns(cpu, data, size):
    try:
        data = b["events"].event(data)
        syscall = data.syscallnumber
        inum_ring = data.inum
        # if localpids.__contains__(str(pid)):
        host_pid_ns = 4026531836
        if str(inum_ring) == str(4026532486):
            # # print("Inside Container")
            if syscall == 0:
                # print("found clone inside the Container! with inum: " + str(inum_ring))
                syscall = "clone"
                patterns.append(syscall)
            elif syscall == 1:
                # print("found open inside the Container! with inum: " + str(inum_ring))
                syscall = "open"
                patterns.append(syscall)
            elif syscall == 2:
                # print("found read inside the Container! with inum: " + str(inum_ring))
                syscall = "read"
                patterns.append(syscall)
            elif syscall == 3:
                # print("found write inside the Container! with inum: " + str(inum_ring))
                syscall = "write"
                patterns.append(syscall)
            elif syscall == 4:
                # print("found close inside the Container! with inum: " + str(inum_ring))
                syscall = "close"
                patterns.append(syscall)
            elif syscall == 5:
                # print("found stat inside the Container! with inum: " + str(inum_ring))
                syscall = "stat"
                patterns.append(syscall)
            elif syscall == 6:
                # print("found fstat inside the Container! with inum: " + str(inum_ring))
                syscall = "fstat"
                patterns.append(syscall)
            elif syscall == 7:
                # print("found lstat inside the Container! with inum: " + str(inum_ring))
                syscall = "lstat"
                patterns.append(syscall)
            elif syscall == 8:
                # print("found poll inside the Container! with inum: " + str(inum_ring))
                syscall = "poll"
                patterns.append(syscall)
            elif syscall == 9:
                # print("found lseek inside the Container! with inum: " + str(inum_ring))
                syscall = "lseek"
                patterns.append(syscall)
            elif syscall == 10:
                # print("found mmap inside the Container! with inum: " + str(inum_ring))
                syscall = "mmap"
                patterns.append(syscall)
            elif syscall == 11:
                # print("found mprotect inside the Container! with inum: " + str(inum_ring))
                syscall = "mprotect"
                patterns.append(syscall)
            elif syscall == 12:
                # print("found munmap inside the Container! with inum: " + str(inum_ring))
                syscall = "munmap"
                patterns.append(syscall)
            elif syscall == 13:
                # print("found brk inside the Container! with inum: " + str(inum_ring))
                syscall = "brk"
                patterns.append(syscall)
            elif syscall == 14:
                # print("found rt_sigaction inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigaction"
                patterns.append(syscall)
            elif syscall == 14:
                # print("found rt_sigprocmask inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigprocmask"
                patterns.append(syscall)
            elif syscall == 15:
                # print("found rt_sigreturn inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigreturn"
                patterns.append(syscall)
            elif syscall == 16:
                # print("found rt_sigreturn inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigreturn"
                patterns.append(syscall)
            elif syscall == 17:
                # print("found ioctl inside the Container! with inum: " + str(inum_ring))
                syscall = "ioctl"
                patterns.append(syscall)
            elif syscall == 18:
                # print("found pread64 inside the Container! with inum: " + str(inum_ring))
                syscall = "pread64"
                patterns.append(syscall)
            elif syscall == 19:
                # print("found pwrite64 inside the Container! with inum: " + str(inum_ring))
                syscall = "pwrite64"
                patterns.append(syscall)
            elif syscall == 20:
                # print("found readv inside the Container! with inum: " + str(inum_ring))
                syscall = "readv"
                patterns.append(syscall)
            elif syscall == 21:
                # print("found writev inside the Container! with inum: " + str(inum_ring))
                syscall = "writev"
                patterns.append(syscall)
            elif syscall == 22:
                # print("found access inside the Container! with inum: " + str(inum_ring))
                syscall = "access"
                patterns.append(syscall)
            elif syscall == 23:
                # print("found pipe inside the Container! with inum: " + str(inum_ring))
                syscall = "pipe"
                patterns.append(syscall)
            elif syscall == 24:
                # print("found select inside the Container! with inum: " + str(inum_ring))
                syscall = "select"
                patterns.append(syscall)
            elif syscall == 25:
                # print("found mremap inside the Container! with inum: " + str(inum_ring))
                syscall = "mremap"
                patterns.append(syscall)
            elif syscall == 26:
                # print("found sched_yield inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_yield"
                patterns.append(syscall)
            elif syscall == 27:
                # print("found msync inside the Container! with inum: " + str(inum_ring))
                syscall = "msync"
                patterns.append(syscall)
            elif syscall == 28:
                # print("found mincore inside the Container! with inum: " + str(inum_ring))
                syscall = "mincore"
                patterns.append(syscall)
            elif syscall == 29:
                # print("found madvise inside the Container! with inum: " + str(inum_ring))
                syscall = "madvise"
                patterns.append(syscall)
            elif syscall == 30:
                # print("found shmget inside the Container! with inum: " + str(inum_ring))
                syscall = "shmget"
                patterns.append(syscall)
            elif syscall == 31:
                # print("found shmat inside the Container! with inum: " + str(inum_ring))
                syscall = "shmat"
                patterns.append(syscall)
            elif syscall == 32:
                # print("found shmctl inside the Container! with inum: " + str(inum_ring))
                syscall = "shmctl"
                patterns.append(syscall)
            elif syscall == 33:
                # print("found dup inside the Container! with inum: " + str(inum_ring))
                syscall = "dup"
                patterns.append(syscall)
            elif syscall == 34:
                # print("found dup2 inside the Container! with inum: " + str(inum_ring))
                syscall = "dup2"
                patterns.append(syscall)
            elif syscall == 35:
                # print("found pause inside the Container! with inum: " + str(inum_ring))
                syscall = "pause"
                patterns.append(syscall)
            elif syscall == 36:
                # print("found nanosleep inside the Container! with inum: " + str(inum_ring))
                syscall = "nanosleep"
                patterns.append(syscall)
            elif syscall == 37:
                # print("found getitimer inside the Container! with inum: " + str(inum_ring))
                syscall = "getitimer"
                patterns.append(syscall)
            elif syscall == 38:
                # print("found alarm inside the Container! with inum: " + str(inum_ring))
                syscall = "alarm"
                patterns.append(syscall)
            elif syscall == 39:
                # print("found setitimer inside the Container! with inum: " + str(inum_ring))
                syscall = "setitimer"
                patterns.append(syscall)
            elif syscall == 40:
                # print("found getpid inside the Container! with inum: " + str(inum_ring))
                syscall = "getpid"
                patterns.append(syscall)
            elif syscall == 41:
                # print("found senfile inside the Container! with inum: " + str(inum_ring))
                syscall = "sendfile"
                patterns.append(syscall)
            elif syscall == 42:
                # print("found socket inside the Container! with inum: " + str(inum_ring))
                syscall = "socket"
                patterns.append(syscall)
            elif syscall == 43:
                # print("found connect inside the Container! with inum: " + str(inum_ring))
                syscall = "connect"
                patterns.append(syscall)
            elif syscall == 44:
                # print("found accept inside the Container! with inum: " + str(inum_ring))
                syscall = "accept"
                patterns.append(syscall)
            elif syscall == 45:
                # print("found sendto inside the Container! with inum: " + str(inum_ring))
                syscall = "sendto"
                patterns.append(syscall)
            elif syscall == 46:
                # print("found recvfrom inside the Container! with inum: " + str(inum_ring))
                syscall = "recvfrom"
                patterns.append(syscall)
            elif syscall == 47:
                # print("found sendmsg inside the Container! with inum: " + str(inum_ring))
                syscall = "sendmsg"
                patterns.append(syscall)
            elif syscall == 48:
                # print("found recvmsg inside the Container! with inum: " + str(inum_ring))
                syscall = "recvmsg"
                patterns.append(syscall)
            elif syscall == 49:
                # print("found shutdown inside the Container! with inum: " + str(inum_ring))
                syscall = "shutdown"
                patterns.append(syscall)
            elif syscall == 50:
                # print("found bind inside the Container! with inum: " + str(inum_ring))
                syscall = "bind"
                patterns.append(syscall)
            elif syscall == 51:
                # print("found listen inside the Container! with inum: " + str(inum_ring))
                syscall = "listen"
                patterns.append(syscall)
            elif syscall == 52:
                # print("found getsockname inside the Container! with inum: " + str(inum_ring))
                syscall = "getsockname"
                patterns.append(syscall)
            elif syscall == 53:
                # print("found getpeername inside the Container! with inum: " + str(inum_ring))
                syscall = "getpername"
                patterns.append(syscall)
            elif syscall == 54:
                # print("found socketpair inside the Container! with inum: " + str(inum_ring))
                syscall = "socketpair"
                patterns.append(syscall)
            elif syscall == 55:
                # print("found setsockopt inside the Container! with inum: " + str(inum_ring))
                syscall = "setsockopt"
                patterns.append(syscall)
            elif syscall == 56:
                # print("found getsockopt inside the Container! with inum: " + str(inum_ring))
                syscall = "getsockopt"
                patterns.append(syscall)
            elif syscall == 57:
                # print("found fork inside the Container! with inum: " + str(inum_ring))
                syscall = "fork"
                patterns.append(syscall)
            elif syscall == 58:
                # print("found vfork inside the Container! with inum: " + str(inum_ring))
                syscall = "vfork"
                patterns.append(syscall)
            elif syscall == 59:
                # print("found execve inside the Container! with inum: " + str(inum_ring))
                syscall = "execve"
                patterns.append(syscall)
            elif syscall == 60:
                # print("found exit inside the Container! with inum: " + str(inum_ring))
                syscall = "exit"
                patterns.append(syscall)
            elif syscall == 61:
                # print("found wait4 inside the Container! with inum: " + str(inum_ring))
                syscall = "wait4"
                patterns.append(syscall)
            elif syscall == 62:
                # print("found kill inside the Container! with inum: " + str(inum_ring))
                syscall = "kill"
                patterns.append(syscall)
            elif syscall == 63:
                # print("found uname inside the Container! with inum: " + str(inum_ring))
                syscall = "uname"
                patterns.append(syscall)
            elif syscall == 64:
                # print("found semget inside the Container! with inum: " + str(inum_ring))
                syscall = "semget"
                patterns.append(syscall)
            elif syscall == 65:
                # print("found semop inside the Container! with inum: " + str(inum_ring))
                syscall = "semop"
                patterns.append(syscall)
            elif syscall == 66:
                # print("found semctl inside the Container! with inum: " + str(inum_ring))
                syscall = "semctl"
                patterns.append(syscall)
            elif syscall == 67:
                # print("found shmdt inside the Container! with inum: " + str(inum_ring))
                syscall = "shmdt"
                patterns.append(syscall)
            elif syscall == 68:
                # print("found msgget inside the Container! with inum: " + str(inum_ring))
                syscall = "msgget"
                patterns.append(syscall)
            elif syscall == 69:
                # print("found msgsnd inside the Container! with inum: " + str(inum_ring))
                syscall = "exit"
                patterns.append(syscall)
            elif syscall == 70:
                # print("found msgrcv inside the Container! with inum: " + str(inum_ring))
                syscall = "msgrcv"
                patterns.append(syscall)
            elif syscall == 71:
                # print("found msgctl inside the Container! with inum: " + str(inum_ring))
                syscall = "msgctl"
                patterns.append(syscall)
            elif syscall == 72:
                # print("found fcntl inside the Container! with inum: " + str(inum_ring))
                syscall = "fcntl"
                patterns.append(syscall)
            elif syscall == 73:
                # print("found flock inside the Container! with inum: " + str(inum_ring))
                syscall = "flock"
                patterns.append(syscall)
            elif syscall == 74:
                # print("found fsync inside the Container! with inum: " + str(inum_ring))
                syscall = "fsync"
                patterns.append(syscall)
            elif syscall == 75:
                # print("found fdatasync inside the Container! with inum: " + str(inum_ring))
                syscall = "fdatasync"
                patterns.append(syscall)
            elif syscall == 76:
                # print("found truncate inside the Container! with inum: " + str(inum_ring))
                syscall = "truncate"
                patterns.append(syscall)
            elif syscall == 77:
                # print("found ftruncate inside the Container! with inum: " + str(inum_ring))
                syscall = "ftruncate"
                patterns.append(syscall)
            elif syscall == 78:
                # print("found getdents inside the Container! with inum: " + str(inum_ring))
                syscall = "getdents"
                patterns.append(syscall)
            elif syscall == 79:
                # print("found getcwd inside the Container! with inum: " + str(inum_ring))
                syscall = "getcwd"
                patterns.append(syscall)
            elif syscall == 80:
                # print("found chdir inside the Container! with inum: " + str(inum_ring))
                syscall = "chdir"
                patterns.append(syscall)
            elif syscall == 81:
                # print("found fchdir inside the Container! with inum: " + str(inum_ring))
                syscall = "fchdir"
                patterns.append(syscall)
            elif syscall == 82:
                # print("found rename inside the Container! with inum: " + str(inum_ring))
                syscall = "rename"
                patterns.append(syscall)
            elif syscall == 83:
                # print("found mkdir inside the Container! with inum: " + str(inum_ring))
                syscall = "mkdir"
                patterns.append(syscall)
            elif syscall == 84:
                # print("found rmdir inside the Container! with inum: " + str(inum_ring))
                syscall = "rmdir"
                patterns.append(syscall)
            elif syscall == 85:
                # print("found creat inside the Container! with inum: " + str(inum_ring))
                syscall = "creat"
                patterns.append(syscall)
            elif syscall == 86:
                # print("found link inside the Container! with inum: " + str(inum_ring))
                syscall = "link"
                patterns.append(syscall)
            elif syscall == 87:
                # print("found unlink inside the Container! with inum: " + str(inum_ring))
                syscall = "unlink"
                patterns.append(syscall)
            elif syscall == 88:
                # print("found symlink inside the Container! with inum: " + str(inum_ring))
                syscall = "symlink"
                patterns.append(syscall)
            elif syscall == 89:
                # print("found readlink inside the Container! with inum: " + str(inum_ring))
                syscall = "readlink"
                patterns.append(syscall)
            elif syscall == 90:
                # print("found chmod inside the Container! with inum: " + str(inum_ring))
                syscall = "chmod"
                patterns.append(syscall)
            elif syscall == 91:
                # print("found fchmod inside the Container! with inum: " + str(inum_ring))
                syscall = "fchmod"
                patterns.append(syscall)
            elif syscall == 92:
                # print("found chown inside the Container! with inum: " + str(inum_ring))
                syscall = "chown"
                patterns.append(syscall)
            elif syscall == 93:
                # print("found fchown inside the Container! with inum: " + str(inum_ring))
                syscall = "fchown"
                patterns.append(syscall)
            elif syscall == 94:
                # print("found lchown inside the Container! with inum: " + str(inum_ring))
                syscall = "lchown"
                patterns.append(syscall)
            elif syscall == 95:
                # print("found umask inside the Container! with inum: " + str(inum_ring))
                syscall = "umask"
                patterns.append(syscall)
            elif syscall == 96:
                # print("found gettimeofday inside the Container! with inum: " + str(inum_ring))
                syscall = "gettimeofday"
                patterns.append(syscall)
            elif syscall == 97:
                # print("found getrlimit inside the Container! with inum: " + str(inum_ring))
                syscall = "getrlimit"
                patterns.append(syscall)
            elif syscall == 98:
                # print("found getrusage inside the Container! with inum: " + str(inum_ring))
                syscall = "getrusage"
                patterns.append(syscall)
            elif syscall == 99:
                # print("found sysinfo inside the Container! with inum: " + str(inum_ring))
                syscall = "chown"
                patterns.append(syscall)
            elif syscall == 100:
                # print("found times inside the Container! with inum: " + str(inum_ring))
                syscall = "times"
                patterns.append(syscall)
            elif syscall == 101:
                # print("found ptrace inside the Container! with inum: " + str(inum_ring))
                syscall = "ptrace"
                patterns.append(syscall)
            elif syscall == 102:
                # print("found getuid inside the Container! with inum: " + str(inum_ring))
                syscall = "getuid"
                patterns.append(syscall)
            elif syscall == 103:
                # print("found syslog inside the Container! with inum: " + str(inum_ring))
                syscall = "syslog"
                patterns.append(syscall)
            elif syscall == 104:
                # print("found getgid inside the Container! with inum: " + str(inum_ring))
                syscall = "getgid"
                patterns.append(syscall)
            elif syscall == 105:
                # print("found setuid inside the Container! with inum: " + str(inum_ring))
                syscall = "setuid"
                patterns.append(syscall)
            elif syscall == 106:
                # print("found setgid inside the Container! with inum: " + str(inum_ring))
                syscall = "setgid"
                patterns.append(syscall)
            elif syscall == 107:
                # print("found geteuid inside the Container! with inum: " + str(inum_ring))
                syscall = "geteuid"
                patterns.append(syscall)
            elif syscall == 108:
                # print("found getegid inside the Container! with inum: " + str(inum_ring))
                syscall = "getegid"
                patterns.append(syscall)
            elif syscall == 109:
                # print("found setpgid inside the Container! with inum: " + str(inum_ring))
                syscall = "setpgid"
                patterns.append(syscall)
            elif syscall == 110:
                # print("found getppid inside the Container! with inum: " + str(inum_ring))
                syscall = "getppid"
                patterns.append(syscall)
            elif syscall == 111:
                # print("found getpgrp inside the Container! with inum: " + str(inum_ring))
                syscall = "getpgrp"
                patterns.append(syscall)
            elif syscall == 112:
                # print("found setsid inside the Container! with inum: " + str(inum_ring))
                syscall = "setsid"
                patterns.append(syscall)
            elif syscall == 113:
                # print("found setreuid inside the Container! with inum: " + str(inum_ring))
                syscall = "setreuid"
                patterns.append(syscall)
            elif syscall == 114:
                # print("found setregid inside the Container! with inum: " + str(inum_ring))
                syscall = "setregid"
                patterns.append(syscall)
            elif syscall == 115:
                # print("found getgroups inside the Container! with inum: " + str(inum_ring))
                syscall = "getgroups"
                patterns.append(syscall)
            elif syscall == 116:
                # print("found setgroups inside the Container! with inum: " + str(inum_ring))
                syscall = "setgroups"
                patterns.append(syscall)
            elif syscall == 117:
                # print("found setresuid inside the Container! with inum: " + str(inum_ring))
                syscall = "setresuid"
                patterns.append(syscall)
            elif syscall == 118:
                # print("found getresuid inside the Container! with inum: " + str(inum_ring))
                syscall = "getresuid"
                patterns.append(syscall)
            elif syscall == 119:
                # print("found setresgid inside the Container! with inum: " + str(inum_ring))
                syscall = "setresgid"
                patterns.append(syscall)
            elif syscall == 120:
                # print("found getresgid inside the Container! with inum: " + str(inum_ring))
                syscall = "getresgid"
                patterns.append(syscall)
            elif syscall == 121:
                # print("found getpgid inside the Container! with inum: " + str(inum_ring))
                syscall = "getpgid"
                patterns.append(syscall)
            elif syscall == 122:
                # print("found setfsuid inside the Container! with inum: " + str(inum_ring))
                syscall = "setfsuid"
                patterns.append(syscall)
            elif syscall == 123:
                # print("found setfsgid inside the Container! with inum: " + str(inum_ring))
                syscall = "setfsgid"
                patterns.append(syscall)
            elif syscall == 124:
                # print("found getsid inside the Container! with inum: " + str(inum_ring))
                syscall = "getsid"
                patterns.append(syscall)
            elif syscall == 125:
                # print("found capget inside the Container! with inum: " + str(inum_ring))
                syscall = "capget"
                patterns.append(syscall)
            elif syscall == 126:
                # print("found capset inside the Container! with inum: " + str(inum_ring))
                syscall = "capset"
                patterns.append(syscall)
            elif syscall == 127:
                # print("found rt_sigpending inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigpending"
                patterns.append(syscall)
                #    occurences['rt_sigpending']))
            elif syscall == 128:
                # print("found rt_sigtimedwait inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigtimedwait"
                patterns.append(syscall)
            elif syscall == 129:
                # print("found rt_sigqueueinfo inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigqueueinfo"
                patterns.append(syscall)
            elif syscall == 130:
                # print("found rt_sigsuspend inside the Container! with inum: " + str(inum_ring))
                syscall = "rt_sigsuspend"
                patterns.append(syscall)
            elif syscall == 131:
                # print("found sigaltstack inside the Container! with inum: " + str(inum_ring))
                syscall = "sigaltstack"
                patterns.append(syscall)
            elif syscall == 132:
                # print("found utime inside the Container! with inum: " + str(inum_ring))
                syscall = "utime"
                patterns.append(syscall)
            elif syscall == 133:
                # print("found mknod inside the Container! with inum: " + str(inum_ring))
                syscall = "mknod"
                patterns.append(syscall)
            elif syscall == 134:
                # print("found uselib inside the Container! with inum: " + str(inum_ring))
                syscall = "uselib"
                patterns.append(syscall)
            elif syscall == 135:
                # print("found personality inside the Container! with inum: " + str(inum_ring))
                syscall = "personality"
                patterns.append(syscall)
            elif syscall == 136:
                # print("found ustat inside the Container! with inum: " + str(inum_ring))
                syscall = "ustat"
                patterns.append(syscall)
            elif syscall == 137:
                # print("found statfs inside the Container! with inum: " + str(inum_ring))
                syscall = "statfs"
                patterns.append(syscall)
            elif syscall == 138:
                # print("found fstatfs inside the Container! with inum: " + str(inum_ring))
                syscall = "fstatfs"
                patterns.append(syscall)
            elif syscall == 139:
                # print("found sysfs inside the Container! with inum: " + str(inum_ring))
                syscall = "sysfs"
                patterns.append(syscall)
            elif syscall == 140:
                # print("found getpriority inside the Container! with inum: " + str(inum_ring))
                syscall = "getpriority"
                patterns.append(syscall)
            elif syscall == 141:
                # print("found setpriority inside the Container! with inum: " + str(inum_ring))
                syscall = "setpriority"
                patterns.append(syscall)
            elif syscall == 142:
                # print("found sched_setparam inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_setparam"
                patterns.append(syscall)
            elif syscall == 143:
                # print("found sched_getparam inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_getparam"
                patterns.append(syscall)
            elif syscall == 144:
                # print("found sched_setscheduler inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_setscheduler"
                patterns.append(syscall)
            elif syscall == 145:
                # print("found sched_getscheduler inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_getscheduler"
                patterns.append(syscall)
            elif syscall == 146:
                # print("found sched_get_priority_max inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_get_priority_max"
                patterns.append(syscall)
            elif syscall == 147:
                # print("found sched_get_priority_min inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_get_priority_min"
                patterns.append(syscall)
            elif syscall == 148:
                # print("found sched_rr_get_interval inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_rr_get_interval"
                patterns.append(syscall)
            elif syscall == 149:
                # print("found mlock inside the Container! with inum: " + str(inum_ring))
                syscall = "mlock"
                patterns.append(syscall)
            elif syscall == 150:
                # print("found munlock inside the Container! with inum: " + str(inum_ring))
                syscall = "munlock"
                patterns.append(syscall)
            elif syscall == 151:
                # print("found mlockall inside the Container! with inum: " + str(inum_ring))
                syscall = "mlockall"
                patterns.append(syscall)
            elif syscall == 152:
                # print("found munlockall inside the Container! with inum: " + str(inum_ring))
                syscall = "munlockall"
                patterns.append(syscall)
            elif syscall == 153:
                # print("found vhangup inside the Container! with inum: " + str(inum_ring))
                syscall = "vhangup"
                patterns.append(syscall)
            elif syscall == 154:
                # print("found modify_ldt inside the Container! with inum: " + str(inum_ring))
                syscall = "modify_ldt"
                patterns.append(syscall)
            elif syscall == 155:
                # print("found pivot_root inside the Container! with inum: " + str(inum_ring))
                syscall = "pivot_root"
                patterns.append(syscall)
            elif syscall == 156:
                # print("found sysctl inside the Container! with inum: " + str(inum_ring))
                syscall = "sysctl"
                patterns.append(syscall)
            elif syscall == 157:
                # print("found prctl inside the Container! with inum: " + str(inum_ring))
                syscall = "prctl"
                patterns.append(syscall)
            elif syscall == 158:
                # print("found arch_prctl inside the Container! with inum: " + str(inum_ring))
                syscall = "arch_prctl"
                patterns.append(syscall)
            elif syscall == 159:
                # print("found adjtimex inside the Container! with inum: " + str(inum_ring))
                syscall = "adjtimex"
                patterns.append(syscall)
            elif syscall == 160:
                # print("found setrlimit inside the Container! with inum: " + str(inum_ring))
                syscall = "setrlimit"
                patterns.append(syscall)
            elif syscall == 161:
                # print("found chroot inside the Container! with inum: " + str(inum_ring))
                syscall = "chroot"
                patterns.append(syscall)
            elif syscall == 162:
                # print("found sync inside the Container! with inum: " + str(inum_ring))
                syscall = "sync"
                patterns.append(syscall)
            elif syscall == 163:
                # print("found acct inside the Container! with inum: " + str(inum_ring))
                syscall = "acct"
                patterns.append(syscall)
            elif syscall == 164:
                # print("found settimeofday inside the Container! with inum: " + str(inum_ring))
                syscall = "settimeofday"
                patterns.append(syscall)
            elif syscall == 165:
                # print("found mount inside the Container! with inum: " + str(inum_ring))
                syscall = "mount"
                patterns.append(syscall)
            elif syscall == 166:
                # print("found umount2 inside the Container! with inum: " + str(inum_ring))
                syscall = "umount2"
                patterns.append(syscall)
            elif syscall == 167:
                # print("found swapon inside the Container! with inum: " + str(inum_ring))
                syscall = "swapon"
                patterns.append(syscall)
            elif syscall == 168:
                # print("found swapoff inside the Container! with inum: " + str(inum_ring))
                syscall = "swapoff"
                patterns.append(syscall)
            elif syscall == 169:
                # print("found reboot inside the Container! with inum: " + str(inum_ring))
                syscall = "reboot"
                patterns.append(syscall)
            elif syscall == 170:
                # print("found sethostname inside the Container! with inum: " + str(inum_ring))
                syscall = "setrlimit"
                patterns.append(syscall)
            elif syscall == 171:
                # print("found setdoaminname inside the Container! with inum: " + str(inum_ring))
                syscall = "setdomainname"
                patterns.append(syscall)
            elif syscall == 172:
                # print("found iopl inside the Container! with inum: " + str(inum_ring))
                syscall = "iopl"
                patterns.append(syscall)
            elif syscall == 173:
                # print("found ioperm inside the Container! with inum: " + str(inum_ring))
                syscall = "ioperm"
                patterns.append(syscall)
            elif syscall == 174:
                # print("found create_module inside the Container! with inum: " + str(inum_ring))
                syscall = "create_module"
                patterns.append(syscall)
            elif syscall == 175:
                # print("found init_module inside the Container! with inum: " + str(inum_ring))
                syscall = "init_module"
                patterns.append(syscall)
            elif syscall == 176:
                # print("found delete_module inside the Container! with inum: " + str(inum_ring))
                syscall = "delete_module"
                patterns.append(syscall)
            elif syscall == 177:
                # print("found get_kernel_syms inside the Container! with inum: " + str(inum_ring))
                syscall = "get_kernel_syms"
                patterns.append(syscall)
            elif syscall == 178:
                # print("found query_module inside the Container! with inum: " + str(inum_ring))
                syscall = "query_module"
                patterns.append(syscall)
            elif syscall == 179:
                # print("found quotactl inside the Container! with inum: " + str(inum_ring))
                syscall = "quotactl"
                patterns.append(syscall)
            elif syscall == 180:
                # print("found nfsservctl inside the Container! with inum: " + str(inum_ring))
                syscall = "nfsservctl"
                patterns.append(syscall)
            elif syscall == 181:
                # print("found getpmsg inside the Container! with inum: " + str(inum_ring))
                syscall = "getpmsg"
                patterns.append(syscall)
            elif syscall == 182:
                # print("found putpmsg inside the Container! with inum: " + str(inum_ring))
                syscall = "putpmsg"
                patterns.append(syscall)
            elif syscall == 183:
                # print("found afs_syscall inside the Container! with inum: " + str(inum_ring))
                syscall = "afs_syscall"
                patterns.append(syscall)
            elif syscall == 184:
                # print("found tuxcall inside the Container! with inum: " + str(inum_ring))
                syscall = "tuxcall"
                patterns.append(syscall)
            elif syscall == 185:
                # print("found security inside the Container! with inum: " + str(inum_ring))
                syscall = "security"
                patterns.append(syscall)
            elif syscall == 186:
                # print("found gettid inside the Container! with inum: " + str(inum_ring))
                syscall = "gettid"
                patterns.append(syscall)
            elif syscall == 187:
                # print("found readahead inside the Container! with inum: " + str(inum_ring))
                syscall = "readahead"
                patterns.append(syscall)
            elif syscall == 188:
                # print("found setxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "setxattr"
                patterns.append(syscall)
            elif syscall == 189:
                # print("found lsetxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "lsetxattr"
                patterns.append(syscall)
            elif syscall == 190:
                # print("found fsetxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "fsetxattr"
                patterns.append(syscall)
            elif syscall == 191:
                # print("found getxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "getxattr"
                patterns.append(syscall)
            elif syscall == 192:
                # print("found lgetxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "lgetxattr"
                patterns.append(syscall)
            elif syscall == 193:
                # print("found fgetxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "fgetxattr"
                patterns.append(syscall)
            elif syscall == 194:
                # print("found listxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "listxattr"
                patterns.append(syscall)
            elif syscall == 195:
                # print("found llistxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "llistxattr"
                patterns.append(syscall)
            elif syscall == 196:
                # print("found flistxattr inside the Container! with inum: " + str(inum_ring))
                syscall = "flistxattr"
                patterns.append(syscall)
            elif syscall == 197:
                # print("found removexattr inside the Container! with inum: " + str(inum_ring))
                syscall = "removexattr"
                patterns.append(syscall)
            elif syscall == 198:
                # print("found lremovexattr inside the Container! with inum: " + str(inum_ring))
                syscall = "lremovexattr"
                patterns.append(syscall)
            elif syscall == 199:
                # print("found fremovexattr inside the Container! with inum: " + str(inum_ring))
                syscall = "fremovexattr"
                patterns.append(syscall)
            elif syscall == 200:
                # print("found tkill inside the Container! with inum: " + str(inum_ring))
                syscall = "tkill"
                patterns.append(syscall)
            elif syscall == 201:
                # print("found time inside the Container! with inum: " + str(inum_ring))
                syscall = "time"
                patterns.append(syscall)
            elif syscall == 202:
                # print("found futex inside the Container! with inum: " + str(inum_ring))
                syscall = "futex"
                patterns.append(syscall)
            elif syscall == 203:
                # print("found sched_setaffinity inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_setaffinity"
                patterns.append(syscall)
            elif syscall == 204:
                # print("found sched_getaffinity inside the Container! with inum: " + str(inum_ring))
                syscall = "sched_getaffinity"
                patterns.append(syscall)
            elif syscall == 205:
                # print("found set_threat_area inside the Container! with inum: " + str(inum_ring))
                syscall = "set_threat_area"
                patterns.append(syscall)
            elif syscall == 206:
                # print("found io_setup inside the Container! with inum: " + str(inum_ring))
                syscall = "io_setup"
                patterns.append(syscall)
            elif syscall == 207:
                # print("found io_destroy inside the Container! with inum: " + str(inum_ring))
                syscall = "io_destroy"
                patterns.append(syscall)
            elif syscall == 208:
                # print("found io_getevents inside the Container! with inum: " + str(inum_ring))
                syscall = "io_getevents"
                patterns.append(syscall)
            elif syscall == 209:
                # print("found io_submit inside the Container! with inum: " + str(inum_ring))
                syscall = "io_submit"
                patterns.append(syscall)
            elif syscall == 210:
                # print("found io_cancel inside the Container! with inum: " + str(inum_ring))
                syscall = "io_cancel"
                patterns.append(syscall)
            elif syscall == 211:
                # print("found get_threat_area inside the Container! with inum: " + str(inum_ring))
                syscall = "get_threat_area"
                patterns.append(syscall)
            elif syscall == 212:
                # print("found lookup_dcookie inside the Container! with inum: " + str(inum_ring))
                syscall = "lookup_dcookie"
                patterns.append(syscall)
            elif syscall == 213:
                # print("found epoll_create inside the Container! with inum: " + str(inum_ring))
                syscall = "epoll_create"
                patterns.append(syscall)
            elif syscall == 214:
                # print("found epoll_ctl_old inside the Container! with inum: " + str(inum_ring))
                syscall = "epoll_ctl_old"
                patterns.append(syscall)
            elif syscall == 215:
                # print("found epoll_wait_old inside the Container! with inum: " + str(inum_ring))
                syscall = "epoll_wait_old"
                patterns.append(syscall)
            elif syscall == 216:
                # print("found remap_file_pages inside the Container! with inum: " + str(inum_ring))
                syscall = "remap_file_pages"
                patterns.append(syscall)
            elif syscall == 217:
                # print("found getdents64 inside the Container! with inum: " + str(inum_ring))
                syscall = "getdents64"
                patterns.append(syscall)
            elif syscall == 218:
                # print("found set_tid_address inside the Container! with inum: " + str(inum_ring))
                syscall = "set_tid_address"
                patterns.append(syscall)
            elif syscall == 219:
                # print("found restart_syscall inside the Container! with inum: " + str(inum_ring))
                syscall = "restart_syscall"
                patterns.append(syscall)
            elif syscall == 220:
                # print("found settimedop inside the Container! with inum: " + str(inum_ring))
                syscall = "settimedop"
                patterns.append(syscall)
            elif syscall == 221:
                # print("found fadvise64 inside the Container! with inum: " + str(inum_ring))
                syscall = "fadvice64"
                patterns.append(syscall)
            elif syscall == 222:
                # print("found timer_create inside the Container! with inum: " + str(inum_ring))
                syscall = "timer_create"
                patterns.append(syscall)
            elif syscall == 223:
                # print("found timer_settime inside the Container! with inum: " + str(inum_ring))
                syscall = "timer_settime"
                patterns.append(syscall)
            elif syscall == 224:
                # print("found timer_gettime inside the Container! with inum: " + str(inum_ring))
                syscall = "timer_gettime"
                patterns.append(syscall)
            elif syscall == 225:
                # print("found timer_getoverrun inside the Container! with inum: " + str(inum_ring))
                syscall = "timer_getoverrun"
                patterns.append(syscall)
            elif syscall == 226:
                # print("found timer_delete inside the Container! with inum: " + str(inum_ring))
                syscall = "timer_delete"
                patterns.append(syscall)
            elif syscall == 227:
                # print("found clock_settime inside the Container! with inum: " + str(inum_ring))
                syscall = "clock_settime"
                patterns.append(syscall)
            elif syscall == 228:
                # print("found clock_gettime inside the Container! with inum: " + str(inum_ring))
                syscall = "clock_gettime"
                patterns.append(syscall)
            elif syscall == 229:
                # print("found clock_getres inside the Container! with inum: " + str(inum_ring))
                syscall = "clock_getres"
                patterns.append(syscall)
            elif syscall == 230:
                # print("found clock_nanosleep inside the Container! with inum: " + str(inum_ring))
                syscall = "clock_nanosleep"
                patterns.append(syscall)
            elif syscall == 231:
                # print("found exit_group inside the Container! with inum: " + str(inum_ring))
                syscall = "exit_group"
                patterns.append(syscall)
            elif syscall == 232:
                # print("found epoll_wait inside the Container! with inum: " + str(inum_ring))
                syscall = "epoll_wait"
                patterns.append(syscall)
            elif syscall == 233:
                # print("found epoll_ctl inside the Container! with inum: " + str(inum_ring))
                syscall = "epoll_ctl"
                patterns.append(syscall)
            elif syscall == 234:
                # print("found tgkill inside the Container! with inum: " + str(inum_ring))
                syscall = "tgkill"
                patterns.append(syscall)
            elif syscall == 235:
                # print("found utimes inside the Container! with inum: " + str(inum_ring))
                syscall = "utimes"
                patterns.append(syscall)
            elif syscall == 236:
                # print("found vserver inside the Container! with inum: " + str(inum_ring))
                syscall = "vserver"
                patterns.append(syscall)
            elif syscall == 237:
                # print("found mbind inside the Container! with inum: " + str(inum_ring))
                syscall = "mbind"
                patterns.append(syscall)
            elif syscall == 238:
                # print("found set_mempolicy inside the Container! with inum: " + str(inum_ring))
                syscall = "set_mempolicy"
                patterns.append(syscall)
            elif syscall == 239:
                # print("found get_mempolicy inside the Container! with inum: " + str(inum_ring))
                syscall = "get_mempolicy"
                patterns.append(syscall)
            elif syscall == 240:
                # print("found mq_open inside the Container! with inum: " + str(inum_ring))
                syscall = "mq_open"
                patterns.append(syscall)
            elif syscall == 241:
                # print("found mq_unlink inside the Container! with inum: " + str(inum_ring))
                syscall = "mq_unlink"
                patterns.append(syscall)
            elif syscall == 242:
                # print("found mq_timedsend inside the Container! with inum: " + str(inum_ring))
                syscall = "mq_timedsend"
                patterns.append(syscall)
            elif syscall == 243:
                # print("found mq_timedreceive inside the Container! with inum: " + str(inum_ring))
                syscall = "mq_timedreceive"
                patterns.append(syscall)
            elif syscall == 244:
                # print("found mq_notify inside the Container! with inum: " + str(inum_ring))
                syscall = "mq_notify"
                patterns.append(syscall)
            elif syscall == 245:
                # print("found mq_getsetattr inside the Container! with inum: " + str(inum_ring))
                syscall = "mq_getsetattr"
                patterns.append(syscall)
            elif syscall == 246:
                # print("found kexec_load inside the Container! with inum: " + str(inum_ring))
                syscall = "kexec_load"
                patterns.append(syscall)
            elif syscall == 247:
                # print("found waitid inside the Container! with inum: " + str(inum_ring))
                syscall = "waitid"
                patterns.append(syscall)
            elif syscall == 248:
                # print("found add_key inside the Container! with inum: " + str(inum_ring))
                syscall = "add_key"
                patterns.append(syscall)
            elif syscall == 249:
                # print("found request_key inside the Container! with inum: " + str(inum_ring))
                syscall = "request_key"
                patterns.append(syscall)
            elif syscall == 250:
                # print("found keyctl inside the Container! with inum: " + str(inum_ring))
                syscall = "keyctl"
                patterns.append(syscall)
            elif syscall == 251:
                # print("found ioprio_set inside the Container! with inum: " + str(inum_ring))
                syscall = "ioprio_set"
                patterns.append(syscall)
            elif syscall == 252:
                # print("found ioprio_get inside the Container! with inum: " + str(inum_ring))
                syscall = "ioprio_get"
                patterns.append(syscall)
            elif syscall == 253:
                # print("found inotify_init inside the Container! with inum: " + str(inum_ring))
                syscall = "inotify_init"
                patterns.append(syscall)
            elif syscall == 254:
                # print("found inotify_add_watch inside the Container! with inum: " + str(inum_ring))
                syscall = "inotify_add_watch"
                patterns.append(syscall)
            elif syscall == 255:
                # print("found inotify_rm_watch inside the Container! with inum: " + str(inum_ring))
                syscall = "inotify_rm_watch"
                patterns.append(syscall)
            elif syscall == 256:
                # print("found migrate_pages inside the Container! with inum: " + str(inum_ring))
                syscall = "migrate_pages"
                patterns.append(syscall)
            elif syscall == 257:
                # print("found openat inside the Container! with inum: " + str(inum_ring))
                syscall = "openat"
                patterns.append(syscall)
            elif syscall == 258:
                # print("found mkdirat inside the Container! with inum: " + str(inum_ring))
                syscall = "mkdirat"
                patterns.append(syscall)
            elif syscall == 259:
                # print("found mknodat inside the Container! with inum: " + str(inum_ring))
                syscall = "mknodat"
                patterns.append(syscall)
            elif syscall == 260:
                # print("found fchownat inside the Container! with inum: " + str(inum_ring))
                syscall = "fchownat"
                patterns.append(syscall)
            elif syscall == 261:
                # print("found futimesat inside the Container! with inum: " + str(inum_ring))
                syscall = "futimesat"
                patterns.append(syscall)
            elif syscall == 262:
                # print("found newfstat inside the Container! with inum: " + str(inum_ring))
                syscall = "newfstat"
                patterns.append(syscall)
            elif syscall == 263:
                # print("found unlinkat inside the Container! with inum: " + str(inum_ring))
                syscall = "unlinkat"
                patterns.append(syscall)
            elif syscall == 264:
                # print("found renameat inside the Container! with inum: " + str(inum_ring))
                syscall = "renameat"
                patterns.append(syscall)
            elif syscall == 265:
                # print("found linkat inside the Container! with inum: " + str(inum_ring))
                syscall = "linkat"
                patterns.append(syscall)
            elif syscall == 266:
                # print("found symlinkat inside the Container! with inum: " + str(inum_ring))
                syscall = "symlinkat"
                patterns.append(syscall)
            elif syscall == 267:
                # print("found readlinkat inside the Container! with inum: " + str(inum_ring))
                syscall = "readlinkat"
                patterns.append(syscall)
            elif syscall == 268:
                # print("found fchmodat inside the Container! with inum: " + str(inum_ring))
                syscall = "fchmodat"
                patterns.append(syscall)
            elif syscall == 269:
                # print("found faccsessat inside the Container! with inum: " + str(inum_ring))
                syscall = "faccsessat"
                patterns.append(syscall)
            elif syscall == 270:
                # print("found pselect6 inside the Container! with inum: " + str(inum_ring))
                syscall = "pselect69"
                patterns.append(syscall)
            elif syscall == 271:
                # print("found ppoll inside the Container! with inum: " + str(inum_ring))
                syscall = "ppoll"
                patterns.append(syscall)
            elif syscall == 272:
                # print("found unshare inside the Container! with inum: " + str(inum_ring))
                syscall = "unshare"
                patterns.append(syscall)
            elif syscall == 273:
                # print("found set_robust_list inside the Container! with inum: " + str(inum_ring))
                syscall = "set_robust_list"
                patterns.append(syscall)
            elif syscall == 274:
                # print("found get_robust_list inside the Container! with inum: " + str(inum_ring))
                syscall = "get_robust_list"
                patterns.append(syscall)
            elif syscall == 275:
                # print("found splice inside the Container! with inum: " + str(inum_ring))
                syscall = "splice"
                patterns.append(syscall)
            elif syscall == 276:
                # print("found tee inside the Container! with inum: " + str(inum_ring))
                syscall = "tee"
                patterns.append(syscall)
            elif syscall == 277:
                # print("found sync_file_range inside the Container! with inum: " + str(inum_ring))
                syscall = "sync_file_range"
                patterns.append(syscall)
            elif syscall == 278:
                # print("found vmsplice inside the Container! with inum: " + str(inum_ring))
                syscall = "vmsplice"
                patterns.append(syscall)
            elif syscall == 279:
                # print("found move_pages inside the Container! with inum: " + str(inum_ring))
                syscall = "move_pages"
                patterns.append(syscall)
            elif syscall == 280:
                # print("found utimensat inside the Container! with inum: " + str(inum_ring))
                syscall = "utimensat"
                patterns.append(syscall)
                x=0
            # elif syscall == 281:
            #     occurences['epoll_pwait'] = occurences['epoll_pwait'] + 1
            #     # print(
            #     #     "Update für folgenden System Call: epoll_pwait. Neue Häufigkeit: " + str(occurences['epoll_pwait']))
            # elif syscall == 282:
            #     occurences['signalfd'] = occurences['signalfd'] + 1
            #     # print("Update für folgenden System Call signalfd. Neue Häufigkeit: " + str(occurences['utimensat']))
            # elif syscall == 283:
            #     occurences['timerfd_create'] = occurences['timerfd_create'] + 1
            #     # print("Update für folgenden System Call timerfd_create. Neue Häufigkeit: " + str(
            #     #    occurences['timerfd_create']))
            # elif syscall == 284:
            #     occurences['eventfd'] = occurences['eventfd'] + 1
            #     # print("Update für folgenden System Call eventfd. Neue Häufigkeit: " + str(occurences['eventfd']))
            # elif syscall == 285:
            #     occurences['fallocate'] = occurences['fallocate'] + 1
            #     # print("Update für folgenden System Call fallocate. Neue Häufigkeit: " + str(occurences['fallocate']))
            # elif syscall == 286:
            #     occurences['timerfd_settime'] = occurences['timerfd_settime'] + 1
            #     # print("Update für folgenden System Call timerfd_settime. Neue Häufigkeit: " + str(
            #     #    occurences['timerfd_settime']))
            # elif syscall == 287:
            #     occurences['timerfd_gettime'] = occurences['timerfd_gettime'] + 1
            #     # print("Update für folgenden System Call timerfd_gettime. Neue Häufigkeit: " + str(
            #     #    occurences['timerfd_gettime']))
            # elif syscall == 288:
            #     occurences['accept4'] = occurences['accept4'] + 1
            #     # print("Update für folgenden System Call accept4. Neue Häufigkeit: " + str(occurences['accept4']))
            # elif syscall == 289:
            #     occurences['signalfd4'] = occurences['signalfd4'] + 1
            #     # print("Update für folgenden System Call signalfd4. Neue Häufigkeit: " + str(occurences['signalfd4']))
            # elif syscall == 290:
            #     occurences['eventfd2'] = occurences['eventfd2'] + 1
            #     # print("Update für folgenden System Call eventfd2. Neue Häufigkeit: " + str(occurences['eventfd2']))
            # elif syscall == 291:
            #     occurences['epoll_create1'] = occurences['epoll_create1'] + 1
            #     # print("Update für folgenden System Call epoll_create1. Neue Häufigkeit: " + str(
            #     #    occurences['epoll_create1']))
            # elif syscall == 292:
            #     occurences['dup3'] = occurences['dup3'] + 1
            #     # print("Update für folgenden System Call dup3. Neue Häufigkeit: " + str(occurences['eventfd2']))
            # elif syscall == 293:
            #     occurences['pipe2'] = occurences['pipe2'] + 1
            #     # print("Update für folgenden System Call pipe2. Neue Häufigkeit: " + str(occurences['pipe2']))
            # elif syscall == 294:
            #     occurences['inotify_init1'] = occurences['inotify_init1'] + 1
            #     # print("Update für folgenden System Call inotify_init1. Neue Häufigkeit: " + str(
            #     #    occurences['inotify_init1']))
            # elif syscall == 295:
            #     occurences['preadv'] = occurences['preadv'] + 1
            #     # print("Update für folgenden System Call preadv. Neue Häufigkeit: " + str(occurences['preadv']))
            # elif syscall == 296:
            #     occurences['pwritev'] = occurences['pwritev'] + 1
            #     # print("Update für folgenden System Call pwritev. Neue Häufigkeit: " + str(occurences['pwritev']))
            # elif syscall == 297:
            #     occurences['rt_tgsigqueueinfo'] = occurences['rt_tgsigqueueinfo'] + 1
            #     # print("Update für folgenden System Call rt_tgsigqueueinfo. Neue Häufigkeit: " + str(
            #     #    occurences['rt_tgsigqueueinfo']))
            # elif syscall == 298:
            #     occurences['perf_event_open'] = occurences['perf_event_open'] + 1
            #     # print("Update für folgenden System Call perf_event_open. Neue Häufigkeit: " + str(
            #     #    occurences['perf_event_open']))
            # elif syscall == 299:
            #     occurences['recvmmsg'] = occurences['recvmmsg'] + 1
            #     # print("Update für folgenden System Call recvmmsg. Neue Häufigkeit: " + str(occurences['recvmmsg']))
            # elif syscall == 300:
            #     occurences['fanotify_init'] = occurences['fanotify_init'] + 1
            #     # print("Update für folgenden System Call fanotify_init. Neue Häufigkeit: " + str(
            #     #    occurences['fanotify_init']))
            # elif syscall == 301:
            #     occurences['fanotify_mark'] = occurences['fanotify_mark'] + 1
            #     # print("Update für folgenden System Call fanotify_mark. Neue Häufigkeit: " + str(
            #     #    occurences['fanotify_mark']))
            # elif syscall == 302:
            #     occurences['prlimit64'] = occurences['prlimit64'] + 1
            #     # print("Update für folgenden System Call prlimit64. Neue Häufigkeit: " + str(occurences['prlimit64']))
            # elif syscall == 303:
            #     occurences['name_to_handle_at'] = occurences['name_to_handle_at'] + 1
            #     # print("Update für folgenden System Call name_to_handle_at. Neue Häufigkeit: " + str(
            #     #    occurences['name_to_handle_at']))
            # elif syscall == 304:
            #     occurences['open_by_handle_at'] = occurences['open_by_handle_at'] + 1
            #     # print("Update für folgenden System Call open_by_handle_at. Neue Häufigkeit: " + str(
            #     #    occurences['open_by_handle_at']))
            # elif syscall == 305:
            #     occurences['clock_adjtime'] = occurences['clock_adjtime'] + 1
            #     # print("Update für folgenden System Call clock_adjtime. Neue Häufigkeit: " + str(
            #     #    occurences['clock_adjtime']))
            # elif syscall == 306:
            #     occurences['syncfs'] = occurences['syncfs'] + 1
            #     # print("Update für folgenden System Call syncfs. Neue Häufigkeit: " + str(occurences['syncfs']))
            # elif syscall == 307:
            #     occurences['sendmmsg'] = occurences['sendmmsg'] + 1
            #     # print("Update für folgenden System Call sendmmsg. Neue Häufigkeit: " + str(occurences['sendmmsg']))
            # elif syscall == 308:
            #     occurences['setns'] = occurences['setns'] + 1
            #     # print("Update für folgenden System Call setns. Neue Häufigkeit: " + str(occurences['setns']))
            # elif syscall == 309:
            #     occurences['getcpu'] = occurences['getcpu'] + 1
            #     # print("Update für folgenden System Call getcpu. Neue Häufigkeit: " + str(occurences['getcpu']))
            # elif syscall == 310:
            #     occurences['process_vm_readv'] = occurences['process_vm_readv'] + 1
            #     # print("Update für folgenden System Call process_vm_readv. Neue Häufigkeit: " + str(
            #     #    occurences['process_vm_readv']))
            # elif syscall == 311:
            #     occurences['process_vm_writev'] = occurences['process_vm_writev'] + 1
            #     # print("Update für folgenden System Call process_vm_writev. Neue Häufigkeit: " + str(
            #     #    occurences['process_vm_writev']))
            # elif syscall == 312:
            #     occurences['kcmp'] = occurences['kcmp'] + 1
            #     # print("Update für folgenden System Call kcmp. Neue Häufigkeit: " + str(occurences['kcmp']))
            # elif syscall == 313:
            #     occurences['finit_module'] = occurences['finit_module'] + 1
            #     # print("Update für folgenden System Call finit_module. Neue Häufigkeit: " + str(
            #     #    occurences['finit_module']))
            # elif syscall == 314:
            #     occurences['sched_setattr'] = occurences['sched_setattr'] + 1
            #     # print("Update für folgenden System Call sched_setattr. Neue Häufigkeit: " + str(
            #     #    occurences['sched_setattr']))
            # elif syscall == 315:
            #     occurences['sched_getattr'] = occurences['sched_getattr'] + 1
            #     # print("Update für folgenden System Call sched_getattr. Neue Häufigkeit: " + str(
            #     #    occurences['sched_getattr']))
            # elif syscall == 316:
            #     occurences['renameat2'] = occurences['renameat2'] + 1
            #     # print("Update für folgenden System Call renameat2. Neue Häufigkeit: " + str(occurences['renameat2']))
            # elif syscall == 317:
            #     occurences['seccomp'] = occurences['seccomp'] + 1
            #     # print("Update für folgenden System Call seccomp. Neue Häufigkeit: " + str(occurences['seccomp']))
            # elif syscall == 318:
            #     occurences['getrandom'] = occurences['getrandom'] + 1
            #     # print("Update für folgenden System Call getrandom. Neue Häufigkeit: " + str(occurences['getrandom']))
            # elif syscall == 319:
            #     occurences['memfd_create'] = occurences['memfd_create'] + 1
            #     # print("Update für folgenden System Call memfd_create. Neue Häufigkeit: " + str(
            #     #    occurences['memfd_create']))
            # elif syscall == 320:
            #     occurences['kexec_file_load'] = occurences['kexec_file_load'] + 1
            #     # print("Update für folgenden System Call kexec_file_load. Neue Häufigkeit: " + str(
            #     #    occurences['kexec_file_load']))
            # elif syscall == 321:
            #     occurences['bpf'] = occurences['bpf'] + 1
            # print("Update für folgenden System Call bpf. Neue Häufigkeit: " + str(occurences['process_vm_readv']))
            # else:
            #     print("found gettimeofdate inside the Container! with PID: " + str(pid) + " and cgroup_id: " + str(
            #         cgroup) + " and inum: " + str(
            #         inum_ring))
            #     syscall = "gettimeofday"
            #     patterns.append(syscall)
        # elif syscall == 1:
        #     print("found read! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup))
        #     syscall = "read"
        #     patterns.append(syscall)
        # elif syscall == 2:
        #     print("found write! with PID: " + str(pid) + " and cgroup_id: " + str(cgroup))
        #     syscall = "write"
        #     patterns.append(syscall)

        # elif syscall == 1:
        #     print("found read!")
    except KeyboardInterrupt:
        getprobability()
        print(patterns)
        signal_handler(signal.SIGINT, signal_handler)



def getringbuffer():
    b["events"].open_perf_buffer(detectpatterns, page_cnt=256)
    while True:
        try:
            b.perf_buffer_poll(timeout=10 * 1000)
        except KeyboardInterrupt:
            getprobability()
            print(patterns)
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


# def getinum():
#     # Führe den Befehl aus und lese die Ausgabe
#     result = os.popen("ls -la /proc/self/ns").read()
#
#     # Splitten der Ausgabe an den Leerzeichen
#     # Beispiel-Ausgabe: "total 0\nlrwxrwxrwx 1 user user 0 Apr 20 10:00 pid -> 'pid:[4026531836]'\n"
#     parts = result.split(" ")
#
#     # Suche nach der Zeichenkette "'pid:[...]'"
#     pid_ns_id = None
#     for part in parts:
#         if part.__contains__("pid:["):  # and part.endswith("]'\n"):
#             # Extrahiere die ID aus der Zeichenkette
#             pid_ns_id = part[5:-12]
#             break
#     # print("PID-Namespace ID des Host Systems:", pid_ns_id)
#     return pid_ns_id


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
# ibinary = input("Input Binary: ")
# localpids = getpids(ibinary)
print("attaching to kretprobes")
attachkretprobe()
print("attachment ready" + "\n" + "now tracing! \npress CTRL + C to stop tracing.")
getringbuffer()
