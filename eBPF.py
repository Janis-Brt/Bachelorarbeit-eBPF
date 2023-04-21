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
    unsigned int inum;
};

BPF_PERF_OUTPUT(events);

int sclone(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 0;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;

}
int sopen(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 1;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sread(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 2;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int swrite(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 3;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sclose(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 4;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sstat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 5;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int sfstat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 6;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slstat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 7;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int spoll(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 8;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int slseek(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
    data.syscallnumber = 9;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int smmap(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    u64 id = bpf_get_current_pid_tgid();
    u32 cgroup_id = bpf_get_current_cgroup_id();
    data.cgroup = cgroup_id;
    data.pid = id >> 32;
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
    int x = 0;
}

int sfchmod(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 91;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int schown(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 92;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sfchown(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 93;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int slchown(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 94;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sumask(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 95;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgettimeofday(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 96;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetrlimit(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 97;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetrusage(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 98;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssysinfo(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 99;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int stimes(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 100;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sptrace(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 101;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 102;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssyslog(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 103;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 104;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 105;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 106;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgeteuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 107;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetegid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 108;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetpgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 109;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetppid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 110;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetpgrp(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 111;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetsid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 112;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetreuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 113;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetregid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 114;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetgroups(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 115;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetgroups(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 116;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetresuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 117;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetresuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 118;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetresgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 119;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetresgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 120;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetpgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 121;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetfsuid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 122;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetfsgid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 123;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetsid(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 124;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int scapget(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 125;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int scapset(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 126;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int srt_sigpending(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 127;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int srt_sigtimedwait(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 128;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int srt_sigqueueinfo(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 129;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int srt_sigsuspend(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 130;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssigaltstack(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 131;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sutime(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 132;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int smknod(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 133;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int suselib(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 134;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int spersonality(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 135;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sustat(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 136;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sstatfs(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 137;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sfstatfs(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 138;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssysfs(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 139;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sgetpriority(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 140;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetpriority(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 141;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssched_setparam(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 142;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssched_getparam(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 143;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssched_setscheduler(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 144;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssched_getscheduler(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 145;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssched_get_priority_max(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 146;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssched_get_priority_min(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 147;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssched_rr_get_interval(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 148;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int smlock(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 149;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int smunlock(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 150;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int smlockall(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 151;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int smunlockall(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 152;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int svhangup(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 153;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int smodify_ldt(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 154;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int spivot_root(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 155;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssysctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 156;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sprctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 157;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sarch_prctl(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 158;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int sadjtimex(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 159;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
}
int ssetrlimit(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    unsigned int inum_ring = t->nsproxy->pid_ns_for_children->ns.inum;
    data.syscallnumber = 160;
    data.inum = inum_ring;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    int x = 0;
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
    # b.attach_kretprobe(event=b.get_syscall_fnname("chroot"), fn_name="schroot")
    # b.attach_kretprobe(event=b.get_syscall_fnname("sync"), fn_name="ssync")
    # b.attach_kretprobe(event=b.get_syscall_fnname("acct"), fn_name="sacct")
    # b.attach_kretprobe(event=b.get_syscall_fnname("settimeofday"), fn_name="ssettimeofday")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mount"), fn_name="smount")
    # b.attach_kretprobe(event=b.get_syscall_fnname("umount2"), fn_name="sumount2") not traceble
    # b.attach_kretprobe(event=b.get_syscall_fnname("swapon"), fn_name="sswapon")
    # b.attach_kretprobe(event=b.get_syscall_fnname("swapoff"), fn_name="sswapoff")
    # b.attach_kretprobe(event=b.get_syscall_fnname("reboot"), fn_name="sreboot")
    # b.attach_kretprobe(event=b.get_syscall_fnname("sethostname"), fn_name="ssethostname")
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
    # b.attach_kretprobe(event=b.get_syscall_fnname("gettid"), fn_name="sgettid")
    # b.attach_kretprobe(event=b.get_syscall_fnname("readahead"), fn_name="sreadahead")
    # b.attach_kretprobe(event=b.get_syscall_fnname("setxattr"), fn_name="ssetxattr")
    # b.attach_kretprobe(event=b.get_syscall_fnname("lsetxattr"), fn_name="slsetxattr")
    # b.attach_kretprobe(event=b.get_syscall_fnname("fsetxattr"), fn_name="sfsetxattr")
    # b.attach_kretprobe(event=b.get_syscall_fnname("getxattr"), fn_name="sgetxattr")
#    b.attach_kretprobe(event=b.get_syscall_fnname("lgetxattr"), fn_name="slgetxattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("fgetxattr"), fn_name="sfgetxattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("listxattr"), fn_name="slistxattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("llistxattr"), fn_name="sllistxattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("flistxattr"), fn_name="sflistxattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("removexattr"), fn_name="sremovexattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("lremovexattr"), fn_name="slremovexattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("fremovexattr"), fn_name="sfremovexattr")
#     b.attach_kretprobe(event=b.get_syscall_fnname("tkill"), fn_name="stkill")
#     b.attach_kretprobe(event=b.get_syscall_fnname("time"), fn_name="stime")
#     b.attach_kretprobe(event=b.get_syscall_fnname("futex"), fn_name="sfutex")
#     b.attach_kretprobe(event=b.get_syscall_fnname("sched_setaffinity"), fn_name="ssched_setaffinity")
#     b.attach_kretprobe(event=b.get_syscall_fnname("sched_getaffinity"), fn_name="ssched_getaffinity")
#     b.attach_kretprobe(event=b.get_syscall_fnname("set_thread_area"), fn_name="sset_thread_area")
#     b.attach_kretprobe(event=b.get_syscall_fnname("io_setup"), fn_name="sio_setup")
#     b.attach_kretprobe(event=b.get_syscall_fnname("io_destroy"), fn_name="sio_destroy")
#     b.attach_kretprobe(event=b.get_syscall_fnname("io_getevents"), fn_name="sio_getevents")
#     b.attach_kretprobe(event=b.get_syscall_fnname("io_submit"), fn_name="sio_submit")
#     b.attach_kretprobe(event=b.get_syscall_fnname("io_cancel"), fn_name="sio_cancel")
#     b.attach_kretprobe(event=b.get_syscall_fnname("get_thread_area"), fn_name="sget_thread_area")
#     b.attach_kretprobe(event=b.get_syscall_fnname("lookup_dcookie"), fn_name="slookup_dcookie")
#     b.attach_kretprobe(event=b.get_syscall_fnname("epoll_create"), fn_name="sepoll_create")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_ctl_old"), fn_name="sepoll_ctl_old")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_wait_old"), fn_name="sepoll_wait_old")
    # b.attach_kretprobe(event=b.get_syscall_fnname("remap_file_pages"), fn_name="sremap_file_pages")
    # b.attach_kretprobe(event=b.get_syscall_fnname("getdents64"), fn_name="sgetdents64")
    # b.attach_kretprobe(event=b.get_syscall_fnname("set_tid_address"), fn_name="sset_tid_address")
    # b.attach_kretprobe(event=b.get_syscall_fnname("restart_syscall"), fn_name="srestart_syscall")
    # b.attach_kretprobe(event=b.get_syscall_fnname("semtimedop"), fn_name="ssemtimedop")
    # b.attach_kretprobe(event=b.get_syscall_fnname("fadvise64"), fn_name="sfadvise64")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timer_create"), fn_name="stimer_create")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timer_settime"), fn_name="stimer_settime")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timer_gettime"), fn_name="stimer_gettime")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timer_getoverrun"), fn_name="stimer_getoverrun")
    # b.attach_kretprobe(event=b.get_syscall_fnname("timer_delete"), fn_name="stimer_delete")
    # b.attach_kretprobe(event=b.get_syscall_fnname("clock_settime"), fn_name="sclock_settime")
    # b.attach_kretprobe(event=b.get_syscall_fnname("clock_gettime"), fn_name="sclock_gettime")
    # b.attach_kretprobe(event=b.get_syscall_fnname("clock_getres"), fn_name="sclock_getres")
    # b.attach_kretprobe(event=b.get_syscall_fnname("clock_nanosleep"), fn_name="sclock_nanosleep")
    # b.attach_kretprobe(event=b.get_syscall_fnname("exit_group"), fn_name="sexit_group")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_wait"), fn_name="sepoll_wait")
    # b.attach_kretprobe(event=b.get_syscall_fnname("epoll_ctl"), fn_name="sepoll_ctl")
    # b.attach_kretprobe(event=b.get_syscall_fnname("tgkill"), fn_name="stgkill")
    # b.attach_kretprobe(event=b.get_syscall_fnname("utimes"), fn_name="sutimes")
    # b.attach_kretprobe(event=b.get_syscall_fnname("vserver"), fn_name="svserver")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mbind"), fn_name="smbind")
    # b.attach_kretprobe(event=b.get_syscall_fnname("set_mempolicy"), fn_name="sset_mempolicy")
    # b.attach_kretprobe(event=b.get_syscall_fnname("get_mempolicy"), fn_name="sget_mempolicy")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mq_open"), fn_name="smq_open")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mq_unlink"), fn_name="smq_unlink")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mq_timedsend"), fn_name="smq_timedsend")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mq_timedreceive"), fn_name="smq_timedreceive")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mq_notify"), fn_name="smq_notify")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mq_getsetattr"), fn_name="smq_getsetattr")
    # b.attach_kretprobe(event=b.get_syscall_fnname("kexec_load"), fn_name="skexec_load")
    # b.attach_kretprobe(event=b.get_syscall_fnname("waitid"), fn_name="swaitid")
    # b.attach_kretprobe(event=b.get_syscall_fnname("add_key"), fn_name="sadd_key")
    # b.attach_kretprobe(event=b.get_syscall_fnname("request_key"), fn_name="srequest_key")
    # b.attach_kretprobe(event=b.get_syscall_fnname("keyctl"), fn_name="skeyctl")
    # b.attach_kretprobe(event=b.get_syscall_fnname("ioprio_set"), fn_name="sioprio_set")
    # b.attach_kretprobe(event=b.get_syscall_fnname("ioprio_get"), fn_name="sioprio_get")
    # b.attach_kretprobe(event=b.get_syscall_fnname("inotify_init"), fn_name="sinotify_init")
    # b.attach_kretprobe(event=b.get_syscall_fnname("inotify_add_watch"), fn_name="sinotify_add_watch")
    # b.attach_kretprobe(event=b.get_syscall_fnname("inotify_rm_watch"), fn_name="sinotify_rm_watch")
    # b.attach_kretprobe(event=b.get_syscall_fnname("migrate_pages"), fn_name="smigrate_pages")
    # b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="sopenat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="smkdirat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("mknodat"), fn_name="smknodat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("fchownat"), fn_name="sfchownat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("futimesat"), fn_name="sfutimesat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("newfstatat"), fn_name="snewfstatat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="sunlinkat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("renameat"), fn_name="srenameat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("linkat"), fn_name="slinkat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("symlinkat"), fn_name="ssymlinkat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("readlinkat"), fn_name="sreadlinkat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("fchmodat"), fn_name="sfchmodat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("faccessat"), fn_name="sfaccessat")
    # b.attach_kretprobe(event=b.get_syscall_fnname("pselect6"), fn_name="spselect6")
    # b.attach_kretprobe(event=b.get_syscall_fnname("ppoll"), fn_name="sppoll")
    # b.attach_kretprobe(event=b.get_syscall_fnname("unshare"), fn_name="sunshare")
    # b.attach_kretprobe(event=b.get_syscall_fnname("set_robust_list"), fn_name="sset_robust_list")
    # b.attach_kretprobe(event=b.get_syscall_fnname("get_robust_list"), fn_name="sget_robust_list")
    # b.attach_kretprobe(event=b.get_syscall_fnname("splice"), fn_name="ssplice")
    # b.attach_kretprobe(event=b.get_syscall_fnname("tee"), fn_name="stee")
    # b.attach_kretprobe(event=b.get_syscall_fnname("sync_file_range"), fn_name="ssync_file_range")
    # b.attach_kretprobe(event=b.get_syscall_fnname("vmsplice"), fn_name="svmsplice")
    # b.attach_kretprobe(event=b.get_syscall_fnname("move_pages"), fn_name="smove_pages")
    # b.attach_kretprobe(event=b.get_syscall_fnname("utimensat"), fn_name="sutimensat")
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
    data = b["events"].event(data)
    syscall = data.syscallnumber
    pid = data.pid
    inum_ring = data.inum
    cgroup = data.cgroup
    # if localpids.__contains__(str(pid)):
    host_pid_ns = 4026531836
    if str(inum_ring) == str(4026532486):
        # print("Inside Container")
        if syscall == 0:
            print("found clone inside the Container! with inum: " + str(inum_ring))
            syscall = "clone"
            patterns.append(syscall)
        elif syscall == 1:
            print("found open inside the Container! with inum: " + str(inum_ring))
            syscall = "open"
            patterns.append(syscall)
        elif syscall == 2:
            print("found read inside the Container! with inum: " + str(inum_ring))
            syscall = "read"
            patterns.append(syscall)
        elif syscall == 3:
            print("found write inside the Container! with inum: " + str(inum_ring))
            syscall = "write"
            patterns.append(syscall)
        elif syscall == 4:
            print("found close inside the Container! with inum: " + str(inum_ring))
            syscall = "close"
            patterns.append(syscall)
        elif syscall == 5:
            print("found stat inside the Container! with inum: " + str(inum_ring))
            syscall = "stat"
            patterns.append(syscall)
        elif syscall == 6:
            print("found fstat inside the Container! with inum: " + str(inum_ring))
            syscall = "fstat"
            patterns.append(syscall)
        elif syscall == 7:
            print("found lstat inside the Container! with inum: " + str(inum_ring))
            syscall = "lstat"
            patterns.append(syscall)
        elif syscall == 8:
            print("found poll inside the Container! with inum: " + str(inum_ring))
            syscall = "poll"
            patterns.append(syscall)
        elif syscall == 9:
            print("found lseek inside the Container! with inum: " + str(inum_ring))
            syscall = "lseek"
            patterns.append(syscall)
        elif syscall == 10:
            print("found mmap inside the Container! with inum: " + str(inum_ring))
            syscall = "mmap"
            patterns.append(syscall)
        elif syscall == 11:
            print("found mprotect inside the Container! with inum: " + str(inum_ring))
            syscall = "mprotect"
            patterns.append(syscall)
        elif syscall == 12:
            print("found munmap inside the Container! with inum: " + str(inum_ring))
            syscall = "munmap"
            patterns.append(syscall)
        elif syscall == 13:
            print("found brk inside the Container! with inum: " + str(inum_ring))
            syscall = "brk"
            patterns.append(syscall)
        elif syscall == 14:
            print("found rt_sigaction inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigaction"
            patterns.append(syscall)
        elif syscall == 14:
            print("found rt_sigprocmask inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigprocmask"
            patterns.append(syscall)
        elif syscall == 15:
            print("found rt_sigreturn inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigreturn"
            patterns.append(syscall)
        elif syscall == 16:
            print("found rt_sigreturn inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigreturn"
            patterns.append(syscall)
        elif syscall == 17:
            print("found ioctl inside the Container! with inum: " + str(inum_ring))
            syscall = "ioctl"
            patterns.append(syscall)
        elif syscall == 18:
            print("found pread64 inside the Container! with inum: " + str(inum_ring))
            syscall = "pread64"
            patterns.append(syscall)
        elif syscall == 19:
            print("found pwrite64 inside the Container! with inum: " + str(inum_ring))
            syscall = "pwrite64"
            patterns.append(syscall)
        elif syscall == 20:
            print("found readv inside the Container! with inum: " + str(inum_ring))
            syscall = "readv"
            patterns.append(syscall)
        elif syscall == 21:
            print("found writev inside the Container! with inum: " + str(inum_ring))
            syscall = "writev"
            patterns.append(syscall)
        elif syscall == 22:
            print("found access inside the Container! with inum: " + str(inum_ring))
            syscall = "access"
            patterns.append(syscall)
        elif syscall == 23:
            print("found pipe inside the Container! with inum: " + str(inum_ring))
            syscall = "pipe"
            patterns.append(syscall)
        elif syscall == 24:
            print("found select inside the Container! with inum: " + str(inum_ring))
            syscall = "select"
            patterns.append(syscall)
        elif syscall == 25:
            print("found mremap inside the Container! with inum: " + str(inum_ring))
            syscall = "mremap"
            patterns.append(syscall)
        elif syscall == 26:
            print("found sched_yield inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_yield"
            patterns.append(syscall)
        elif syscall == 27:
            print("found msync inside the Container! with inum: " + str(inum_ring))
            syscall = "msync"
            patterns.append(syscall)
        elif syscall == 28:
            print("found mincore inside the Container! with inum: " + str(inum_ring))
            syscall = "mincore"
            patterns.append(syscall)
        elif syscall == 29:
            print("found madvise inside the Container! with inum: " + str(inum_ring))
            syscall = "madvise"
            patterns.append(syscall)
        elif syscall == 30:
            print("found shmget inside the Container! with inum: " + str(inum_ring))
            syscall = "shmget"
            patterns.append(syscall)
        elif syscall == 31:
            print("found shmat inside the Container! with inum: " + str(inum_ring))
            syscall = "shmat"
            patterns.append(syscall)
        elif syscall == 32:
            print("found shmctl inside the Container! with inum: " + str(inum_ring))
            syscall = "shmctl"
            patterns.append(syscall)
        elif syscall == 33:
            print("found dup inside the Container! with inum: " + str(inum_ring))
            syscall = "dup"
            patterns.append(syscall)
        elif syscall == 34:
            print("found dup2 inside the Container! with inum: " + str(inum_ring))
            syscall = "dup2"
            patterns.append(syscall)
        elif syscall == 35:
            print("found pause inside the Container! with inum: " + str(inum_ring))
            syscall = "pause"
            patterns.append(syscall)
        elif syscall == 36:
            print("found nanosleep inside the Container! with inum: " + str(inum_ring))
            syscall = "nanosleep"
            patterns.append(syscall)
        elif syscall == 37:
            print("found getitimer inside the Container! with inum: " + str(inum_ring))
            syscall = "getitimer"
            patterns.append(syscall)
        elif syscall == 38:
            print("found alarm inside the Container! with inum: " + str(inum_ring))
            syscall = "alarm"
            patterns.append(syscall)
        elif syscall == 39:
            print("found setitimer inside the Container! with inum: " + str(inum_ring))
            syscall = "setitimer"
            patterns.append(syscall)
        elif syscall == 40:
            print("found getpid inside the Container! with inum: " + str(inum_ring))
            syscall = "getpid"
            patterns.append(syscall)
        elif syscall == 41:
            print("found senfile inside the Container! with inum: " + str(inum_ring))
            syscall = "sendfile"
            patterns.append(syscall)
        elif syscall == 42:
            print("found socket inside the Container! with inum: " + str(inum_ring))
            syscall = "socket"
            patterns.append(syscall)
        elif syscall == 43:
            print("found connect inside the Container! with inum: " + str(inum_ring))
            syscall = "connect"
            patterns.append(syscall)
        elif syscall == 44:
            print("found accept inside the Container! with inum: " + str(inum_ring))
            syscall = "accept"
            patterns.append(syscall)
        elif syscall == 45:
            print("found sendto inside the Container! with inum: " + str(inum_ring))
            syscall = "sendto"
            patterns.append(syscall)
        elif syscall == 46:
            print("found recvfrom inside the Container! with inum: " + str(inum_ring))
            syscall = "recvfrom"
            patterns.append(syscall)
        elif syscall == 47:
            print("found sendmsg inside the Container! with inum: " + str(inum_ring))
            syscall = "sendmsg"
            patterns.append(syscall)
        elif syscall == 48:
            print("found recvmsg inside the Container! with inum: " + str(inum_ring))
            syscall = "recvmsg"
            patterns.append(syscall)
        elif syscall == 49:
            print("found shutdown inside the Container! with inum: " + str(inum_ring))
            syscall = "shutdown"
            patterns.append(syscall)
        elif syscall == 50:
            print("found bind inside the Container! with inum: " + str(inum_ring))
            syscall = "bind"
            patterns.append(syscall)
        elif syscall == 51:
            print("found listen inside the Container! with inum: " + str(inum_ring))
            syscall = "listen"
            patterns.append(syscall)
        elif syscall == 52:
            print("found getsockname inside the Container! with inum: " + str(inum_ring))
            syscall = "getsockname"
            patterns.append(syscall)
        elif syscall == 53:
            print("found getpeername inside the Container! with inum: " + str(inum_ring))
            syscall = "getpername"
            patterns.append(syscall)
        elif syscall == 54:
            print("found socketpair inside the Container! with inum: " + str(inum_ring))
            syscall = "socketpair"
            patterns.append(syscall)
        elif syscall == 55:
            print("found setsockopt inside the Container! with inum: " + str(inum_ring))
            syscall = "setsockopt"
            patterns.append(syscall)
        elif syscall == 56:
            print("found getsockopt inside the Container! with inum: " + str(inum_ring))
            syscall = "getsockopt"
            patterns.append(syscall)
        elif syscall == 57:
            print("found fork inside the Container! with inum: " + str(inum_ring))
            syscall = "fork"
            patterns.append(syscall)
        elif syscall == 58:
            print("found vfork inside the Container! with inum: " + str(inum_ring))
            syscall = "vfork"
            patterns.append(syscall)
        elif syscall == 59:
            print("found execve inside the Container! with inum: " + str(inum_ring))
            syscall = "execve"
            patterns.append(syscall)
        elif syscall == 60:
            print("found exit inside the Container! with inum: " + str(inum_ring))
            syscall = "exit"
            patterns.append(syscall)
        elif syscall == 61:
            print("found wait4 inside the Container! with inum: " + str(inum_ring))
            syscall = "wait4"
            patterns.append(syscall)
        elif syscall == 62:
            print("found kill inside the Container! with inum: " + str(inum_ring))
            syscall = "kill"
            patterns.append(syscall)
        elif syscall == 63:
            print("found uname inside the Container! with inum: " + str(inum_ring))
            syscall = "uname"
            patterns.append(syscall)
        elif syscall == 64:
            print("found semget inside the Container! with inum: " + str(inum_ring))
            syscall = "semget"
            patterns.append(syscall)
        elif syscall == 65:
            print("found semop inside the Container! with inum: " + str(inum_ring))
            syscall = "semop"
            patterns.append(syscall)
        elif syscall == 66:
            print("found semctl inside the Container! with inum: " + str(inum_ring))
            syscall = "semctl"
            patterns.append(syscall)
        elif syscall == 67:
            print("found shmdt inside the Container! with inum: " + str(inum_ring))
            syscall = "shmdt"
            patterns.append(syscall)
        elif syscall == 68:
            print("found msgget inside the Container! with inum: " + str(inum_ring))
            syscall = "msgget"
            patterns.append(syscall)
        elif syscall == 69:
            print("found msgsnd inside the Container! with inum: " + str(inum_ring))
            syscall = "exit"
            patterns.append(syscall)
        elif syscall == 70:
            print("found msgrcv inside the Container! with inum: " + str(inum_ring))
            syscall = "msgrcv"
            patterns.append(syscall)
        elif syscall == 71:
            print("found msgctl inside the Container! with inum: " + str(inum_ring))
            syscall = "msgctl"
            patterns.append(syscall)
        elif syscall == 72:
            print("found fcntl inside the Container! with inum: " + str(inum_ring))
            syscall = "fcntl"
            patterns.append(syscall)
        elif syscall == 73:
            print("found flock inside the Container! with inum: " + str(inum_ring))
            syscall = "flock"
            patterns.append(syscall)
        elif syscall == 74:
            print("found fsync inside the Container! with inum: " + str(inum_ring))
            syscall = "fsync"
            patterns.append(syscall)
        elif syscall == 75:
            print("found fdatasync inside the Container! with inum: " + str(inum_ring))
            syscall = "fdatasync"
            patterns.append(syscall)
        elif syscall == 76:
            print("found truncate inside the Container! with inum: " + str(inum_ring))
            syscall = "truncate"
            patterns.append(syscall)
        elif syscall == 77:
            print("found ftruncate inside the Container! with inum: " + str(inum_ring))
            syscall = "ftruncate"
            patterns.append(syscall)
        elif syscall == 78:
            print("found getdents inside the Container! with inum: " + str(inum_ring))
            syscall = "getdents"
            patterns.append(syscall)
        elif syscall == 79:
            print("found getcwd inside the Container! with inum: " + str(inum_ring))
            syscall = "getcwd"
            patterns.append(syscall)
        elif syscall == 80:
            print("found chdir inside the Container! with inum: " + str(inum_ring))
            syscall = "chdir"
            patterns.append(syscall)
        elif syscall == 81:
            print("found fchdir inside the Container! with inum: " + str(inum_ring))
            syscall = "fchdir"
            patterns.append(syscall)
        elif syscall == 82:
            print("found rename inside the Container! with inum: " + str(inum_ring))
            syscall = "rename"
            patterns.append(syscall)
        elif syscall == 83:
            print("found mkdir inside the Container! with inum: " + str(inum_ring))
            syscall = "mkdir"
            patterns.append(syscall)
        elif syscall == 84:
            print("found rmdir inside the Container! with inum: " + str(inum_ring))
            syscall = "rmdir"
            patterns.append(syscall)
        elif syscall == 85:
            print("found creat inside the Container! with inum: " + str(inum_ring))
            syscall = "creat"
            patterns.append(syscall)
        elif syscall == 86:
            print("found link inside the Container! with inum: " + str(inum_ring))
            syscall = "link"
            patterns.append(syscall)
        elif syscall == 87:
            print("found unlink inside the Container! with inum: " + str(inum_ring))
            syscall = "unlink"
            patterns.append(syscall)
        elif syscall == 88:
            print("found symlink inside the Container! with inum: " + str(inum_ring))
            syscall = "symlink"
            patterns.append(syscall)
        elif syscall == 89:
            print("found readlink inside the Container! with inum: " + str(inum_ring))
            syscall = "readlink"
            patterns.append(syscall)
        elif syscall == 90:
            print("found chmod inside the Container! with inum: " + str(inum_ring))
            syscall = "chmod"
            patterns.append(syscall)
        elif syscall == 91:
            print("found fchmod inside the Container! with inum: " + str(inum_ring))
            syscall = "fchmod"
            patterns.append(syscall)
        elif syscall == 92:
            print("found chown inside the Container! with inum: " + str(inum_ring))
            syscall = "chown"
            patterns.append(syscall)
        elif syscall == 93:
            print("found fchown inside the Container! with inum: " + str(inum_ring))
            syscall = "fchown"
            patterns.append(syscall)
        elif syscall == 94:
            print("found lchown inside the Container! with inum: " + str(inum_ring))
            syscall = "lchown"
            patterns.append(syscall)
        elif syscall == 95:
            print("found umask inside the Container! with inum: " + str(inum_ring))
            syscall = "umask"
            patterns.append(syscall)
        elif syscall == 96:
            print("found gettimeofday inside the Container! with inum: " + str(inum_ring))
            syscall = "gettimeofday"
            patterns.append(syscall)
        elif syscall == 97:
            print("found getrlimit inside the Container! with inum: " + str(inum_ring))
            syscall = "getrlimit"
            patterns.append(syscall)
        elif syscall == 98:
            print("found getrusage inside the Container! with inum: " + str(inum_ring))
            syscall = "getrusage"
            patterns.append(syscall)
        elif syscall == 99:
            print("found sysinfo inside the Container! with inum: " + str(inum_ring))
            syscall = "chown"
            patterns.append(syscall)
        elif syscall == 100:
            print("found times inside the Container! with inum: " + str(inum_ring))
            syscall = "times"
            patterns.append(syscall)
        elif syscall == 101:
            print("found ptrace inside the Container! with inum: " + str(inum_ring))
            syscall = "ptrace"
            patterns.append(syscall)
        elif syscall == 102:
            print("found getuid inside the Container! with inum: " + str(inum_ring))
            syscall = "getuid"
            patterns.append(syscall)
        elif syscall == 103:
            print("found syslog inside the Container! with inum: " + str(inum_ring))
            syscall = "syslog"
            patterns.append(syscall)
        elif syscall == 104:
            print("found getgid inside the Container! with inum: " + str(inum_ring))
            syscall = "getgid"
            patterns.append(syscall)
        elif syscall == 105:
            print("found setuid inside the Container! with inum: " + str(inum_ring))
            syscall = "setuid"
            patterns.append(syscall)
        elif syscall == 106:
            print("found setgid inside the Container! with inum: " + str(inum_ring))
            syscall = "setgid"
            patterns.append(syscall)
        elif syscall == 107:
            print("found geteuid inside the Container! with inum: " + str(inum_ring))
            syscall = "geteuid"
            patterns.append(syscall)
        elif syscall == 108:
            print("found getegid inside the Container! with inum: " + str(inum_ring))
            syscall = "getegid"
            patterns.append(syscall)
        elif syscall == 109:
            print("found setpgid inside the Container! with inum: " + str(inum_ring))
            syscall = "setpgid"
            patterns.append(syscall)
        elif syscall == 110:
            print("found getppid inside the Container! with inum: " + str(inum_ring))
            syscall = "getppid"
            patterns.append(syscall)
        elif syscall == 111:
            print("found getpgrp inside the Container! with inum: " + str(inum_ring))
            syscall = "getpgrp"
            patterns.append(syscall)
        elif syscall == 112:
            print("found setsid inside the Container! with inum: " + str(inum_ring))
            syscall = "setsid"
            patterns.append(syscall)
        elif syscall == 113:
            print("found setreuid inside the Container! with inum: " + str(inum_ring))
            syscall = "setreuid"
            patterns.append(syscall)
        elif syscall == 114:
            print("found setregid inside the Container! with inum: " + str(inum_ring))
            syscall = "setregid"
            patterns.append(syscall)
        elif syscall == 115:
            print("found getgroups inside the Container! with inum: " + str(inum_ring))
            syscall = "getgroups"
            patterns.append(syscall)
        elif syscall == 116:
            print("found setgroups inside the Container! with inum: " + str(inum_ring))
            syscall = "setgroups"
            patterns.append(syscall)
        elif syscall == 117:
            print("found setresuid inside the Container! with inum: " + str(inum_ring))
            syscall = "setresuid"
            patterns.append(syscall)
        elif syscall == 118:
            print("found getresuid inside the Container! with inum: " + str(inum_ring))
            syscall = "getresuid"
            patterns.append(syscall)
        elif syscall == 119:
            print("found setresgid inside the Container! with inum: " + str(inum_ring))
            syscall = "setresgid"
            patterns.append(syscall)
        elif syscall == 120:
            print("found getresgid inside the Container! with inum: " + str(inum_ring))
            syscall = "getresgid"
            patterns.append(syscall)
        elif syscall == 121:
            print("found getpgid inside the Container! with inum: " + str(inum_ring))
            syscall = "getpgid"
            patterns.append(syscall)
        elif syscall == 122:
            print("found setfsuid inside the Container! with inum: " + str(inum_ring))
            syscall = "setfsuid"
            patterns.append(syscall)
        elif syscall == 123:
            print("found setfsgid inside the Container! with inum: " + str(inum_ring))
            syscall = "setfsgid"
            patterns.append(syscall)
        elif syscall == 124:
            print("found getsid inside the Container! with inum: " + str(inum_ring))
            syscall = "getsid"
            patterns.append(syscall)
        elif syscall == 125:
            print("found capget inside the Container! with inum: " + str(inum_ring))
            syscall = "capget"
            patterns.append(syscall)
        elif syscall == 126:
            print("found capset inside the Container! with inum: " + str(inum_ring))
            syscall = "capset"
            patterns.append(syscall)
        elif syscall == 127:
            print("found rt_sigpending inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigpending"
            patterns.append(syscall)
            #    occurences['rt_sigpending']))
        elif syscall == 128:
            print("found rt_sigtimedwait inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigtimedwait"
            patterns.append(syscall)
        elif syscall == 129:
            print("found rt_sigqueueinfo inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigqueueinfo"
            patterns.append(syscall)
        elif syscall == 130:
            print("found rt_sigsuspend inside the Container! with inum: " + str(inum_ring))
            syscall = "rt_sigsuspend"
            patterns.append(syscall)
        elif syscall == 131:
            print("found sigaltstack inside the Container! with inum: " + str(inum_ring))
            syscall = "sigaltstack"
            patterns.append(syscall)
        elif syscall == 132:
            print("found utime inside the Container! with inum: " + str(inum_ring))
            syscall = "utime"
            patterns.append(syscall)
        elif syscall == 133:
            print("found mknod inside the Container! with inum: " + str(inum_ring))
            syscall = "mknod"
            patterns.append(syscall)
        elif syscall == 134:
            print("found uselib inside the Container! with inum: " + str(inum_ring))
            syscall = "uselib"
            patterns.append(syscall)
        elif syscall == 135:
            print("found personality inside the Container! with inum: " + str(inum_ring))
            syscall = "personality"
            patterns.append(syscall)
        elif syscall == 136:
            print("found ustat inside the Container! with inum: " + str(inum_ring))
            syscall = "ustat"
            patterns.append(syscall)
        elif syscall == 137:
            print("found statfs inside the Container! with inum: " + str(inum_ring))
            syscall = "statfs"
            patterns.append(syscall)
        elif syscall == 138:
            print("found fstatfs inside the Container! with inum: " + str(inum_ring))
            syscall = "fstatfs"
            patterns.append(syscall)
        elif syscall == 139:
            print("found sysfs inside the Container! with inum: " + str(inum_ring))
            syscall = "sysfs"
            patterns.append(syscall)
        elif syscall == 140:
            print("found getpriority inside the Container! with inum: " + str(inum_ring))
            syscall = "getpriority"
            patterns.append(syscall)
        elif syscall == 141:
            print("found setpriority inside the Container! with inum: " + str(inum_ring))
            syscall = "setpriority"
            patterns.append(syscall)
        elif syscall == 142:
            print("found sched_setparam inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_setparam"
            patterns.append(syscall)
        elif syscall == 143:
            print("found sched_getparam inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_getparam"
            patterns.append(syscall)
        elif syscall == 144:
            print("found sched_setscheduler inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_setscheduler"
            patterns.append(syscall)
        elif syscall == 145:
            print("found sched_getscheduler inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_getscheduler"
            patterns.append(syscall)
        elif syscall == 146:
            print("found sched_get_priority_max inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_get_priority_max"
            patterns.append(syscall)
        elif syscall == 147:
            print("found sched_get_priority_min inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_get_priority_min"
            patterns.append(syscall)
        elif syscall == 148:
            print("found sched_rr_get_interval inside the Container! with inum: " + str(inum_ring))
            syscall = "sched_rr_get_interval"
            patterns.append(syscall)
        elif syscall == 149:
            print("found mlock inside the Container! with inum: " + str(inum_ring))
            syscall = "mlock"
            patterns.append(syscall)
        elif syscall == 150:
            print("found munlock inside the Container! with inum: " + str(inum_ring))
            syscall = "munlock"
            patterns.append(syscall)
        elif syscall == 151:
            print("found mlockall inside the Container! with inum: " + str(inum_ring))
            syscall = "mlockall"
            patterns.append(syscall)
        elif syscall == 152:
            print("found munlockall inside the Container! with inum: " + str(inum_ring))
            syscall = "munlockall"
            patterns.append(syscall)
        elif syscall == 153:
            print("found vhangup inside the Container! with inum: " + str(inum_ring))
            syscall = "vhangup"
            patterns.append(syscall)
        elif syscall == 154:
            print("found modify_ldt inside the Container! with inum: " + str(inum_ring))
            syscall = "modify_ldt"
            patterns.append(syscall)
        elif syscall == 155:
            print("found pivot_root inside the Container! with inum: " + str(inum_ring))
            syscall = "pivot_root"
            patterns.append(syscall)
        elif syscall == 156:
            print("found sysctl inside the Container! with inum: " + str(inum_ring))
            syscall = "sysctl"
            patterns.append(syscall)
        elif syscall == 157:
            print("found prctl inside the Container! with inum: " + str(inum_ring))
            syscall = "prctl"
            patterns.append(syscall)
        elif syscall == 158:
            print("found arch_prctl inside the Container! with inum: " + str(inum_ring))
            syscall = "arch_prctl"
            patterns.append(syscall)
        elif syscall == 159:
            print("found adjtimex inside the Container! with inum: " + str(inum_ring))
            syscall = "adjtimex"
            patterns.append(syscall)
        elif syscall == 160:
            print("found setrlimit inside the Container! with inum: " + str(inum_ring))
            syscall = "setrlimit"
            patterns.append(syscall)
        # elif syscall == 162:
        #     occurences['chroot'] = occurences['chroot'] + 1
        #     # print("Update für folgenden System Call chroot. Neue Häufigkeit: " + str(occurences['chroot']))
        # elif syscall == 163:
        #     occurences['sync'] = occurences['sync'] + 1
        #     # print("Update für folgenden System Call sync. Neue Häufigkeit: " + str(occurences['sync']))
        # elif syscall == 164:
        #     occurences['acct'] = occurences['acct'] + 1
        #     # print("Update für folgenden System Call acct. Neue Häufigkeit: " + str(occurences['acct']))
        # elif syscall == 165:
        #     occurences['settimeofday'] = occurences['settimeofday'] + 1
        #     # print("Update für folgenden System Call settimeofday. Neue Häufigkeit: " + str(
        #     #    occurences['settimeofday']))
        # elif syscall == 166:
        #     occurences['mount'] = occurences['mount'] + 1
        #     # print("Update für folgenden System Call mount. Neue Häufigkeit: " + str(occurences['mount']))
        # elif syscall == 167:
        #     occurences['umount2'] = occurences['umount2'] + 1
        #     # print("Update für folgenden System Call umount2. Neue Häufigkeit: " + str(occurences['umount2']))
        # elif syscall == 168:
        #     occurences['swapon'] = occurences['swapon'] + 1
        #     # print("Update für folgenden System Call swapon. Neue Häufigkeit: " + str(occurences['swapon']))
        # elif syscall == 169:
        #     occurences['swapoff'] = occurences['swapoff'] + 1
        #     # print("Update für folgenden System Call swapoff. Neue Häufigkeit: " + str(occurences['swapoff']))
        # elif syscall == 170:
        #     occurences['reboot'] = occurences['reboot'] + 1
        #     # print("Update für folgenden System Call reboot. Neue Häufigkeit: " + str(occurences['reboot']))
        # elif syscall == 171:
        #     occurences['sethostname'] = occurences['sethostname'] + 1
        #     # print(
        #     #     "Update für folgenden System Call: sethostname. Neue Häufigkeit: " + str(occurences['sethostname']))
        # elif syscall == 172:
        #     occurences['setdomainname'] = occurences['setdomainname'] + 1
        #     # print("Update für folgenden System Call setdomainname. Neue Häufigkeit: " + str(
        #     #    occurences['setdomainname']))
        # elif syscall == 173:
        #     occurences['iopl'] = occurences['iopl'] + 1
        #     # print("Update für folgenden System Call iopl. Neue Häufigkeit: " + str(occurences['iopl']))
        # elif syscall == 174:
        #     occurences['ioperm'] = occurences['ioperm'] + 1
        #     # print("Update für folgenden System Call ioperm. Neue Häufigkeit: " + str(occurences['ioperm']))
        # elif syscall == 175:
        #     occurences['create_module'] = occurences['create_module'] + 1
        #     # print("Update für folgenden System Call create_module. Neue Häufigkeit: " + str(
        #     #    occurences['create_module']))
        # elif syscall == 176:
        #     occurences['init_module'] = occurences['init_module'] + 1
        #     # print(
        #     #     "Update für folgenden System Call: init_module. Neue Häufigkeit: " + str(occurences['init_module']))
        # elif syscall == 177:
        #     occurences['delete_module'] = occurences['delete_module'] + 1
        #     # print("Update für folgenden System Call delete_module. Neue Häufigkeit: " + str(
        #     #    occurences['delete_module']))
        # elif syscall == 178:
        #     occurences['get_kernel_syms'] = occurences['get_kernel_syms'] + 1
        #     # print("Update für folgenden System Call get_kernel_syms. Neue Häufigkeit: " + str(
        #     #    occurences['get_kernel_syms']))
        # elif syscall == 179:
        #     occurences['query_module'] = occurences['query_module'] + 1
        #     # print("Update für folgenden System Call query_module. Neue Häufigkeit: " + str(
        #     #    occurences['query_module']))
        # elif syscall == 180:
        #     occurences['quotactl'] = occurences['quotactl'] + 1
        #     # print("Update für folgenden System Call quotactl. Neue Häufigkeit: " + str(occurences['quotactl']))
        # elif syscall == 181:
        #     occurences['nfsservctl'] = occurences['nfsservctl'] + 1
        #     # print("Update für folgenden System Call nfsservctl. Neue Häufigkeit: " + str(occurences['nfsservctl']))
        # elif syscall == 182:
        #     occurences['getpmsg'] = occurences['getpmsg'] + 1
        #     # print("Update für folgenden System Call getpmsg. Neue Häufigkeit: " + str(occurences['getpmsg']))
        # elif syscall == 183:
        #     occurences['putpmsg'] = occurences['putpmsg'] + 1
        #     # print("Update für folgenden System Call putpmsg. Neue Häufigkeit: " + str(occurences['putpmsg']))
        # elif syscall == 184:
        #     occurences['afs_syscall'] = occurences['afs_syscall'] + 1
        #     # print(
        #     #     "Update für folgenden System Call: afs_syscall. Neue Häufigkeit: " + str(occurences['afs_syscall']))
        # elif syscall == 185:
        #     occurences['tuxcall'] = occurences['tuxcall'] + 1
        #     # print("Update für folgenden System Call tuxcall. Neue Häufigkeit: " + str(occurences['tuxcall']))
        # elif syscall == 186:
        #     occurences['security'] = occurences['security'] + 1
        #     # print("Update für folgenden System Call security. Neue Häufigkeit: " + str(occurences['security']))
        # elif syscall == 187:
        #     occurences['gettid'] = occurences['gettid'] + 1
        #     # print("Update für folgenden System Call gettid. Neue Häufigkeit: " + str(occurences['gettid']))
        # elif syscall == 188:
        #     occurences['readahead'] = occurences['readahead'] + 1
        #     # print("Update für folgenden System Call readahead. Neue Häufigkeit: " + str(occurences['readahead']))
        # elif syscall == 189:
        #     occurences['setxattr'] = occurences['setxattr'] + 1
        #     # print("Update für folgenden System Call setxattr. Neue Häufigkeit: " + str(occurences['setxattr']))
        # elif syscall == 190:
        #     occurences['lsetxattr'] = occurences['lsetxattr'] + 1
        #     # print("Update für folgenden System Call lsetxattr. Neue Häufigkeit: " + str(occurences['lsetxattr']))
        # elif syscall == 191:
        #     occurences['fsetxattr'] = occurences['fsetxattr'] + 1
        #     # print("Update für folgenden System Call fsetxattr. Neue Häufigkeit: " + str(occurences['fsetxattr']))
        # elif syscall == 192:
        #     occurences['getxattr'] = occurences['getxattr'] + 1
        #     # print("Update für folgenden System Call getxattr. Neue Häufigkeit: " + str(occurences['getxattr']))
        # # elif syscall == 192:
        # #     occurences['lgetxattr'] = occurences['lgetxattr'] + 1
        # #     # print("Update für folgenden System Call lgetxattr. Neue Häufigkeit: " + str(occurences['lgetxattr']))
        # elif syscall == 193:
        #     occurences['fgetxattr'] = occurences['fgetxattr'] + 1
        #     # print("Update für folgenden System Call fgetxattr. Neue Häufigkeit: " + str(occurences['fgetxattr']))
        # elif syscall == 194:
        #     occurences['listxattr'] = occurences['listxattr'] + 1
        #     # print("Update für folgenden System Call listxattr. Neue Häufigkeit: " + str(occurences['listxattr']))
        # elif syscall == 195:
        #     occurences['llistxattr'] = occurences['llistxattr'] + 1
        #     # print("Update für folgenden System Call llistxattr. Neue Häufigkeit: " + str(occurences['llistxattr']))
        # elif syscall == 196:
        #     occurences['flistxattr'] = occurences['flistxattr'] + 1
        #     # print("Update für folgenden System Call flistxattr. Neue Häufigkeit: " + str(occurences['flistxattr']))
        # elif syscall == 197:
        #     occurences['removexattr'] = occurences['removexattr'] + 1
        #     print(
        #         "Update für folgenden System Call: removexattr. Neue Häufigkeit: " + str(occurences['removexattr']))
        # elif syscall == 198:
        #     occurences['lremovexattr'] = occurences['lremovexattr'] + 1
        #     # print("Update für folgenden System Call lremovexattr. Neue Häufigkeit: " + str(
        #     #    occurences['lremovexattr']))
        # elif syscall == 199:
        #     occurences['fremovexattr'] = occurences['fremovexattr'] + 1
        #     # print("Update für folgenden System Call fremovexattr. Neue Häufigkeit: " + str(
        #     #    occurences['fremovexattr']))
        # elif syscall == 200:
        #     occurences['tkill'] = occurences['tkill'] + 1
        #     # print("Update für folgenden System Call tkill. Neue Häufigkeit: " + str(occurences['tkill']))
        # elif syscall == 201:
        #     occurences['time'] = occurences['time'] + 1
        #     # print("Update für folgenden System Call time. Neue Häufigkeit: " + str(occurences['time']))
        # elif syscall == 202:
        #     occurences['futex'] = occurences['futex'] + 1
        #     # print("Update für folgenden System Call futex. Neue Häufigkeit: " + str(occurences['futex']))
        # elif syscall == 203:
        #     occurences['sched_setaffinity'] = occurences['sched_setaffinity'] + 1
        #     # print("Update für folgenden System Call sched_setaffinity. Neue Häufigkeit: " + str(
        #     #    occurences['sched_setaffinity']))
        # elif syscall == 204:
        #     occurences['sched_getaffinity'] = occurences['sched_getaffinity'] + 1
        #     # print("Update für folgenden System Call sched_getaffinity. Neue Häufigkeit: " + str(
        #     #    occurences['sched_getaffinity']))
        # elif syscall == 205:
        #     occurences['set_thread_area'] = occurences['set_thread_area'] + 1
        #     # print("Update für folgenden System Call set_thread_area. Neue Häufigkeit: " + str(
        #     #    occurences['set_thread_area']))
        # elif syscall == 206:
        #     occurences['io_setup'] = occurences['io_setup'] + 1
        #     # print("Update für folgenden System Call io_setup. Neue Häufigkeit: " + str(occurences['io_setup']))
        # elif syscall == 207:
        #     occurences['io_destroy'] = occurences['io_destroy'] + 1
        #     # print("Update für folgenden System Call io_destroy. Neue Häufigkeit: " + str(occurences['io_destroy']))
        # elif syscall == 208:
        #     occurences['io_getevents'] = occurences['io_getevents'] + 1
        #     # print("Update für folgenden System Call io_getevents. Neue Häufigkeit: " + str(
        #     #    occurences['io_getevents']))
        # elif syscall == 209:
        #     occurences['io_submit'] = occurences['io_submit'] + 1
        #     # print("Update für folgenden System Call io_submit. Neue Häufigkeit: " + str(occurences['io_submit']))
        # elif syscall == 210:
        #     occurences['io_cancel'] = occurences['io_cancel'] + 1
        #     # print("Update für folgenden System Call io_cancel. Neue Häufigkeit: " + str(occurences['io_cancel']))
        # elif syscall == 211:
        #     occurences['get_thread_area'] = occurences['get_thread_area'] + 1
        #     # print("Update für folgenden System Call get_thread_area. Neue Häufigkeit: " + str(
        #     #    occurences['get_thread_area']))
        # elif syscall == 212:
        #     occurences['lookup_dcookie'] = occurences['lookup_dcookie'] + 1
        #     # print("Update für folgenden System Call lookup_dcookie. Neue Häufigkeit: " + str(
        #     #    occurences['lookup_dcookie']))
        # elif syscall == 213:
        #     occurences['epoll_create'] = occurences['epoll_create'] + 1
        #     # print("Update für folgenden System Call epoll_create. Neue Häufigkeit: " + str(
        #     #    occurences['epoll_create']))
        # elif syscall == 214:
        #     occurences['epoll_ctl_old'] = occurences['epoll_ctl_old'] + 1
        #     # print("Update für folgenden System Call epoll_ctl_old. Neue Häufigkeit: " + str(
        #     #    occurences['epoll_ctl_old']))
        # elif syscall == 215:
        #     occurences['epoll_wait_old'] = occurences['epoll_wait_old'] + 1
        #     # print("Update für folgenden System Call epoll_wait_old. Neue Häufigkeit: " + str(
        #     #    occurences['epoll_wait_old']))
        # elif syscall == 216:
        #     occurences['remap_file_pages'] = occurences['remap_file_pages'] + 1
        #     # print("Update für folgenden System Call remap_file_pages. Neue Häufigkeit: " + str(
        #     #    occurences['remap_file_pages']))
        # elif syscall == 217:
        #     occurences['getdents64'] = occurences['getdents64'] + 1
        #     # print("Update für folgenden System Call getdents64. Neue Häufigkeit: " + str(occurences['getdents64']))
        # elif syscall == 218:
        #     occurences['set_tid_address'] = occurences['set_tid_address'] + 1
        #     # print("Update für folgenden System Call set_tid_address. Neue Häufigkeit: " + str(
        #     #    occurences['set_tid_address']))
        # elif syscall == 219:
        #     occurences['restart_syscall'] = occurences['restart_syscall'] + 1
        #     # print("Update für folgenden System Call restart_syscall. Neue Häufigkeit: " + str(
        #     #    occurences['restart_syscall']))
        # elif syscall == 220:
        #     occurences['semtimedop'] = occurences['semtimedop'] + 1
        #     # print("Update für folgenden System Call semtimedop. Neue Häufigkeit: " + str(occurences['semtimedop']))
        # elif syscall == 221:
        #     occurences['fadvise64'] = occurences['fadvise64'] + 1
        #     # print("Update für folgenden System Call fadvise64. Neue Häufigkeit: " + str(occurences['fadvise64']))
        # elif syscall == 222:
        #     occurences['timer_create'] = occurences['timer_create'] + 1
        #     # print("Update für folgenden System Call timer_create. Neue Häufigkeit: " + str(
        #     #    occurences['timer_create']))
        # elif syscall == 223:
        #     occurences['timer_settime'] = occurences['timer_settime'] + 1
        #     # print("Update für folgenden System Call timer_settime. Neue Häufigkeit: " + str(
        #     #    occurences['timer_settime']))
        # elif syscall == 224:
        #     occurences['timer_gettime'] = occurences['timer_gettime'] + 1
        #     # print("Update für folgenden System Call timer_gettime. Neue Häufigkeit: " + str(
        #     #    occurences['timer_gettime']))
        # elif syscall == 225:
        #     occurences['timer_getoverrun'] = occurences['timer_getoverrun'] + 1
        #     # print("Update für folgenden System Call timer_getoverrun. Neue Häufigkeit: " + str(
        #     #    occurences['timer_getoverrun']))
        # elif syscall == 226:
        #     occurences['timer_delete'] = occurences['timer_delete'] + 1
        #     # print("Update für folgenden System Call timer_delete. Neue Häufigkeit: " + str(
        #     #    occurences['timer_delete']))
        # elif syscall == 227:
        #     occurences['clock_settime'] = occurences['clock_settime'] + 1
        #     # print("Update für folgenden System Call clock_settime. Neue Häufigkeit: " + str(
        #     #    occurences['clock_settime']))
        # elif syscall == 228:
        #     occurences['clock_gettime'] = occurences['clock_gettime'] + 1
        #     # print("Update für folgenden System Call clock_gettime. Neue Häufigkeit: " + str(
        #     #    occurences['clock_gettime']))
        # elif syscall == 229:
        #     occurences['clock_getres'] = occurences['clock_getres'] + 1
        #     # print("Update für folgenden System Call clock_getres. Neue Häufigkeit: " + str(
        #     #    occurences['clock_getres']))
        # elif syscall == 230:
        #     occurences['clock_nanosleep'] = occurences['clock_nanosleep'] + 1
        #     # print("Update für folgenden System Call clock_nanosleep. Neue Häufigkeit: " + str(
        #     #    occurences['clock_nanosleep']))
        # elif syscall == 231:
        #     occurences['exit_group'] = occurences['exit_group'] + 1
        #     # print("Update für folgenden System Call exit_group. Neue Häufigkeit: " + str(occurences['exit_group']))
        # elif syscall == 232:
        #     occurences['epoll_wait'] = occurences['epoll_wait'] + 1
        #     # print("Update für folgenden System Call epoll_wait. Neue Häufigkeit: " + str(occurences['epoll_wait']))
        # elif syscall == 233:
        #     occurences['epoll_ctl'] = occurences['epoll_ctl'] + 1
        #     # print("Update für folgenden System Call epoll_ctl. Neue Häufigkeit: " + str(occurences['epoll_ctl']))
        # elif syscall == 234:
        #     occurences['tgkill'] = occurences['tgkill'] + 1
        #     # print("Update für folgenden System Call tgkill. Neue Häufigkeit: " + str(occurences['tgkill']))
        # elif syscall == 235:
        #     occurences['utimes'] = occurences['utimes'] + 1
        #     # print("Update für folgenden System Call utimes. Neue Häufigkeit: " + str(occurences['utimes']))
        # elif syscall == 236:
        #     occurences['vserver'] = occurences['vserver'] + 1
        #     # print("Update für folgenden System Call vserver. Neue Häufigkeit: " + str(occurences['vserver']))
        # elif syscall == 237:
        #     occurences['mbind'] = occurences['mbind'] + 1
        #     # print("Update für folgenden System Call mbind. Neue Häufigkeit: " + str(occurences['mbind']))
        # elif syscall == 238:
        #     occurences['set_mempolicy'] = occurences['set_mempolicy'] + 1
        #     # print("Update für folgenden System Call set_mempolicy. Neue Häufigkeit: " + str(
        # #     occurences['set_mempolicy']))
        # elif syscall == 239:
        #     occurences['get_mempolicy'] = occurences['get_mempolicy'] + 1
        #     # print("Update für folgenden System Call get_mempolicy. Neue Häufigkeit: " + str(
        #     #    occurences['get_mempolicy']))
        # elif syscall == 240:
        #     occurences['mq_open'] = occurences['mq_open'] + 1
        #     # print("Update für folgenden System Call mq_open. Neue Häufigkeit: " + str(occurences['mq_open']))
        # elif syscall == 241:
        #     occurences['mq_unlink'] = occurences['mq_unlink'] + 1
        #     # print("Update für folgenden System Call mq_unlink. Neue Häufigkeit: " + str(occurences['mq_unlink']))
        # elif syscall == 242:
        #     occurences['mq_timedsend'] = occurences['mq_timedsend'] + 1
        #     # print("Update für folgenden System Call mq_timedsend. Neue Häufigkeit: " + str(
        #     #    occurences['mq_timedsend']))
        # elif syscall == 243:
        #     occurences['mq_timedreceive'] = occurences['mq_timedreceive'] + 1
        #     # print("Update für folgenden System Call mq_timedreceive. Neue Häufigkeit: " + str(
        #     #    occurences['mq_timedreceive']))
        # elif syscall == 244:
        #     occurences['mq_notify'] = occurences['mq_notify'] + 1
        #     # print("Update für folgenden System Call mq_notify. Neue Häufigkeit: " + str(occurences['mq_notify']))
        # elif syscall == 245:
        #     occurences['mq_getsetattr'] = occurences['mq_getsetattr'] + 1
        #     # print("Update für folgenden System Call mq_getsetattr. Neue Häufigkeit: " + str(
        #     #    occurences['mq_getsetattr']))
        # elif syscall == 246:
        #     occurences['kexec_load'] = occurences['kexec_load'] + 1
        #     # print("Update für folgenden System Call kexec_load. Neue Häufigkeit: " + str(occurences['kexec_load']))
        # elif syscall == 247:
        #     occurences['waitid'] = occurences['waitid'] + 1
        #     # print("Update für folgenden System Call waitid. Neue Häufigkeit: " + str(occurences['waitid']))
        # elif syscall == 248:
        #     occurences['add_key'] = occurences['add_key'] + 1
        #     # print("Update für folgenden System Call add_key. Neue Häufigkeit: " + str(occurences['add_key']))
        # elif syscall == 249:
        #     occurences['request_key'] = occurences['request_key'] + 1
        #     # print(
        #     #     "Update für folgenden System Call: request_key. Neue Häufigkeit: " + str(occurences['request_key']))
        # elif syscall == 250:
        #     occurences['keyctl'] = occurences['keyctl'] + 1
        #     # print("Update für folgenden System Call keyctl. Neue Häufigkeit: " + str(occurences['keyctl']))
        # elif syscall == 251:
        #     occurences['ioprio_set'] = occurences['ioprio_set'] + 1
        #     # print("Update für folgenden System Call ioprio_set. Neue Häufigkeit: " + str(occurences['ioprio_set']))
        # elif syscall == 252:
        #     occurences['ioprio_get'] = occurences['ioprio_get'] + 1
        #     # print("Update für folgenden System Call ioprio_get. Neue Häufigkeit: " + str(occurences['ioprio_get']))
        # elif syscall == 253:
        #     occurences['inotify_init'] = occurences['inotify_init'] + 1
        #     # print("Update für folgenden System Call inotify_init. Neue Häufigkeit: " + str(
        #     #    occurences['inotify_init']))
        # elif syscall == 254:
        #     occurences['inotify_add_watch'] = occurences['inotify_add_watch'] + 1
        #     # print("Update für folgenden System Call inotify_add_watch. Neue Häufigkeit: " + str(
        #     #    occurences['inotify_add_watch']))
        # elif syscall == 255:
        #     occurences['inotify_rm_watch'] = occurences['inotify_rm_watch'] + 1
        #     # print("Update für folgenden System Call inotify_rm_watch. Neue Häufigkeit: " + str(
        #     #    occurences['inotify_rm_watch']))
        # elif syscall == 256:
        #     occurences['migrate_pages'] = occurences['migrate_pages'] + 1
        #     # print("Update für folgenden System Call migrate_pages. Neue Häufigkeit: " + str(
        #     #    occurences['migrate_pages']))
        # elif syscall == 257:
        #     occurences['openat'] = occurences['openat'] + 1
        #     # print("Update für folgenden System Call openat. Neue Häufigkeit: " + str(occurences['openat']))
        # elif syscall == 258:
        #     occurences['mkdirat'] = occurences['mkdirat'] + 1
        #     # print("Update für folgenden System Call mkdirat. Neue Häufigkeit: " + str(occurences['mkdirat']))
        # elif syscall == 259:
        #     occurences['mknodat'] = occurences['mknodat'] + 1
        #     # print("Update für folgenden System Call mknodat. Neue Häufigkeit: " + str(occurences['mknodat']))
        # elif syscall == 260:
        #     occurences['fchownat'] = occurences['fchownat'] + 1
        #     # print("Update für folgenden System Call fchownat. Neue Häufigkeit: " + str(occurences['fchownat']))
        # elif syscall == 261:
        #     occurences['futimesat'] = occurences['futimesat'] + 1
        #     # print("Update für folgenden System Call futimesat. Neue Häufigkeit: " + str(occurences['futimesat']))
        # elif syscall == 262:
        #     occurences['newfstatat'] = occurences['newfstatat'] + 1
        #     # print("Update für folgenden System Call newfstatat. Neue Häufigkeit: " + str(occurences['newfstatat']))
        # elif syscall == 263:
        #     occurences['unlinkat'] = occurences['unlinkat'] + 1
        #     # print("Update für folgenden System Call unlinkat. Neue Häufigkeit: " + str(occurences['unlinkat']))
        # elif syscall == 264:
        #     occurences['renameat'] = occurences['renameat'] + 1
        #     # print("Update für folgenden System Call renameat. Neue Häufigkeit: " + str(occurences['renameat']))
        # elif syscall == 265:
        #     occurences['linkat'] = occurences['linkat'] + 1
        #     # print("Update für folgenden System Call linkat. Neue Häufigkeit: " + str(occurences['linkat']))
        # elif syscall == 266:
        #     occurences['symlinkat'] = occurences['symlinkat'] + 1
        #     # print("Update für folgenden System Call symlinkat. Neue Häufigkeit: " + str(occurences['symlinkat']))
        # elif syscall == 267:
        #     occurences['readlinkat'] = occurences['readlinkat'] + 1
        #     # print("Update für folgenden System Call readlinkat. Neue Häufigkeit: " + str(occurences['readlinkat']))
        # elif syscall == 268:
        #     occurences['fchmodat'] = occurences['fchmodat'] + 1
        #     # print("Update für folgenden System Call fchmodat. Neue Häufigkeit: " + str(occurences['fchmodat']))
        # elif syscall == 269:
        #     occurences['faccessat'] = occurences['faccessat'] + 1
        #     # print("Update für folgenden System Call faccessat. Neue Häufigkeit: " + str(occurences['faccessat']))
        # elif syscall == 270:
        #     occurences['pselect6'] = occurences['pselect6'] + 1
        #     # print("Update für folgenden System Call pselect6. Neue Häufigkeit: " + str(occurences['pselect6']))
        # elif syscall == 271:
        #     occurences['ppoll'] = occurences['ppoll'] + 1
        #     # print("Update für folgenden System Call ppoll. Neue Häufigkeit: " + str(occurences['ppoll']))
        # elif syscall == 272:
        #     occurences['unshare'] = occurences['unshare'] + 1
        #     # print("Update für folgenden System Call unshare. Neue Häufigkeit: " + str(occurences['unshare']))
        # elif syscall == 273:
        #     occurences['set_robust_list'] = occurences['set_robust_list'] + 1
        #     # print("Update für folgenden System Call set_robust_list. Neue Häufigkeit: " + str(
        #     #    occurences['set_robust_list']))
        # elif syscall == 274:
        #     occurences['get_robust_list'] = occurences['get_robust_list'] + 1
        #     # print("Update für folgenden System Call get_robust_list. Neue Häufigkeit: " + str(
        #     #    occurences['get_robust_list']))
        # elif syscall == 275:
        #     occurences['splice'] = occurences['splice'] + 1
        #     # print("Update für folgenden System Call splice. Neue Häufigkeit: " + str(occurences['splice']))
        # elif syscall == 276:
        #     occurences['tee'] = occurences['tee'] + 1
        #     # print("Update für folgenden System Call tee. Neue Häufigkeit: " + str(occurences['tee']))
        # elif syscall == 277:
        #     occurences['sync_file_range'] = occurences['sync_file_range'] + 1
        #     # print("Update für folgenden System Call sync_file_range. Neue Häufigkeit: " + str(
        #     #    occurences['sync_file_range']))
        # elif syscall == 278:
        #     occurences['vmsplice'] = occurences['vmsplice'] + 1
        #     # print("Update für folgenden System Call vmsplice. Neue Häufigkeit: " + str(occurences['vmsplice']))
        # elif syscall == 279:
        #     occurences['move_pages'] = occurences['move_pages'] + 1
        #     # print("Update für folgenden System Call move_pages. Neue Häufigkeit: " + str(occurences['move_pages']))
        # elif syscall == 280:
        #     occurences['utimensat'] = occurences['utimensat'] + 1
        #     # print("Update für folgenden System Call utimensat. Neue Häufigkeit: " + str(occurences['utimensat']))
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


def getringbuffer():
    uptime = 0
    b["events"].open_perf_buffer(detectpatterns, page_cnt=256)
    while True:
        try:
            b.perf_buffer_poll(timeout=10 * 1000)
        except KeyboardInterrupt:
            print("Abbruch. Patterns:")
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
ibinary = input("Input Binary: ")
localpids = getpids(ibinary)
print("attaching to kretprobes")
attachkretprobe()
print("attachment ready" + "\n" + "now tracing! \npress CTRL + C to stop tracing.")
getringbuffer()
