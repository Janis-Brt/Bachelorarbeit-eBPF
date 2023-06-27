#define _GNU_SOURCE
#include<sched.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/wait.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>

static char child_stack[2048];

int x = 10;

static int child_fn() {
    printf("Pid: %ld\n", (long) getpid());
    return 0;
}

int main() {
    printf("before= %d\n", x);
    errno = 0;
    pid_t child_pid = clone(&child_fn, (void *) child_stack+1024, CLONE_NEWPID | SIGCHLD, NULL);
    if(child_pid == -1) {
        printf("%s\n", strerror(errno));
        return 0;
    } else {
        printf("clone()= %ld\n", (long) child_pid);
        printf("after= %d\n", x);

        while(waitpid(-1, NULL, 0) < 0 && errno == EINTR) {
            printf("waiting\n");
            continue;
        }

        return 0;
    }
}