#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STACK_SIZE 65536

// Funktion, die im Kindprozess ausgeführt wird
int child_function(void *arg) {
    printf("Kindprozess: PID = %d\n", getpid());
    printf("Kindprozess: Parent PID = %d\n", getppid());

    return 0;
}

int main() {
    printf("Elternprozess: PID = %d\n", getpid());

    // Erzeugen eines Stacks für den Kindprozess
    char *stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        perror("Fehler beim Allozieren des Stacks");
        exit(EXIT_FAILURE);
    }

    // Aufruf von clone(), um den Kindprozess zu erzeugen und die child_function darin auszuführen
    pid_t pid = clone(child_function, stack + STACK_SIZE, CLONE_NEWPID | SIGCHLD, NULL);
    if (pid == -1) {
        perror("Fehler beim Erzeugen des Kindprozesses");
        exit(EXIT_FAILURE);
    }

    // Warten auf den Abschluss des Kindprozesses
    if (waitpid(pid, NULL, 0) == -1) {
        perror("Fehler beim Warten auf den Kindprozess");
        exit(EXIT_FAILURE);
    }

    free(stack);
    return 0;
}
