#ifndef TP_WORKER_H
#define TP_WORKER_H

#include <stdatomic.h>
#include <stdint.h>
#include <netdb.h>

/* Worker args / results.
 * Worker will fill conn_times/tls_times arrays up to capacity (success count returned in successes).
 *
 * cipher_names: buffer of capacity * 64 bytes (each entry 64 bytes)
 * tls_versions: buffer of capacity * 16 bytes (each entry 16 bytes)
 *
 * New field:
 *   signalfd : signalfd file descriptor created by main and added to each worker's epoll.
 */
struct worker_args {
    int thread_id;
    const char *host;
    const char *servername;
    const struct addrinfo *ai;
    int port;
    int timeout_sec;
    int skip_verify;
    const char *cipher_str;
    const char *groups_str;
    int slots_count;            /* per-thread concurrency (set by main) */
    atomic_int *tasks_left;     /* shared atomic counter (remaining tasks) */
    atomic_int *stop_flag;      /* shared stop flag (set by signalfd event) */
    int set_affinity_auto;      /* if non-zero, set CPU affinity auto in worker */
    int total_count;
    int signalfd;               /* signalfd fd provided by main (or -1 if not used) */
    /* outputs (allocated by main): */
    int64_t *conn_times;
    int64_t *tls_times;
    char *cipher_names;         /* capacity * 64 bytes */
    char *tls_versions;         /* capacity * 16 bytes */
    char *group_names;          /* capacity * 32 */
    int capacity;               /* capacity of the arrays */
    int successes;              /* number recorded in arrays */
    int failures;               /* counted failures */
};

/* Entry point for worker thread (to be passed to pthread_create) */
void *worker_run(void *arg);

#endif /* TP_WORKER_H */