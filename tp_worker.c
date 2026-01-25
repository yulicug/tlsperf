#define _GNU_SOURCE
#include "tp_worker.h"
#include "tp_util.h"
#include "tp_tls.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <sched.h>

/* slot state */
typedef enum {
    SLOT_FREE = 0,
    SLOT_CONNECTING,
    SLOT_HANDSHAKING
} slot_state_e;

typedef struct {
    int id;
    int fd;
    SSL *ssl;
    slot_state_e state;
    int64_t start_ms;
    int64_t deadline_ms;
    const struct addrinfo *ai;
    int64_t conn_ms;
    int64_t tls_start_ms;
} slot_t;

/* forward declarations */
static int slot_start_attempt(slot_t *s, int epfd, SSL_CTX *ctx,
                              const char *servername, int timeout_sec, int skip_verify);
static void slot_cleanup(slot_t *s, int epfd);
static int slot_process_event(slot_t *s, int epfd, uint32_t events,
                              SSL_CTX *ctx, const char *servername, int timeout_sec, int skip_verify);

/* task claim */
static int
claim_task(atomic_int *tasks_left, atomic_int *stop_flag)
{
    int cur;

    if (stop_flag && atomic_load(stop_flag)) {
        return 0;
    }
    cur = atomic_load(tasks_left);
    while (cur > 0) {
        if (stop_flag && atomic_load(stop_flag)) {
            return 0;
        }
        if (atomic_compare_exchange_weak(tasks_left, &cur, cur - 1)) {
            return 1;
        }
    }
    return 0;
}

/* record a sample if buffer not full */
static inline void
record_sample(struct worker_args *w, int *pidx, int cap,
              int64_t conn_ms, int64_t tls_ms, SSL *ssl)
{
    int idx;

    if (*pidx >= cap) {
        return;
    }
    idx = *pidx;
    w->conn_times[idx] = conn_ms;
    w->tls_times[idx] = tls_ms;

    if (w->cipher_names) {
        const char *cname = SSL_get_cipher_name(ssl);
        if (cname) {
            strncpy(&w->cipher_names[idx * 64], cname, 63);
        } else {
            w->cipher_names[idx * 64] = '\0';
        }
    }
    if (w->tls_versions) {
        const char *v = SSL_get_version(ssl);
        if (v) {
            strncpy(&w->tls_versions[idx * 16], v, 15);
        } else {
            w->tls_versions[idx * 16] = '\0';
        }
    }

    if (w->group_names) {
#if defined(OPENSSL_IS_BORINGSSL)
        uint16_t group_id = SSL_get_curve_id(ssl);
#else
        int group_id = SSL_get_shared_group(ssl, 0);  /* 成功握手后 */
#endif
        const char *gname = NULL;
        if (group_id > 0) {
#if defined(OPENSSL_IS_BORINGSSL)
            gname = SSL_get_curve_name(group_id);  /* BoringSSL: IANA group id -> 名称 */
#else
            gname = OBJ_nid2sn(group_id);          /* OpenSSL/Tongsuo: NID -> 短名称 */
#endif
        }
        if (gname) {
            strncpy(&w->group_names[idx * 32], gname, 31);
        } else {
            w->group_names[idx * 32] = '\0';
        }
    }
    (*pidx)++;
}

/* start a non-blocking connect on slot; returns:
 *  -1: immediate error
 *   0: pending (registered for EPOLLOUT)
 *   1: connected and started handshake
 */
static int
slot_start_attempt(slot_t *s, int epfd, SSL_CTX *ctx,
                   const char *servername, int timeout_sec, int skip_verify)
{
    int sock;
    int c;
    int r;
    int serr;
    uint32_t want;

    sock = socket(s->ai->ai_family, s->ai->ai_socktype, s->ai->ai_protocol);
    if (sock < 0) {
        return -1;
    }
    if (set_nonblock(sock) != 0) {
        close(sock);
        return -1;
    }
    s->fd = sock;
    s->start_ms = now_ms();
    s->deadline_ms = s->start_ms + (int64_t)timeout_sec * 1000;
    s->state = SLOT_CONNECTING;
    s->conn_ms = 0;
    s->tls_start_ms = 0;

    c = connect(sock, s->ai->ai_addr, s->ai->ai_addrlen);
    if (c == 0) {
        /* connected immediately */
    } else if (c < 0) {
        if (errno != EINPROGRESS) {
            close(sock);
            s->fd = -1;
            s->state = SLOT_FREE;
            return -1;
        }
        if (epoll_add_or_mod(epfd, sock, s, EPOLLOUT) != 0) {
            close(sock);
            s->fd = -1;
            s->state = SLOT_FREE;
            return -1;
        }
        return 0;
    }

    s->conn_ms = now_ms() - s->start_ms;
    s->tls_start_ms = now_ms();

    s->ssl = SSL_new(ctx);
    if (!s->ssl) {
        close(sock);
        s->fd = -1;
        s->state = SLOT_FREE;
        return -1;
    }

    if (servername && *servername) {
        SSL_set_tlsext_host_name(s->ssl, servername);
    }

    if (!skip_verify) {
        SSL_set_verify(s->ssl, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_set_verify(s->ssl, SSL_VERIFY_NONE, NULL);
    }

    SSL_set_fd(s->ssl, s->fd);
    s->state = SLOT_HANDSHAKING;

    r = SSL_connect(s->ssl);
    if (r == 1) {
        return 1;
    }

    serr = SSL_get_error(s->ssl, r);
    want = 0;
    if (serr == SSL_ERROR_WANT_READ) {
        want = EPOLLIN;
    } else if (serr == SSL_ERROR_WANT_WRITE) {
        want = EPOLLOUT;
    } else {
        SSL_free(s->ssl);
        s->ssl = NULL;
        close(sock);
        s->fd = -1;
        s->state = SLOT_FREE;
        return -1;
    }
    if (epoll_add_or_mod(epfd, s->fd, s, want) != 0) {
        SSL_free(s->ssl);
        s->ssl = NULL;
        close(sock);
        s->fd = -1;
        s->state = SLOT_FREE;
        return -1;
    }
    return 0;
}

/* cleanup slot */
static void
slot_cleanup(slot_t *s, int epfd)
{
    if (s->fd >= 0) {
        epoll_remove_fd(epfd, s->fd);
        close(s->fd);
        s->fd = -1;
    }
    if (s->ssl) {
        SSL_free(s->ssl);
        s->ssl = NULL;
    }
    s->state = SLOT_FREE;
    s->conn_ms = 0;
    s->tls_start_ms = 0;
}

/* process events for a slot
 * return:
 *  0 = pending
 *  1 = handshake succeeded
 * -1 = handshake failed
 */
static int
slot_process_event(slot_t *s, int epfd, uint32_t events, SSL_CTX *ctx,
                   const char *servername, int timeout_sec, int skip_verify)
{
    int64_t now;
    int soerr;
    socklen_t len;
    int r;
    int serr;
    uint32_t want;

    (void)timeout_sec;
    now = now_ms();
    if (now > s->deadline_ms) {
        slot_cleanup(s, epfd);
        return -1;
    }

    if (s->state == SLOT_CONNECTING) {
        soerr = 0;
        len = sizeof(soerr);
        if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0) {
            slot_cleanup(s, epfd);
            return -1;
        }

        if (soerr != 0) {
            errno = soerr;
            slot_cleanup(s, epfd);
            return -1;
        }

        s->conn_ms = now_ms() - s->start_ms;
        s->tls_start_ms = now_ms();

        s->ssl = SSL_new(ctx);
        if (!s->ssl) {
            slot_cleanup(s, epfd);
            return -1;
        }
        if (servername && *servername) {
            SSL_set_tlsext_host_name(s->ssl, servername);
        }

        if (!skip_verify) {
            SSL_set_verify(s->ssl, SSL_VERIFY_PEER, NULL);
        } else {
            SSL_set_verify(s->ssl, SSL_VERIFY_NONE, NULL);
        }

        SSL_set_fd(s->ssl, s->fd);
        s->state = SLOT_HANDSHAKING;

        r = SSL_connect(s->ssl);
        if (r == 1) {
            return 1;
        }

        serr = SSL_get_error(s->ssl, r);
        want = 0;
        if (serr == SSL_ERROR_WANT_READ) {
            want = EPOLLIN;
        } else if (serr == SSL_ERROR_WANT_WRITE) {
            want = EPOLLOUT;
        } else {
            slot_cleanup(s, epfd);
            return -1;
        }
        if (epoll_add_or_mod(epfd, s->fd, s, want) != 0) {
            slot_cleanup(s, epfd);
            return -1;
        }

        return 0;
    }

    if (s->state == SLOT_HANDSHAKING) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            slot_cleanup(s, epfd);
            return -1;
        }

        r = SSL_connect(s->ssl);
        if (r == 1) {
            return 1;
        }

        serr = SSL_get_error(s->ssl, r);
        want = 0;
        if (serr == SSL_ERROR_WANT_READ) {
            want = EPOLLIN;
        } else if (serr == SSL_ERROR_WANT_WRITE) {
            want = EPOLLOUT;
        } else {
            slot_cleanup(s, epfd);
            return -1;
        }

        if (epoll_add_or_mod(epfd, s->fd, s, want) != 0) {
            slot_cleanup(s, epfd);
            return -1;
        }
        return 0;
    }

    slot_cleanup(s, epfd);
    return -1;
}

/* helpers */
static void
handle_success(slot_t *s, struct worker_args *w, int epfd, SSL_CTX *ctx, int *pidx, int cap)
{
    int rc;

    record_sample(w, pidx, cap, s->conn_ms, now_ms() - s->tls_start_ms, s->ssl);
    w->successes++;

    SSL_shutdown(s->ssl);
    slot_cleanup(s, epfd);

    if (claim_task(w->tasks_left, w->stop_flag)) {
        rc = slot_start_attempt(s, epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
        if (rc < 0) {
            w->failures++;
            slot_cleanup(s, epfd);
        } else if (rc == 1) {
            record_sample(w, pidx, cap, s->conn_ms, now_ms() - s->tls_start_ms, s->ssl);
            w->successes++;
            SSL_shutdown(s->ssl);
            slot_cleanup(s, epfd);
        }
    }
}

static void
handle_failure(slot_t *s, struct worker_args *w, int epfd, SSL_CTX *ctx, int *pidx, int cap)
{
    int rc;

    (void)pidx;
    (void)cap;

    w->failures++;
    slot_cleanup(s, epfd);

    if (claim_task(w->tasks_left, w->stop_flag)) {
        rc = slot_start_attempt(s, epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
        if (rc < 0) {
            w->failures++;
            slot_cleanup(s, epfd);
        } else if (rc == 1) {
            record_sample(w, pidx, cap, s->conn_ms, now_ms() - s->tls_start_ms, s->ssl);
            w->successes++;
            SSL_shutdown(s->ssl);
            slot_cleanup(s, epfd);
        }
    }
}

static void
initial_fill(slot_t *slots, int sc, struct worker_args *w, int epfd, SSL_CTX *ctx, int *pidx, int cap)
{
    int i;
    int rc;

    for (i = 0; i < sc; ++i) {
        if (!claim_task(w->tasks_left, w->stop_flag)) {
            break;
        }

        rc = slot_start_attempt(&slots[i], epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
        if (rc < 0) {
            w->failures++;
        } else if (rc == 1) {
            record_sample(w, pidx, cap, slots[i].conn_ms, now_ms() - slots[i].tls_start_ms, slots[i].ssl);
            w->successes++;
            slot_cleanup(&slots[i], epfd);
        }
    }
}

static void
deadline_sweep(slot_t *slots, int sc, struct worker_args *w, int epfd, SSL_CTX *ctx, int *pidx, int cap)
{
    int i;
    int rc;
    int64_t tnow;

    tnow = now_ms();
    for (i = 0; i < sc; ++i) {
        if (slots[i].state != SLOT_FREE && tnow > slots[i].deadline_ms) {
            w->failures++;
            slot_cleanup(&slots[i], epfd);
            if (claim_task(w->tasks_left, w->stop_flag)) {
                rc = slot_start_attempt(&slots[i], epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
                if (rc < 0) {
                    w->failures++;
                    slot_cleanup(&slots[i], epfd);
                } else if (rc == 1) {
                    record_sample(w, pidx, cap, slots[i].conn_ms, now_ms() - slots[i].tls_start_ms, slots[i].ssl);
                    w->successes++;
                    SSL_shutdown(slots[i].ssl);
                    slot_cleanup(&slots[i], epfd);
                }
            }
        }
    }
}

/* worker thread implementation */
void *
worker_run(void *arg)
{
    struct worker_args *w;
    int epfd;
    SSL_CTX *ctx;
    slot_t *slots;
    int cap;
    int idx;
    int sc;
    int i;
    int rc;
    struct epoll_event events[64];

    w = (struct worker_args *)arg;
    epfd = -1;
    ctx = NULL;
    slots = NULL;
    cap = w->capacity;
    idx = 0;

    ctx = create_thread_ctx(w->cipher_str, w->groups_str, w->skip_verify);
    if (!ctx) {
        fprintf(stderr, "thread %d: SSL_CTX_new failed\n", w->thread_id);
        goto out;
    }

    epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        goto out;
    }

    /* optional CPU affinity */
    if (w->set_affinity_auto) {
        long nprocs;
        int cpu;
        cpu_set_t cpus;

        nprocs = sysconf(_SC_NPROCESSORS_ONLN);
        if (nprocs > 0) {
            cpu = w->thread_id % (int)nprocs;
            CPU_ZERO(&cpus);
            CPU_SET(cpu, &cpus);
            (void)sched_setaffinity(0, sizeof(cpus), &cpus);
        }
    }

    /* register signalfd if provided (for graceful stop) */
    if (w->signalfd >= 0) {
        struct epoll_event sev;

        memset(&sev, 0, sizeof(sev));
        sev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
        sev.data.ptr = &w->signalfd; /* marker */
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, w->signalfd, &sev) != 0) {
            perror("epoll_ctl add signalfd");
        }
    }

    sc = w->slots_count;
    slots = calloc((size_t)sc, sizeof(slot_t));
    if (!slots) {
        perror("calloc slots");
        goto out;
    }
    for (i = 0; i < sc; ++i) {
        slots[i].id = i;
        slots[i].fd = -1;
        slots[i].ssl = NULL;
        slots[i].state = SLOT_FREE;
        slots[i].ai = w->ai;
        slots[i].conn_ms = 0;
        slots[i].tls_start_ms = 0;
    }

    /* initial fill */
    initial_fill(slots, sc, w, epfd, ctx, &idx, cap);

    /* main loop */
    while (1) {
        int active;
        int n;

        active = 0;
        for (i = 0; i < sc; ++i) {
            if (slots[i].state != SLOT_FREE) {
                active = 1;
                break;
            }
        }

        if (!active) {
            if (!claim_task(w->tasks_left, w->stop_flag)) {
                break;
            }
            for (i = 0; i < sc; ++i) {
                if (slots[i].state == SLOT_FREE) {
                    rc = slot_start_attempt(&slots[i], epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
                    if (rc < 0) {
                        w->failures++;
                    } else if (rc == 1) {
                        record_sample(w, &idx, cap, slots[i].conn_ms, now_ms() - slots[i].tls_start_ms, slots[i].ssl);
                        w->successes++;
                        SSL_shutdown(slots[i].ssl);
                        slot_cleanup(&slots[i], epfd);
                    }
                    break;
                }
            }
        }

        n = epoll_wait(epfd, events, sizeof(events) / sizeof(events[0]), 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            break;
        }

        for (i = 0; i < n; ++i) {
            slot_t *s;
            int res;

            if (w->signalfd >= 0 && events[i].data.ptr == &w->signalfd) {
                struct signalfd_siginfo fdsi;
                ssize_t rbytes;

                rbytes = read(w->signalfd, &fdsi, sizeof(fdsi));
                (void)rbytes;
                atomic_store(w->stop_flag, 1);
                /* graceful: do not start new tasks; let active slots finish */
                continue;
            }

            s = (slot_t *)events[i].data.ptr;
            res = 0;

            if (!s) {
                continue;
            }
            res = slot_process_event(s, epfd, events[i].events, ctx, w->servername, w->timeout_sec, w->skip_verify);
            if (res == 0) {
                continue;
            }
            if (res == 1) {
                handle_success(s, w, epfd, ctx, &idx, cap);
            } else {
                handle_failure(s, w, epfd, ctx, &idx, cap);
            }
        }

        deadline_sweep(slots, sc, w, epfd, ctx, &idx, cap);
    }

    w->successes = idx;

out:
    if (slots) {
        for (i = 0; i < w->slots_count; ++i) {
            slot_cleanup(&slots[i], epfd);
        }
        free(slots);
    }
    if (epfd >= 0) {
        close(epfd);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    return NULL;
}
