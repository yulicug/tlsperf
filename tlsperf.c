#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>           /* getaddrinfo, freeaddrinfo, struct addrinfo, gai_strerror */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/signalfd.h>

#include "tp_worker.h"
#include "tp_util.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "0.0.0"
#endif

static void print_usage(const char *prog) {
    printf(
        "Usage: %s <host-or-ip> [options]\n"
        "TLS handshake perf tester (epoll + non-blocking sockets, multi-threaded)\n\n"
        "Positional:\n"
        "  host-or-ip             : target hostname or IP address (required)\n\n"
        "Options:\n"
        "  -p <port>              : TCP port to connect (default: 443)\n"
        "  -n <count>             : total number of handshakes to perform (default: 1000)\n"
        "  -c <concurrency>       : TOTAL concurrency across all threads (default: 100)\n"
        "  -T <threads>           : number of worker threads (default: number of online CPUs)\n"
        "  -t <timeout>           : per-handshake timeout in seconds (default: 5)\n"
        "  -k                     : skip certificate verification (INSECURE)\n"
        "  -s <servername>        : SNI / server name to send (useful when host is IP)\n"
        "  -C <ciphers>           : OpenSSL cipher list / TLS1.3 ciphersuites string\n"
        "  -G <groups>            : TLS groups/curves list (e.g. \"X25519:P-256\"; BoringSSL: \"X25519MLKEM768:X25519\")\n"
        "  -A auto                : enable CPU affinity auto-binding (thread_id %% ncpus)\n"
        "  -h, --help             : show this help and exit\n"
        "  --version              : print version and exit\n\n"
        "Examples:\n"
        "  %s example.com -n 1000 -c 200 -T 2 -t 10 -s example.com -C \"TLS_AES_128_GCM_SHA256\" -A auto\n"
        "  %s 1.2.3.4 -n 100 -c 50 -k\n\n",
        prog, prog, prog);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *host = argv[1];
    const char *servername = NULL;
    int port = 443;
    int total_concurrency = 100;
    int count = 1000;
    int threads = 0;
    int timeout_sec = 5;
    int skip_verify = 0;
    char *cipher_str = NULL;
    char *groups_str = NULL;
    int set_affinity_auto = 0;

    for (int i = 2; i < argc; ++i) {
        if ((strcmp(argv[i], "-p") == 0) && i + 1 < argc)
            port = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-n") == 0) && i + 1 < argc)
            count = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-c") == 0) && i + 1 < argc)
            total_concurrency = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-T") == 0) && i + 1 < argc)
            threads = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-t") == 0) && i + 1 < argc)
            timeout_sec = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-k") == 0))
            skip_verify = 1;
        else if ((strcmp(argv[i], "-s") == 0) && i + 1 < argc)
            servername = argv[++i];
        else if ((strcmp(argv[i], "-C") == 0) && i + 1 < argc)
            cipher_str = argv[++i];
        else if ((strcmp(argv[i], "-G") == 0) && i + 1 < argc)
            groups_str = argv[++i];
        else if ((strcmp(argv[i], "-A") == 0) && i + 1 < argc) {
            if (strcmp(argv[i+1], "auto") == 0) {
                set_affinity_auto = 1;
                i++;
            } else {
                fprintf(stderr, "Unsupported -A value: %s\n", argv[i+1]);
                return 1;
            }
        } else if ((strcmp(argv[i], "-h") == 0)
                   || (strcmp(argv[i], "--help") == 0))
        {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("%s version %s\n", argv[0], PACKAGE_VERSION);
            return 0;
        } else {
            fprintf(stderr, "Unknown arg: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (total_concurrency < 1)
        total_concurrency = 1;

    if (threads <= 0) {
        long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
        threads = (nprocs > 0) ? (int)nprocs : 1;
    }
    if (threads < 1)
        threads = 1;

    int base_slots = total_concurrency / threads;
    int rem = total_concurrency % threads;
    if (base_slots < 1)
        base_slots = 1;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "getaddrinfo(%s:%s) failed: %s\n", host, portstr,
                gai_strerror(gai));
        return 1;
    }

    /* Block signals and create signalfd before creating threads.
     * This ensures signals are delivered to signalfd rather than arbitrary threads.
     */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) {
        perror("pthread_sigmask");
        /* continue anyway */
    }

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0) {
        perror("signalfd");
        /* continue without signalfd: workers will have no signal integration */
        sfd = -1;
    }

    /* OpenSSL init */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    atomic_int tasks_left;
    atomic_init(&tasks_left, count);

    atomic_int stop_flag;
    atomic_init(&stop_flag, 0);

    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    struct worker_args *wargs = calloc((size_t)threads, sizeof(struct worker_args));
    if (!tids || !wargs) {
        perror("calloc threads");
        free(tids);
        free(wargs);
        freeaddrinfo(res);
        if (sfd>=0)
            close(sfd);
        return 1;
    }

    int approx = (count + threads - 1) / threads;
    int capacity = approx + 16;

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    for (int i = 0; i < threads; ++i) {
        int slots_for_thread = base_slots + (i < rem ? 1 : 0);
        wargs[i].thread_id = i;
        wargs[i].host = host;
        wargs[i].servername = servername ? servername : host;
        wargs[i].ai = res;
        wargs[i].port = port;
        wargs[i].timeout_sec = timeout_sec;
        wargs[i].skip_verify = skip_verify;
        wargs[i].cipher_str = cipher_str;
        wargs[i].groups_str = groups_str;
        wargs[i].slots_count = slots_for_thread;
        wargs[i].tasks_left = &tasks_left;
        wargs[i].stop_flag = &stop_flag;
        wargs[i].set_affinity_auto = set_affinity_auto;
        wargs[i].total_count = count;
        wargs[i].capacity = capacity;
        wargs[i].signalfd = sfd;
        wargs[i].conn_times = calloc((size_t)capacity, sizeof(int64_t));
        wargs[i].tls_times = calloc((size_t)capacity, sizeof(int64_t));
        wargs[i].cipher_names = calloc((size_t)capacity, 64);
        wargs[i].group_names = calloc((size_t)capacity, 32);
        wargs[i].tls_versions = calloc((size_t)capacity, 16);
        wargs[i].successes = 0;
        wargs[i].failures = 0;

        if (!wargs[i].conn_times || !wargs[i].tls_times
            || !wargs[i].cipher_names || !wargs[i].tls_versions)
        {
            perror("calloc per-thread arrays");
            for (int j = 0; j <= i; ++j) {
                free(wargs[j].conn_times);
                free(wargs[j].tls_times);
                free(wargs[j].cipher_names);
                free(wargs[j].tls_versions);
            }
            free(tids);
            free(wargs);
            freeaddrinfo(res);
            if (sfd >= 0)
                close(sfd);
            return 1;
        }

        if (pthread_create(&tids[i], NULL, worker_run, &wargs[i]) != 0) {
            perror("pthread_create");
            for (int j = 0; j <= i; ++j) {
                free(wargs[j].conn_times);
                free(wargs[j].tls_times);
                free(wargs[j].cipher_names);
                free(wargs[j].tls_versions);
            }
            free(tids);
            free(wargs);
            freeaddrinfo(res);
            if (sfd>=0)
                close(sfd);
            return 1;
        }
    }

    /* wait and aggregate */
    int total_success = 0, total_fail = 0, total_recorded = 0;
    int64_t *all_conn = calloc((size_t)count, sizeof(int64_t));
    int64_t *all_tls = calloc((size_t)count, sizeof(int64_t));
    char *all_ciphers = calloc((size_t)count, 64);
    char *all_groups = calloc((size_t)count, 32);
    char *all_versions = calloc((size_t)count, 16);
    if (!all_conn || !all_tls || !all_ciphers || !all_versions) {
        perror("calloc all");
        if (sfd>=0)
            close(sfd);
        return 1;
    }

    for (int i = 0; i < threads; ++i) {
        pthread_join(tids[i], NULL);
        total_success += wargs[i].successes;
        total_fail += wargs[i].failures;
        int copy_n = wargs[i].successes;
        for (int j = 0; j < copy_n && total_recorded < count; ++j) {
            all_conn[total_recorded] = wargs[i].conn_times[j];
            all_tls[total_recorded] = wargs[i].tls_times[j];
            memcpy(&all_ciphers[total_recorded * 64],
                   &wargs[i].cipher_names[j * 64], 64);
            memcpy(&all_versions[total_recorded * 16],
                   &wargs[i].tls_versions[j * 16], 16);
            memcpy(&all_groups[total_recorded * 32],
                   &wargs[i].group_names[j * 32], 32);
            total_recorded++;
        }
        free(wargs[i].conn_times);
        free(wargs[i].tls_times);
        free(wargs[i].cipher_names);
        free(wargs[i].group_names);
        free(wargs[i].tls_versions);
    }

    if (sfd >= 0)
        close(sfd);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    double elapsed = (ts_end.tv_sec - ts_start.tv_sec) +
                        (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    double cps = elapsed > 0 ? total_success / elapsed : 0.0;

    printf("Target: %s:%d  total=%d  threads=%d  concurrency=%d  timeout=%ds"
           "  skip_verify=%s  sni=%s  ciphers=%s\n",
           host, port, count, threads, total_concurrency, timeout_sec,
           skip_verify ? "yes":"no", servername?servername:"(none)",
           cipher_str?cipher_str:"(default)");

    printf("\nResults:\n  total attempts: %d\n  successful : %d\n"
           "  failed     : %d\n",
           count, total_success, total_fail);

    if (total_recorded > 0) {
        qsort(all_conn, (size_t)total_recorded, sizeof(int64_t), cmp_int64);
        qsort(all_tls, (size_t)total_recorded, sizeof(int64_t), cmp_int64);

        double avg_conn = avg_int64(all_conn, total_recorded);
        double avg_tls = avg_int64(all_tls, total_recorded);

        int64_t p50_conn = percentile_int64(all_conn, total_recorded, 50.0);
        int64_t p90_conn = percentile_int64(all_conn, total_recorded, 90.0);
        int64_t p99_conn = percentile_int64(all_conn, total_recorded, 99.0);

        int64_t p50_tls = percentile_int64(all_tls, total_recorded, 50.0);
        int64_t p90_tls = percentile_int64(all_tls, total_recorded, 90.0);
        int64_t p99_tls = percentile_int64(all_tls, total_recorded, 99.0);

        printf("\nTCP connect (ms):\n  avg: %.3f  min: %" PRId64 "  "
               "max: %" PRId64 "\n",
               avg_conn, all_conn[0], all_conn[total_recorded-1]);
        printf("  p50: %" PRId64 "  p90: %" PRId64 "  p99: %" PRId64 "\n",
               p50_conn, p90_conn, p99_conn);

        printf("\nTLS handshake (ms):\n  avg: %.3f  min: %" PRId64 "  "
               "max: %" PRId64 "\n",
               avg_tls, all_tls[0], all_tls[total_recorded-1]);
        printf("  p50: %" PRId64 "  p90: %" PRId64 "  p99: %" PRId64 "\n",
               p50_tls, p90_tls, p99_tls);

        struct kv { char name[64]; int cnt; };
        struct kv *ciphers = calloc(256, sizeof(struct kv));
        int ciphers_n = 0;
        struct kv *groups = calloc(256, sizeof(struct kv));
        int groups_n = 0;
        struct kv *vers = calloc(16, sizeof(struct kv));
        int vers_n = 0;

        for (int i = 0; i < total_recorded; ++i) {
            char *c = &all_ciphers[i * 64];
            if (c && c[0]) {
                int found = 0;
                for (int k = 0; k < ciphers_n; ++k)
                    if (strcmp(ciphers[k].name, c) == 0) {
                        ciphers[k].cnt++;
                        found = 1;
                        break;
                    }
                if (!found) {
                    strncpy(ciphers[ciphers_n].name, c, 63);
                    ciphers[ciphers_n].cnt = 1;
                    ciphers_n++;
                }
            }

            char *g = &all_groups[i * 32];
            if (g && g[0]) {
                int found = 0;
                for (int k = 0; k < groups_n; ++k)
                    if (strcmp(groups[k].name, g) == 0) {
                        groups[k].cnt++;
                        found = 1;
                        break;
                    }
                if (!found) {
                    strncpy(groups[groups_n].name, g, 63);
                    groups[groups_n].cnt = 1;
                    groups_n++;
                }
            }
            char *v = &all_versions[i * 16];
            if (v && v[0]) {
                int found = 0;
                for (int k = 0; k < vers_n; ++k)
                    if (strcmp(vers[k].name, v) == 0) {
                        vers[k].cnt++;
                        found = 1;
                        break;
                    }
                if (!found) {
                    strncpy(vers[vers_n].name, v, 15);
                    vers[vers_n].cnt = 1;
                    vers_n++;
                }
            }
        }

        printf("\nTLS versions distribution:\n");
        for (int i = 0; i < vers_n; ++i)
            printf("  %s : %d\n", vers[i].name, vers[i].cnt);

        printf("\nGroup distribution (unique %d):\n", groups_n);
        for (int i = 0; i < groups_n; ++i)
            printf("  %s : %d\n", groups[i].name, groups[i].cnt);

        printf("\nCipher distribution (unique %d):\n", ciphers_n);
        for (int i = 0; i < ciphers_n; ++i)
            printf("  %s : %d\n", ciphers[i].name, ciphers[i].cnt);

        printf("\nElapsed: %.3f s, CPS (success): %.2f\n", elapsed, cps);

        free(ciphers);
        free(groups);
        free(vers);
    } else {
        printf("  no recorded successful handshakes\n");
    }

    free(all_conn);
    free(all_tls);
    free(all_ciphers);
    free(all_versions);
    free(tids);
    free(wargs);
    freeaddrinfo(res);

    ERR_free_strings();
    EVP_cleanup();

    return 0;
}
