/* Closed-loop UDP DNS query generator for `make check-resolverd-stress` /
 * `check-resolverd-tsan` (CLAUDE-resolverd-cache.md, CSA-CONC-001).
 *
 *   udp_stress <port> <threads> <seconds> <a|nx> <label-1> <label-2>
 *
 * Mode "a" queries www.<label-1>.<label-2> A (one hot name: concurrent
 * replace of the same cache entry); "nx" queries r<00-3f>.<label-1>.<label-2> A
 * (64 names against a tiny cache: constant insert, replace and eviction). Prints "<mode> <qps> qps
 * timeouts=<n>". */
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_THREADS 64

static int g_port;
static int g_secs;
static const char *g_mode;
static const char *g_l1;
static const char *g_l2;
static long g_ok[MAX_THREADS];
static long g_timeouts[MAX_THREADS];

static int put_label(unsigned char *b, int o, const char *lab) {
    int n = (int) strlen(lab);
    if (n > 63)
        n = 63;
    b[o++] = (unsigned char) n;
    memcpy(b + o, lab, (size_t) n);
    return o + n;
}

static int make_query(unsigned char *b, unsigned id, unsigned r) {
    memset(b, 0, 12);
    b[0] = (unsigned char) (id >> 8);
    b[1] = (unsigned char) id;
    b[2] = 1; /* RD */
    b[5] = 1; /* QDCOUNT */
    int o = 12;
    char lab[32];
    if (g_mode[0] == 'a')
        snprintf(lab, sizeof(lab), "www");
    else
        snprintf(lab, sizeof(lab), "r%02x", r % 64); /* small name space: concurrent misses
                                                         of one name -> racing replaces */
    o = put_label(b, o, lab);
    o = put_label(b, o, g_l1);
    o = put_label(b, o, g_l2);
    b[o++] = 0;
    b[o++] = 0;
    b[o++] = 1; /* A */
    b[o++] = 0;
    b[o++] = 1; /* IN */
    return o;
}

static void *run(void *arg) {
    long i = (long) arg;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return NULL;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t) g_port);
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (connect(s, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        close(s);
        return NULL;
    }
    struct timeval tv = {1, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    unsigned char b[512];
    unsigned char r[4096];
    time_t end = time(NULL) + g_secs;
    unsigned seed = (unsigned) (i * 7919 + 1);
    while (time(NULL) < end) {
        int n = make_query(b, (unsigned) rand_r(&seed), (unsigned) rand_r(&seed));
        if (send(s, b, (size_t) n, 0) < 0) {
            g_timeouts[i]++;
            continue;
        }
        if (recv(s, r, sizeof(r), 0) > 0)
            g_ok[i]++;
        else
            g_timeouts[i]++;
    }
    close(s);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "usage: %s <port> <threads> <seconds> <a|nx> <label-1> <label-2>\n",
                argv[0]);
        return 2;
    }
    g_port = atoi(argv[1]);
    int t = atoi(argv[2]);
    g_secs = atoi(argv[3]);
    g_mode = argv[4];
    g_l1 = argv[5];
    g_l2 = argv[6];
    if (t < 1)
        t = 1;
    if (t > MAX_THREADS)
        t = MAX_THREADS;
    pthread_t th[MAX_THREADS];
    int started = 0;
    for (long i = 0; i < t; i++)
        if (pthread_create(&th[started], NULL, run, (void *) i) == 0)
            started++;
    long ok = 0;
    long to = 0;
    for (int i = 0; i < started; i++) {
        pthread_join(th[i], NULL);
        ok += g_ok[i];
        to += g_timeouts[i];
    }
    printf("%s %.0f qps timeouts=%ld\n", g_mode, g_secs > 0 ? (double) ok / g_secs : 0.0, to);
    return 0;
}
