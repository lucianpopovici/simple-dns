/* CSA-SBX-002 (CLAUDE-medium-fixes.md 7h): libsandbox privilege drop with
 * keep_net_bind_service. Run as root (sudo, or uid 0 in a user namespace with
 * its own netns): `keep` must end as uid != 0 holding CAP_NET_BIND_SERVICE
 * only (bind 443 ok), `nokeep` with no capabilities (bind 443 refused); in
 * both, setuid(0) must fail. Driven by `make check-sidecar-sandbox`. */
#include "sandbox.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void lg(int level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    (void) level;
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

int main(int argc, char **argv) {
    sandbox_config_t sb;
    sandbox_config_load(&sb, "test", "TEST", NULL);
    sb.keep_net_bind_service = argc > 1 && !strcmp(argv[1], "keep");
    sb.seccomp_default = SANDBOX_SECCOMP_AUDIT;
    sb.log = lg;
    sb.tag = "t";
    sandbox_apply(&sb);
    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    while (f && fgets(line, sizeof(line), f))
        if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) ||
            !strncmp(line, "CapPrm:", 7))
            fputs(line, stdout);
    if (f)
        fclose(f);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(443)};
    printf("bind 443: %s\n",
           bind(fd, (struct sockaddr *) &sa, sizeof(sa)) == 0 ? "ok" : "EACCES/failed");
    printf("setuid(0): %s\n", setuid(0) == 0 ? "REGAINED ROOT" : "refused");
    return 0;
}
