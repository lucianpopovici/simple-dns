/* ==========================================================================
 * sandbox.h — shared privilege-drop / filesystem-isolation / seccomp sandbox
 *
 * One implementation linked by every daemon that confines itself after binding
 * its privileged resources (dnsd, resolverd). It replaces the per-daemon copies
 * that used to live in dns_server.c and resolverd.c — CLAUDE.md's core rule is
 * "one implementation, no duplicated copies"; a hardening fix to the privilege
 * sequence or the syscall whitelist now lands in exactly one place.
 *
 * Order (applied by sandbox_apply): resolve the unprivileged account (getpwnam,
 * while the passwd database is still reachable) -> confine the filesystem
 * (chroot or a private mount namespace) -> irreversibly drop root -> install the
 * seccomp filter. Privilege drop and chroot are no-ops when not started as root;
 * the seccomp filter is installed regardless (it needs no privilege).
 *
 * The caller resolves ALL configuration into sandbox_config_t BEFORE calling
 * sandbox_apply(), so no configuration read happens after chroot. That is
 * deliberate: a chroot that hides the config source (e.g. a Valkey socket that
 * needs a hostname lookup the empty chroot can no longer perform) must not be
 * able to silently downgrade the seccomp mode from enforce to its default.
 * ======================================================================= */
#ifndef SANDBOX_H
#define SANDBOX_H

#include <syslog.h> /* LOG_* levels for the log callback */

/* Log sink. The signature matches dnsd's dns_log(), so dnsd passes it directly;
 * resolverd passes a small stderr adapter. Levels are syslog LOG_*. */
typedef void (*sandbox_logf)(int level, const char *fmt, ...);

/* seccomp mode applied when sandbox_config_t.seccomp_mode is left empty. */
typedef enum {
    SANDBOX_SECCOMP_AUDIT,   /* default action SCMP_ACT_LOG — log-only */
    SANDBOX_SECCOMP_ENFORCE, /* default action EPERM on a non-whitelisted call */
} sandbox_seccomp_default_t;

/* Optional syscall groups added to the base whitelist (bitwise OR). Keeping the
 * actual SCMP_SYS() numbers inside sandbox.c means callers never need to include
 * <seccomp.h>. */
#define SANDBOX_SYS_GETADDRINFO 0x1u /* recvmmsg/sendmmsg — glibc stub resolver */
#define SANDBOX_SYS_FILEWRITE                                                                      \
    0x2u /* durable file-store I/O (fsync/rename/…) —                                          \
          * resolverd's embedded objectdb cache */

typedef struct {
    /* All resolved by the caller before sandbox_apply(). Empty string = unset. */
    char chroot_dir[512];    /* filesystem confinement target; empty = none */
    char isolation_mode[16]; /* "chroot" (default) | "mountns" */
    char privdrop_user[64];  /* unprivileged account; empty => "nobody" */
    char privdrop_group[64]; /* optional; empty => the user's primary group */
    char seccomp_mode[16];   /* "enforce" | "audit" | "off"; empty => default */

    sandbox_seccomp_default_t seccomp_default; /* used when seccomp_mode empty */
    unsigned extra_syscall_groups;             /* SANDBOX_SYS_* bitmask */

    sandbox_logf log; /* required — must be non-NULL */
    const char *tag;  /* daemon name for log lines, e.g. "dnsd" / "resolverd" */
} sandbox_config_t;

/* Apply the full sandbox (see the ordering note above). Fail-closed: exits on
 * any failure while root, or on a seccomp setup error in enforce mode. */
void sandbox_apply(const sandbox_config_t *cfg);

/* If environment variable `name` is set and non-empty, copy it into buf,
 * overriding whatever the caller already read from its config store. Shared so
 * both daemons gather config the same way. */
void sandbox_env_override(char *buf, int len, const char *name);

#endif /* SANDBOX_H */
