/* ==========================================================================
 * sandbox.c — shared privilege-drop / filesystem-isolation / seccomp sandbox.
 * See sandbox.h for the contract and ordering rationale.
 * ======================================================================= */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "sandbox.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>
#ifdef __linux__
#include <sched.h>       /* unshare, CLONE_NEWNS */
#include <sys/mount.h>   /* mount, umount2, MS_* */
#include <sys/syscall.h> /* SYS_pivot_root */
#endif
#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif
#include "dns_wire.h" /* safe_strcpy */

void sandbox_env_override(char *buf, int len, const char *name) {
    const char *v = getenv(name);
    if (v && v[0])
        safe_strcpy(buf, v, len);
}

/* ==========================================================================
 * Filesystem isolation
 *
 * Confine the daemon's filesystem view once the privileged sockets are bound,
 * while still root (chroot/pivot_root need CAP_SYS_CHROOT / CAP_SYS_ADMIN). The
 * default `chroot` mode is a plain chroot(2)+chdir("/"); `mountns` unshares a
 * private mount namespace and pivot_root(2)s into the dir, unmounting the old
 * root (stronger — the old root is gone, not merely hidden behind a directory
 * swap an attacker might break out of).
 *
 * Threading note for mountns: unshare(CLONE_NEWNS) moves only the *calling*
 * thread. Callers run sandbox_apply on the main thread before spawning any
 * per-connection worker, so every thread that handles untrusted request input
 * inherits the pivoted root. A trusted background thread started *before*
 * sandbox_apply stays in the parent mount namespace — keep such threads off
 * attacker-controlled paths, or use the default `chroot` mode (which shares the
 * fs_struct and so confines every thread).
 * ======================================================================= */
#ifdef __linux__
/* Pivot into `dir` using a private mount namespace. Fail-closed (exit) on any
 * step, since a half-applied isolation is worse than a clear refusal. */
static void enter_mount_namespace(const sandbox_config_t *cfg, const char *dir) {
    if (unshare(CLONE_NEWNS) != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: unshare(CLONE_NEWNS) failed: %s\n", cfg->tag,
                 strerror(errno));
        exit(1);
    }
    /* Make every mount private so our pivot does not propagate to the host. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: make-rprivate(/) failed: %s\n", cfg->tag,
                 strerror(errno));
        exit(1);
    }
    /* pivot_root requires new_root to be a mount point: bind dir onto itself. */
    if (mount(dir, dir, NULL, MS_BIND | MS_REC, NULL) != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: bind-mount('%s') failed: %s\n", cfg->tag, dir,
                 strerror(errno));
        exit(1);
    }
    if (chdir(dir) != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: chdir('%s') failed: %s\n", cfg->tag, dir,
                 strerror(errno));
        exit(1);
    }
    /* pivot_root(".", ".") stacks the old root on top of the new one (the
     * util-linux / runc idiom), so no separate put_old directory is needed. */
    if (syscall(SYS_pivot_root, ".", ".") != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: pivot_root('%s') failed: %s\n", cfg->tag, dir,
                 strerror(errno));
        exit(1);
    }
    /* Detach the old root (now stacked at "/") so it is fully gone, then
     * re-anchor the working directory at the new root. */
    if (umount2(".", MNT_DETACH) != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: umount2(old-root) failed: %s\n", cfg->tag,
                 strerror(errno));
        exit(1);
    }
    if (chdir("/") != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: chdir('/') after pivot_root failed: %s\n", cfg->tag,
                 strerror(errno));
        exit(1);
    }
    cfg->log(LOG_NOTICE, "[%s/sandbox] pivoted into '%s' via private mount namespace (now /)\n",
             cfg->tag, dir);
}
#endif /* __linux__ */

static void enter_chroot(const sandbox_config_t *cfg) {
    if (!cfg->chroot_dir[0])
        return; /* not configured — no filesystem isolation */
    if (geteuid() != 0) {
        cfg->log(LOG_WARNING, "[%s/sandbox] chroot_dir set but not running as root — skipping\n",
                 cfg->tag);
        return;
    }
#ifdef __linux__
    if (strcmp(cfg->isolation_mode, "mountns") == 0) {
        enter_mount_namespace(cfg, cfg->chroot_dir);
        return;
    }
#else
    if (strcmp(cfg->isolation_mode, "mountns") == 0)
        cfg->log(LOG_WARNING,
                 "[%s/sandbox] isolation_mode=mountns unsupported on this OS — using chroot\n",
                 cfg->tag);
#endif
    if (chroot(cfg->chroot_dir) != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: chroot('%s') failed: %s\n", cfg->tag,
                 cfg->chroot_dir, strerror(errno));
        exit(1);
    }
    if (chdir("/") != 0) {
        cfg->log(LOG_ERR, "[%s/sandbox] FATAL: chdir('/') after chroot failed: %s\n", cfg->tag,
                 strerror(errno));
        exit(1);
    }
    cfg->log(LOG_NOTICE, "[%s/sandbox] confined to '%s' (now /)\n", cfg->tag, cfg->chroot_dir);
}

/* ==========================================================================
 * Privilege drop (least privilege)
 *
 * Split so the order with enter_chroot() is correct: resolve the account
 * (getpwnam) BEFORE chroot, while the host passwd/group databases are reachable
 * (an empty chroot has no /etc/passwd); apply the numeric ids AFTER chroot.
 * ======================================================================= */
typedef struct {
    int do_drop; /* 1 = root, resolved, apply after chroot; 0 = not root, skip */
    uid_t uid;
    gid_t gid;
    char user[64];
} privdrop_plan_t;

static void priv_resolve(privdrop_plan_t *p, const sandbox_config_t *cfg) {
    memset(p, 0, sizeof(*p));
    if (geteuid() != 0) {
        cfg->log(LOG_INFO, "[%s/priv] not running as root — privilege drop skipped\n", cfg->tag);
        return;
    }
    safe_strcpy(p->user, cfg->privdrop_user[0] ? cfg->privdrop_user : "nobody", sizeof(p->user));

    errno = 0;
    struct passwd *pw = getpwnam(p->user);
    if (!pw) {
        cfg->log(LOG_ERR,
                 "[%s/priv] FATAL: privdrop user '%s' not found%s — set the privdrop user to a "
                 "valid account\n",
                 cfg->tag, p->user, errno ? " (getpwnam failed)" : "");
        exit(1);
    }
    p->uid = pw->pw_uid;
    p->gid = pw->pw_gid;
    if (cfg->privdrop_group[0]) {
        errno = 0;
        struct group *gr = getgrnam(cfg->privdrop_group);
        if (!gr) {
            cfg->log(LOG_ERR, "[%s/priv] FATAL: privdrop group '%s' not found%s\n", cfg->tag,
                     cfg->privdrop_group, errno ? " (getgrnam failed)" : "");
            exit(1);
        }
        p->gid = gr->gr_gid;
    }
    if (p->uid == 0) {
        cfg->log(LOG_ERR, "[%s/priv] FATAL: privdrop user '%s' is root (uid 0) — refusing\n",
                 cfg->tag, p->user);
        exit(1);
    }
    p->do_drop = 1;
}

static void drop_privileges(const privdrop_plan_t *p, const sandbox_config_t *cfg) {
    if (!p->do_drop)
        return; /* not root — priv_resolve already logged the skip */

    /* Order matters: shed supplementary groups, then gid, then uid. Doing uid
     * first would forfeit the privilege needed for the group calls. */
    if (setgroups(0, NULL) != 0) {
        cfg->log(LOG_ERR, "[%s/priv] FATAL: setgroups failed: %s\n", cfg->tag, strerror(errno));
        exit(1);
    }
    if (setgid(p->gid) != 0) {
        cfg->log(LOG_ERR, "[%s/priv] FATAL: setgid(%u) failed: %s\n", cfg->tag, (unsigned) p->gid,
                 strerror(errno));
        exit(1);
    }
    if (setuid(p->uid) != 0) {
        cfg->log(LOG_ERR, "[%s/priv] FATAL: setuid(%u) failed: %s\n", cfg->tag, (unsigned) p->uid,
                 strerror(errno));
        exit(1);
    }
    /* Verify the drop is irreversible: regaining root must fail. */
    if (setuid(0) == 0 || setgid(0) == 0) {
        cfg->log(LOG_ERR, "[%s/priv] FATAL: privileges not fully dropped (could regain root)\n",
                 cfg->tag);
        exit(1);
    }
    /* Keep key material out of core dumps and ptrace by another process running
     * as the same unprivileged user. */
    if (prctl(PR_SET_DUMPABLE, 0) != 0)
        cfg->log(LOG_WARNING, "[%s/priv] PR_SET_DUMPABLE failed: %s\n", cfg->tag, strerror(errno));

    cfg->log(LOG_NOTICE, "[%s/priv] dropped privileges to user '%s' (uid=%u gid=%u)\n", cfg->tag,
             p->user, (unsigned) p->uid, (unsigned) p->gid);
}

/* ==========================================================================
 * seccomp syscall filter (sandbox layer 2)
 *
 * Whitelist-based, applied to all threads (libseccomp loads with TSYNC). The
 * base list below was audit-validated for dnsd (SCMP_ACT_LOG, syscall set
 * harvested with strace across UDP/TCP/DoT-TLS/metrics/Valkey/rollover); callers
 * add transport-specific groups via cfg->extra_syscall_groups.
 *
 * enforce returns EPERM (not SIGKILL) on a miss, so a gap surfaces as an error
 * rather than taking the daemon down. Built only with libseccomp at compile
 * time (-DHAVE_SECCOMP); otherwise a no-op stub.
 * ======================================================================= */
#ifdef HAVE_SECCOMP
static void seccomp_install(const sandbox_config_t *cfg) {
    char mode[16] = "";
    safe_strcpy(mode, cfg->seccomp_mode, sizeof(mode));
    if (!mode[0])
        safe_strcpy(mode, cfg->seccomp_default == SANDBOX_SECCOMP_ENFORCE ? "enforce" : "audit",
                    sizeof(mode));
    if (strcmp(mode, "off") == 0) {
        cfg->log(LOG_NOTICE, "[%s/seccomp] disabled (mode=off)\n", cfg->tag);
        return;
    }
    int enforce = (strcmp(mode, "enforce") == 0);
    uint32_t def_act = enforce ? SCMP_ACT_ERRNO(EPERM) : SCMP_ACT_LOG;

    scmp_filter_ctx ctx = seccomp_init(def_act);
    if (!ctx) {
        cfg->log(LOG_ERR, "[%s/seccomp] seccomp_init failed — running unconfined\n", cfg->tag);
        if (enforce)
            exit(1); /* fail closed in enforce mode */
        return;
    }

    /* Base whitelist — grouped by purpose. SCMP_SYS() resolves names to this
     * architecture's syscall numbers; unknown names are skipped. */
    const int base[] = {
        /* socket I/O — UDP/TCP serving + outbound clients (incl. reconnect) */
        SCMP_SYS(read),
        SCMP_SYS(write),
        SCMP_SYS(readv),
        SCMP_SYS(writev),
        SCMP_SYS(pread64),
        SCMP_SYS(pwrite64),
        SCMP_SYS(recvfrom),
        SCMP_SYS(sendto),
        SCMP_SYS(recvmsg),
        SCMP_SYS(sendmsg),
        SCMP_SYS(accept),
        SCMP_SYS(accept4),
        SCMP_SYS(socket),
        SCMP_SYS(connect),
        SCMP_SYS(bind),
        SCMP_SYS(listen),
        SCMP_SYS(shutdown),
        SCMP_SYS(setsockopt),
        SCMP_SYS(getsockopt),
        SCMP_SYS(getsockname),
        SCMP_SYS(getpeername),
        SCMP_SYS(select),
        SCMP_SYS(pselect6),
        SCMP_SYS(poll),
        SCMP_SYS(ppoll),
        SCMP_SYS(fcntl),
        SCMP_SYS(ioctl),
        SCMP_SYS(close),
        /* filesystem — qlog reopen, /dev/urandom, CA certs, resolver files */
        SCMP_SYS(openat),
        SCMP_SYS(open),
        SCMP_SYS(lseek),
        SCMP_SYS(fstat),
        SCMP_SYS(stat),
        SCMP_SYS(lstat),
        SCMP_SYS(newfstatat),
        SCMP_SYS(statx),
        SCMP_SYS(readlink),
        SCMP_SYS(readlinkat),
        SCMP_SYS(getdents64),
        SCMP_SYS(access),
        SCMP_SYS(faccessat),
        SCMP_SYS(faccessat2),
        /* memory */
        SCMP_SYS(mmap),
        SCMP_SYS(munmap),
        SCMP_SYS(mremap),
        SCMP_SYS(mprotect),
        SCMP_SYS(brk),
        SCMP_SYS(madvise),
        /* threads, signals, process lifecycle */
        SCMP_SYS(clone),
        SCMP_SYS(clone3),
        SCMP_SYS(futex),
        SCMP_SYS(futex_waitv),
        SCMP_SYS(set_robust_list),
        SCMP_SYS(get_robust_list),
        SCMP_SYS(rt_sigaction),
        SCMP_SYS(rt_sigprocmask),
        SCMP_SYS(rt_sigreturn),
        SCMP_SYS(sigaltstack),
        SCMP_SYS(set_tid_address),
        SCMP_SYS(gettid),
        SCMP_SYS(getpid),
        SCMP_SYS(tgkill),
        SCMP_SYS(exit),
        SCMP_SYS(exit_group),
        SCMP_SYS(restart_syscall),
        /* time + randomness */
        SCMP_SYS(clock_gettime),
        SCMP_SYS(clock_nanosleep),
        SCMP_SYS(nanosleep),
        SCMP_SYS(gettimeofday),
        SCMP_SYS(time),
        SCMP_SYS(getrandom),
        /* process/runtime info used by glibc/OpenSSL */
        SCMP_SYS(uname),
        SCMP_SYS(arch_prctl),
        SCMP_SYS(rseq),
        SCMP_SYS(getuid),
        SCMP_SYS(geteuid),
        SCMP_SYS(getgid),
        SCMP_SYS(getegid),
        SCMP_SYS(getrlimit),
        SCMP_SYS(prlimit64),
        SCMP_SYS(sysinfo),
        SCMP_SYS(sched_getaffinity),
        SCMP_SYS(sched_yield),
        SCMP_SYS(getcpu),
        SCMP_SYS(membarrier),
        SCMP_SYS(prctl),
    };
    /* glibc getaddrinfo's stub resolver uses these for upstream name lookup. */
    const int getaddrinfo_extra[] = {
        SCMP_SYS(recvmmsg),
        SCMP_SYS(sendmmsg),
    };

    int allowed = 0;
    int skipped = 0;
    for (int i = 0; i < (int) (sizeof(base) / sizeof(base[0])); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, base[i], 0) == 0)
            allowed++;
        else
            skipped++; /* syscall not known on this arch — fine, just skip */
    }
    if (cfg->extra_syscall_groups & SANDBOX_SYS_GETADDRINFO) {
        for (int i = 0; i < (int) (sizeof(getaddrinfo_extra) / sizeof(getaddrinfo_extra[0])); i++) {
            if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, getaddrinfo_extra[i], 0) == 0)
                allowed++;
            else
                skipped++;
        }
    }

    if (seccomp_load(ctx) != 0) {
        cfg->log(LOG_ERR, "[%s/seccomp] seccomp_load failed: %s%s\n", cfg->tag, strerror(errno),
                 enforce ? " — refusing to serve without the filter" : " — running unconfined");
        seccomp_release(ctx);
        if (enforce)
            exit(1); /* fail closed */
        return;
    }
    seccomp_release(ctx);

    cfg->log(LOG_NOTICE,
             "[%s/seccomp] filter active: mode=%s, %d syscalls allowed (%d skipped). %s\n",
             cfg->tag, mode, allowed, skipped,
             enforce ? "Disallowed syscalls return EPERM."
                     : "Audit mode — violations are logged, not blocked "
                       "(check the audit log / dmesg, then switch to enforce).");
}
#else
static void seccomp_install(const sandbox_config_t *cfg) {
    cfg->log(LOG_INFO, "[%s/seccomp] not built in (libseccomp unavailable at build time)\n",
             cfg->tag);
}
#endif

void sandbox_apply(const sandbox_config_t *cfg) {
    privdrop_plan_t plan;
    priv_resolve(&plan, cfg); /* getpwnam — must precede chroot */
    enter_chroot(cfg);
    drop_privileges(&plan, cfg);
    seccomp_install(cfg);
}
