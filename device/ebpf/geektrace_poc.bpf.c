// Minimal geektrace device probes for the bench app.
// No libbpf/BTF dependency: the loader creates the maps and patches the
// R_BPF_64_64 relocations itself.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef signed long long __s64;

#define SEC(name) __attribute__((section(name), used))
#define always_inline __attribute__((always_inline)) inline

#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1

#define RINGBUF_SIZE (64 * 1024 * 1024)
#define LEGACY_CPU_SLOTS 256
#define STACK_DEPTH 8
#define BPF_F_USER_STACK (1ULL << 8)
#define BPF_F_CURRENT_CPU 0xffffffffULL

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

// GT_LEGACY targets kernels without BPF ringbuf (< 5.8). The broker creates
// the matching map itself; the section type here only documents intent.
#ifdef GT_LEGACY
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 4,
    .value_size = 4,
    .max_entries = LEGACY_CPU_SLOTS,
    .map_flags = 0,
};
#else
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = RINGBUF_SIZE,
    .map_flags = 0,
};
#endif

struct gt_config {
    __u32 target_uid;
    __u32 flags;
    // Maximum number of payload bytes copied out of the target. 0 means
    // metadata-only mode: no user memory is read at all.
    __u32 payload_limit;
};

#define GT_CONFIG_ZYGOTE_FORKS 1
#define GT_CONFIG_STACK 2
#define GT_CONFIG_RAW_OPENAT 4
#define GT_CONFIG_RAW_CONNECT 8
// < 5.8 kernels have no bpf_probe_read_user*, so the openat path cannot be
// copied in the kernel. The broker then resolves it from /proc/<pid>/fd/<fd>
// after sys_exit, which needs the entry arguments kept until then.
#define GT_CONFIG_PATH_FALLBACK 16
#define GT_OPENAT_PENDING_TTL_NS (5ULL * 1000000000ULL)
// pid_tgid is 32-bit, so bit 63 keeps openat state in its own key space. An
// openat issued inside a long-running SSL_read must not overwrite that
// thread's entry state (and vice versa).
#define GT_OPENAT_KEY_BIT (1ULL << 63)

// reserved field of struct gt_event: the broker added the path from procfs.
#define GT_EVENT_SOURCE_PROC_FD 1

struct bpf_map_def SEC("maps") config = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = 4,
    .value_size = sizeof(struct gt_config),
    .max_entries = 1,
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = 4,
    .value_size = sizeof(__u64),
    .max_entries = 4,
    .map_flags = 0,
};

struct gt_pending {
    __u64 object;
    __u64 buffer;
    __u64 length_ptr;
    __u64 entry_ts_ns;
    __u32 kind;
    __u32 pad;
};

struct bpf_map_def SEC("maps") pending = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(struct gt_pending),
    .max_entries = 10240,
    .map_flags = 0,
};

enum {
    EV_FORK = 1,
    EV_OPENAT = 2,
    EV_SSL_WRITE = 3,
    EV_SSL_READ = 4,
    EV_EVP_ENCRYPT = 5,
    EV_EVP_DIGEST = 6,
    EV_EVP_DECRYPT = 7,
    EV_EVP_DIGEST_ONESHOT = 8,
    EV_EVP_SIGN_UPDATE = 9,
    EV_EVP_VERIFY_UPDATE = 10,
    EV_EVP_ENCRYPT_RET = 11,
    EV_EVP_DECRYPT_RET = 12,
    EV_CONNECT = 13,
};

#define DATA_LEN 256
#define COMM_LEN 16

struct gt_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 kind;
    __u64 arg0;
    __u64 arg1;
    __u64 arg2;
    __u32 dlen;
    __u32 ret;
    __u32 stack_depth;
    __u32 reserved;
    char comm[COMM_LEN];
    __u64 stack[STACK_DEPTH];
    __u8 data[DATA_LEN];
};

struct fork_ctx {
    __u8 common[8];
    char parent_comm[COMM_LEN];
    __s32 parent_pid;
    char child_comm[COMM_LEN];
    __s32 child_pid;
};

struct openat_ctx {
    __u8 common[8];
    __s32 syscall_nr;
    __u32 pad0;
    __s32 dfd;
    __u32 pad1;
    const char *filename;
    __s32 flags;
    __u32 pad2;
};

struct connect_ctx {
    __u8 common[8];
    __s32 syscall_nr;
    __u32 pad0;
    __s32 fd;
    __u32 pad1;
    const void *address;
    __s32 address_len;
    __u32 pad2;
};

// Kernels built without CONFIG_FTRACE_SYSCALLS expose only raw_syscalls;
// the broker enables the raw fallback per syscall when needed.
struct raw_syscalls_ctx {
    __u8 common[8];
    __s64 id;
    __u64 args[6];
};

// tracepoint/raw_syscalls/sys_exit: common(8) + id(8) + ret(8).
struct raw_syscalls_exit_ctx {
    __u8 common[8];
    __s64 id;
    __s64 ret;
};

#if defined(__TARGET_ARCH_arm64)
#define GT_NR_OPENAT 56
#define GT_NR_CONNECT 203
#elif defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_x86_64)
#define GT_NR_OPENAT 257
#define GT_NR_CONNECT 42
#endif

#if defined(__TARGET_ARCH_arm64)
struct gt_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#define PARM1(ctx) ((ctx)->regs[0])
#define PARM2(ctx) ((ctx)->regs[1])
#define PARM3(ctx) ((ctx)->regs[2])
#define PARM4(ctx) ((ctx)->regs[3])
#define PARM5(ctx) ((ctx)->regs[4])
#define RET(ctx) ((ctx)->regs[0])
#elif defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_x86_64)
struct gt_pt_regs {
    __u64 r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi;
    __u64 orig_ax, rip, cs, eflags, rsp, ss;
};
#define PARM1(ctx) ((ctx)->rdi)
#define PARM2(ctx) ((ctx)->rsi)
#define PARM3(ctx) ((ctx)->rdx)
#define PARM4(ctx) ((ctx)->rcx)
#define PARM5(ctx) ((ctx)->r8)
#define RET(ctx) ((ctx)->rax)
#else
#error "compile with -D__TARGET_ARCH_arm64 or -D__TARGET_ARCH_x86"
#endif

static void *(*gt_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*gt_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;
static long (*gt_map_delete_elem)(void *, const void *) = (void *)3;
static __u64 (*gt_ktime_get_ns)(void) = (void *)5;
static __u64 (*gt_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*gt_get_current_uid_gid)(void) = (void *)15;
static long (*gt_get_current_comm)(void *, __u32) = (void *)16;
#ifdef GT_LEGACY
// Linux 4.19 has no bpf_probe_read_user (helper 112, added in 5.5). On the
// arm64 kernels measured so far (PAN enabled) helpers 4 and 45 return -EFAULT
// for user addresses, so legacy runs only get syscall metadata and lengths.
// bpf_get_stack still reads user stacks through the perf callchain path.
#ifndef GT_HELPER_READ
#define GT_HELPER_READ 4
#endif
#ifndef GT_HELPER_READ_STR
#define GT_HELPER_READ_STR 45
#endif
static long (*gt_probe_read_user)(void *, __u32, const void *) =
    (void *)GT_HELPER_READ;
static long (*gt_probe_read_user_str)(void *, __u32, const void *) =
    (void *)GT_HELPER_READ_STR;
static long (*gt_perf_event_output)(void *, void *, __u64, void *, __u64) =
    (void *)25;
#else
static long (*gt_probe_read_user)(void *, __u32, const void *) = (void *)112;
static long (*gt_probe_read_user_str)(void *, __u32, const void *) = (void *)114;
static long (*gt_ringbuf_output)(void *, void *, __u64, __u64) = (void *)130;
#endif
#ifndef GT_NO_STACK
static long (*gt_get_stack)(void *, void *, __u32, __u64) = (void *)67;
#endif

// Filter by UID, not comm: worker threads carry their own comm but the same UID.
static always_inline int is_target(void)
{
    __u32 key = 0;
    struct gt_config *cfg = (struct gt_config *)gt_map_lookup_elem(&config, &key);
    if (!cfg)
        return 0;
    return (__u32)gt_get_current_uid_gid() == cfg->target_uid;
}

static always_inline void event_init(struct gt_event *e, __u32 kind)
{
    __u64 id = gt_get_current_pid_tgid();
    e->ts_ns = gt_ktime_get_ns();
    e->pid = (__u32)(id >> 32);
    e->tid = (__u32)id;
    e->uid = (__u32)gt_get_current_uid_gid();
    e->kind = kind;
    gt_get_current_comm(e->comm, sizeof(e->comm));
}

static always_inline void stat_inc(__u32 key)
{
    __u64 *value = (__u64 *)gt_map_lookup_elem(&stats, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static always_inline void focus_init(struct gt_event *e, __u32 kind,
                                     struct gt_pt_regs *ctx)
{
    event_init(e, kind);
#ifdef GT_NO_STACK
    (void)ctx;
#else
    __u32 key = 0;
    struct gt_config *cfg = (struct gt_config *)gt_map_lookup_elem(&config, &key);
    if (!cfg || !(cfg->flags & GT_CONFIG_STACK))
        return;
    long n = gt_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
    if (n > 0)
        e->stack_depth = (__u32)n / sizeof(__u64);
    else
        stat_inc(1);
#endif
}

static always_inline __u64 config_payload_limit(void)
{
    __u32 key = 0;
    struct gt_config *cfg = (struct gt_config *)gt_map_lookup_elem(&config, &key);
    if (!cfg)
        return 0;
    return (__u64)cfg->payload_limit;
}

static always_inline void read_payload(struct gt_event *e, __u64 len,
                                      const void *source)
{
    if (!len)
        return;
    // Metadata-only mode never touches target memory: a smaller read budget
    // means less perturbation and no user-memory fault risk.
    __u64 limit = config_payload_limit();
    if (!limit)
        return;
    if (len > limit)
        len = limit;
    if (len > DATA_LEN - 1)
        len = DATA_LEN - 1;
    // 4.19's verifier derives the non-negative signed lower bound only from
    // an unsigned compare. The mask keeps clang from folding this back into
    // a signed compare when it can prove len is already small.
    __u64 read_len = len & (DATA_LEN - 1);
    if (gt_probe_read_user(e->data, read_len, source) == 0)
        e->dlen = (__u32)read_len;
    else
        stat_inc(2);
}

static always_inline int pending_save_key(__u64 key,
                                          struct gt_pending *pending_state)
{
    if (gt_map_update_elem(&pending, &key, pending_state, 0) < 0) {
        stat_inc(3);
        return 0;
    }
    return 1;
}

static always_inline int pending_load_key(__u64 key, struct gt_pending *out,
                                          __u32 kind)
{
    struct gt_pending *saved = (struct gt_pending *)gt_map_lookup_elem(&pending, &key);
    if (!saved || saved->kind != kind)
        return 0;
    *out = *saved;
    gt_map_delete_elem(&pending, &key);
    return 1;
}

static always_inline int pending_save(struct gt_pending *pending_state)
{
    return pending_save_key(gt_get_current_pid_tgid(), pending_state);
}

static always_inline int pending_load(struct gt_pending *out, __u32 kind)
{
    return pending_load_key(gt_get_current_pid_tgid(), out, kind);
}

static always_inline int event_emit(struct gt_event *e, void *ctx)
{
#ifdef GT_LEGACY
    int rc = (int)gt_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
                                       sizeof(*e));
#else
    (void)ctx;
    int rc = (int)gt_ringbuf_output(&events, e, sizeof(*e), 0);
#endif
    if (rc < 0)
        stat_inc(0);
    return rc;
}

// App processes are forked from zygote, where the UID filter does not apply yet.
static always_inline int is_zygote_parent(const char comm[COMM_LEN])
{
    if (comm[0] != 'z' || comm[1] != 'y' || comm[2] != 'g' || comm[3] != 'o' ||
        comm[4] != 't' || comm[5] != 'e')
        return 0;
    return comm[6] == '\0' ||
           (comm[6] == '6' && comm[7] == '4' && comm[8] == '\0');
}

SEC("tracepoint/sched/sched_process_fork")
int gt_sched_process_fork(struct fork_ctx *ctx)
{
    __u32 key = 0;
    struct gt_config *cfg = (struct gt_config *)gt_map_lookup_elem(&config, &key);
    if (!cfg)
        return 0;
    if ((__u32)gt_get_current_uid_gid() != cfg->target_uid &&
        (!(cfg->flags & GT_CONFIG_ZYGOTE_FORKS) ||
         !is_zygote_parent(ctx->parent_comm)))
        return 0;

    struct gt_event e = {};
    event_init(&e, EV_FORK);
    e.arg0 = (__u32)ctx->parent_pid;
    e.arg1 = (__u32)ctx->child_pid;
#pragma unroll
    for (int i = 0; i < COMM_LEN; i++) {
        e.data[i] = (__u8)ctx->parent_comm[i];
        e.data[COMM_LEN + i] = (__u8)ctx->child_comm[i];
    }
    e.dlen = COMM_LEN * 2;
    return event_emit(&e, ctx);
}

#ifdef GT_LEGACY
static always_inline int path_fallback_enabled(void)
{
    __u32 key = 0;
    struct gt_config *cfg = (struct gt_config *)gt_map_lookup_elem(&config, &key);
    return cfg && (cfg->flags & GT_CONFIG_PATH_FALLBACK);
}

// Keep the enter arguments until sys_exit reports the fd. object carries dfd,
// buffer carries flags; length_ptr stays unused for this kind.
static always_inline __u64 openat_key(void)
{
    return gt_get_current_pid_tgid() | GT_OPENAT_KEY_BIT;
}

static always_inline int openat_pending_save(__s32 dfd, __u32 flags)
{
    struct gt_pending state = {};
    state.object = (__u32)dfd;
    state.buffer = flags;
    state.entry_ts_ns = gt_ktime_get_ns();
    state.kind = EV_OPENAT;
    return pending_save_key(openat_key(), &state);
}
#endif

static always_inline void fill_openat(struct gt_event *e, __s32 dfd,
                                      __u32 flags, const void *filename)
{
    event_init(e, EV_OPENAT);
    e->arg0 = (__u32)dfd;
    e->arg1 = flags;
    long n = gt_probe_read_user_str(e->data, sizeof(e->data), filename);
    if (n > 0)
        e->dlen = (__u32)n - 1;
    else
        stat_inc(2);
}

static always_inline void fill_connect(struct gt_event *e, __s32 fd,
                                       const void *address, __s64 addrlen)
{
    event_init(e, EV_CONNECT);
    e->arg0 = (__u32)fd;
    if (addrlen <= 0)
        return;
    e->arg1 = (__u32)addrlen;
    __u64 n = (__u64)addrlen;
    if (n > 128)
        n = 128;
    read_payload(e, n, address);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int gt_sys_enter_openat(struct openat_ctx *ctx)
{
    if (!is_target())
        return 0;

#ifdef GT_LEGACY
    if (path_fallback_enabled() &&
        openat_pending_save(ctx->dfd, (__u32)ctx->flags))
        return 0;
#endif
    struct gt_event e = {};
    fill_openat(&e, ctx->dfd, (__u32)ctx->flags, ctx->filename);
    return event_emit(&e, ctx);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int gt_sys_enter_connect(struct connect_ctx *ctx)
{
    if (!is_target())
        return 0;

    struct gt_event e = {};
    fill_connect(&e, ctx->fd, ctx->address, (__s64)ctx->address_len);
    return event_emit(&e, ctx);
}

// Fallback for kernels without CONFIG_FTRACE_SYSCALLS (e.g. some Android 4.19
// OEM kernels): both syscalls share one raw_syscalls tracepoint program.
SEC("tracepoint/raw_syscalls/sys_enter")
int gt_raw_sys_enter(struct raw_syscalls_ctx *ctx)
{
    __s64 nr = ctx->id;
    if (nr != GT_NR_OPENAT && nr != GT_NR_CONNECT)
        return 0;

    __u32 key = 0;
    struct gt_config *cfg = (struct gt_config *)gt_map_lookup_elem(&config, &key);
    if (!cfg)
        return 0;
    if (nr == GT_NR_OPENAT && !(cfg->flags & GT_CONFIG_RAW_OPENAT))
        return 0;
    if (nr == GT_NR_CONNECT && !(cfg->flags & GT_CONFIG_RAW_CONNECT))
        return 0;
    if ((__u32)gt_get_current_uid_gid() != cfg->target_uid)
        return 0;

#ifdef GT_LEGACY
    if (nr == GT_NR_OPENAT && path_fallback_enabled() &&
        openat_pending_save((__s32)ctx->args[0], (__u32)ctx->args[2]))
        return 0;
#endif
    struct gt_event e = {};
    if (nr == GT_NR_OPENAT)
        fill_openat(&e, (__s32)ctx->args[0], (__u32)ctx->args[2],
                    (const void *)ctx->args[1]);
    else
        fill_connect(&e, (__s32)ctx->args[0], (const void *)ctx->args[1],
                     (__s64)ctx->args[2]);
    return event_emit(&e, ctx);
}

#ifdef GT_LEGACY
// Paired with the openat entry above: once sys_exit reports the fd, the event
// is emitted with the entry arguments and the result. The broker appends the
// path by reading /proc/<pid>/fd/<fd>. This is the < 5.8 replacement for
// bpf_probe_read_user_str, which is unavailable there.
SEC("tracepoint/raw_syscalls/sys_exit")
int gt_raw_sys_exit(struct raw_syscalls_exit_ctx *ctx)
{
    if (ctx->id != GT_NR_OPENAT)
        return 0;

    __u32 key = 0;
    struct gt_config *cfg = (struct gt_config *)gt_map_lookup_elem(&config, &key);
    if (!cfg || !(cfg->flags & GT_CONFIG_PATH_FALLBACK))
        return 0;
    if ((__u32)gt_get_current_uid_gid() != cfg->target_uid)
        return 0;

    struct gt_pending state = {};
    if (!pending_load_key(openat_key(), &state, EV_OPENAT))
        return 0;
    // A signal can widen the enter/exit gap; a stale fd must not be paired
    // with an unrelated openat.
    if (gt_ktime_get_ns() - state.entry_ts_ns > GT_OPENAT_PENDING_TTL_NS)
        return 0;

    struct gt_event e = {};
    event_init(&e, EV_OPENAT);
    e.arg0 = (__u32)state.object;
    e.arg1 = (__u32)state.buffer;
    e.arg2 = state.entry_ts_ns;
    e.ret = (__u32)ctx->ret;
    e.reserved = GT_EVENT_SOURCE_PROC_FD;
    return event_emit(&e, ctx);
}
#endif

// SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/ssl_write")
int gt_ssl_write(struct gt_pt_regs *ctx)
{
    if (!is_target())
        return 0;

    __u64 ssl = PARM1(ctx);
    const void *buf = (const void *)PARM2(ctx);
    __s32 num = (__s32)PARM3(ctx);
    struct gt_event e = {};
    focus_init(&e, EV_SSL_WRITE, ctx);
    e.arg1 = ssl;
    if (num > 0) {
        e.arg0 = (__u32)num;
        read_payload(&e, (__u64)num, buf);
    }
    return event_emit(&e, ctx);
}

// SSL_read(SSL *ssl, void *buf, int num); plaintext is captured on return.
SEC("uprobe/ssl_read")
int gt_ssl_read(struct gt_pt_regs *ctx)
{
    if (!is_target())
        return 0;

    struct gt_pending state = {};
    state.object = PARM1(ctx);
    state.buffer = PARM2(ctx);
    state.entry_ts_ns = gt_ktime_get_ns();
    state.kind = EV_SSL_READ;
    pending_save(&state);
    return 0;
}

SEC("uretprobe/ssl_read")
int gt_ssl_read_ret(struct gt_pt_regs *ctx)
{
    if (!is_target())
        return 0;

    struct gt_pending state = {};
    if (!pending_load(&state, EV_SSL_READ))
        return 0;
    __s32 ret = (__s32)RET(ctx);
    struct gt_event e = {};
    focus_init(&e, EV_SSL_READ, ctx);
    e.arg0 = (__u32)ret;
    e.arg1 = state.object;
    e.arg2 = state.entry_ts_ns;
    e.ret = (__u32)ret;
    if (ret > 0)
        read_payload(&e, (__u64)ret, (const void *)state.buffer);
    return event_emit(&e, ctx);
}

// EVP_EncryptUpdate/EVP_DecryptUpdate(ctx, out, outl, in, inl)
static always_inline int emit_evp_cipher_update(struct gt_pt_regs *ctx,
                                                __u32 kind)
{
    if (!is_target())
        return 0;

    const void *in = (const void *)PARM4(ctx);
    __s32 inl = (__s32)PARM5(ctx);
    struct gt_pending state = {};
    state.object = PARM1(ctx);
    state.buffer = PARM2(ctx);
    state.length_ptr = PARM3(ctx);
    state.entry_ts_ns = gt_ktime_get_ns();
    state.kind = kind;
    pending_save(&state);

    struct gt_event e = {};
    focus_init(&e, kind, ctx);
    // The call id is built from the entry timestamp, so the entry event has
    // to carry exactly the timestamp the return event will report. Otherwise
    // entry and return can never be paired.
    e.ts_ns = state.entry_ts_ns;
    e.arg1 = PARM1(ctx);
    if (inl > 0) {
        e.arg0 = (__u32)inl;
        read_payload(&e, (__u64)inl, in);
    }
    return event_emit(&e, ctx);
}

static always_inline int emit_evp_cipher_return(struct gt_pt_regs *ctx,
                                                __u32 entry_kind,
                                                __u32 return_kind)
{
    if (!is_target())
        return 0;

    struct gt_pending state = {};
    if (!pending_load(&state, entry_kind))
        return 0;
    __s32 ret = (__s32)RET(ctx);
    __s32 out_len = 0;
    if (ret > 0 && gt_probe_read_user(&out_len, sizeof(out_len),
                                      (const void *)state.length_ptr) < 0)
        stat_inc(2);
    struct gt_event e = {};
    focus_init(&e, return_kind, ctx);
    e.arg0 = out_len > 0 ? (__u32)out_len : 0;
    e.arg1 = state.object;
    e.arg2 = state.entry_ts_ns;
    e.ret = (__u32)ret;
    if (out_len > 0)
        read_payload(&e, (__u64)out_len, (const void *)state.buffer);
    return event_emit(&e, ctx);
}

SEC("uretprobe/evp_encrypt")
int gt_evp_encrypt_ret(struct gt_pt_regs *ctx)
{
    return emit_evp_cipher_return(ctx, EV_EVP_ENCRYPT, EV_EVP_ENCRYPT_RET);
}

SEC("uretprobe/evp_decrypt")
int gt_evp_decrypt_ret(struct gt_pt_regs *ctx)
{
    return emit_evp_cipher_return(ctx, EV_EVP_DECRYPT, EV_EVP_DECRYPT_RET);
}

SEC("uprobe/evp_encrypt")
int gt_evp_encrypt(struct gt_pt_regs *ctx)
{
    return emit_evp_cipher_update(ctx, EV_EVP_ENCRYPT);
}

SEC("uprobe/evp_decrypt")
int gt_evp_decrypt(struct gt_pt_regs *ctx)
{
    return emit_evp_cipher_update(ctx, EV_EVP_DECRYPT);
}

// EVP_DigestUpdate / EVP_DigestSignUpdate / EVP_DigestVerifyUpdate(ctx, data, count)
static always_inline int emit_md_update(struct gt_pt_regs *ctx, __u32 kind)
{
    if (!is_target())
        return 0;

    const void *data = (const void *)PARM2(ctx);
    __u64 len = PARM3(ctx);
    struct gt_event e = {};
    focus_init(&e, kind, ctx);
    e.arg0 = len;
    e.arg1 = PARM1(ctx);
    read_payload(&e, len, data);
    return event_emit(&e, ctx);
}

SEC("uprobe/evp_digest")
int gt_evp_digest(struct gt_pt_regs *ctx)
{
    return emit_md_update(ctx, EV_EVP_DIGEST);
}

SEC("uprobe/evp_sign_update")
int gt_evp_sign_update(struct gt_pt_regs *ctx)
{
    return emit_md_update(ctx, EV_EVP_SIGN_UPDATE);
}

SEC("uprobe/evp_verify_update")
int gt_evp_verify_update(struct gt_pt_regs *ctx)
{
    return emit_md_update(ctx, EV_EVP_VERIFY_UPDATE);
}

// EVP_Digest(const void *data, size_t count, unsigned char *md, ...)
SEC("uprobe/evp_digest_oneshot")
int gt_evp_digest_oneshot(struct gt_pt_regs *ctx)
{
    if (!is_target())
        return 0;

    const void *data = (const void *)PARM1(ctx);
    __u64 len = PARM2(ctx);
    struct gt_event e = {};
    focus_init(&e, EV_EVP_DIGEST_ONESHOT, ctx);
    e.arg0 = len;
    e.arg1 = (__u64)data;
    read_payload(&e, len, data);
    return event_emit(&e, ctx);
}

char LICENSE[] SEC("license") = "GPL";
