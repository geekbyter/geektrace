// geektrace device PoC broker.
//
// Loads the libbpf-free probe object, attaches tracepoints/uprobes, drains the
// ring buffer and writes geektrace.event.v1 JSONL to stdout or a file.
// Root is required. The broker never ptrace-attaches to the target.

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifdef GEETRACE_EMBEDDED_BPF
#include "geektrace_embedded_bpf.h"
#include "geektrace_embedded_bpf_legacy.h"
#include "geektrace_embedded_bpf_legacy_nostack.h"
#endif

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__x86_64__)
#define __NR_bpf 321
#endif
#endif
#ifndef __NR_perf_event_open
#if defined(__aarch64__)
#define __NR_perf_event_open 241
#elif defined(__x86_64__)
#define __NR_perf_event_open 298
#endif
#endif

#define LOG_PREFIX "geekbyter===> device: "

// Not provided by all bionic elf.h versions.
#ifndef R_BPF_64_64
#define R_BPF_64_64 1
#endif
// 64 MiB of ring buffer. A crypto heavy app can produce tens of thousands of
// events per second; the buffer has to absorb the burst between two drains.
#define RINGBUF_BYTES (64 * 1024 * 1024)
#define MAX_PROGRAMS 24
#define MAX_PERF_FDS 512
#define MAX_CPUS 256
// 128 KiB of data per CPU: 8 pages lost bursts on crypto-heavy threads.
#define PERF_DATA_PAGES 32
// One uprobe per probed symbol per library copy. A target usually maps two
// usable copies of the crypto library (the Conscrypt one used by the Java
// crypto provider and the public system one used by native code).
#define MAX_UPROBES 64
#define MAX_ATTACHED_LIBS 12
#define SECTION_NAME_MAX 96
#define EVENT_DATA_LEN 256
#define EVENT_COMM_LEN 16
#define EVENT_STACK_DEPTH 8
#define EV_MAX 14

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

struct gt_pending {
    uint64_t object;
    uint64_t buffer;
    uint64_t length_ptr;
    uint64_t entry_ts_ns;
    uint32_t kind;
    uint32_t pad;
};

// reserved field of struct gt_event: the path was added by the broker from
// /proc/<pid>/fd/<fd> (legacy kernels without user memory reads).
#define GT_EVENT_SOURCE_PROC_FD 1

struct gt_event {
    uint64_t ts_ns;
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint32_t kind;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint32_t dlen;
    uint32_t ret;
    uint32_t stack_depth;
    uint32_t reserved;
    char comm[EVENT_COMM_LEN];
    uint64_t stack[EVENT_STACK_DEPTH];
    uint8_t data[EVENT_DATA_LEN];
};

_Static_assert(sizeof(struct gt_event) == 400, "unexpected probe event size");

struct gt_program {
    char section[SECTION_NAME_MAX];
    uint8_t *insns;
    size_t insn_cnt;
    size_t section_size;
    int fd;
    int attached;
};

struct bpf_image {
    uint8_t *file_data;
    size_t file_size;
    bool owns_file_data;
    struct gt_program progs[MAX_PROGRAMS];
    int prog_count;
};

struct ringbuf {
    int map_fd;
    size_t page_size;
    size_t max_entries;
    volatile uint64_t *consumer;
    volatile uint64_t *producer;
    uint8_t *data;
    void *consumer_map;
    void *producer_map;
    void *data_map;
};

struct perf_fds {
    int fds[MAX_PERF_FDS];
    int count;
};

struct perf_reader_cpu {
    int fd;
    void *map;
    size_t map_len;
    size_t page_size;
};

struct perf_reader {
    int cpu_count;
    uint64_t lost;
    struct perf_reader_cpu cpu[MAX_CPUS];
};

struct uprobe_state {
    char spec[64];
    char id_path[512];
};

static volatile sig_atomic_t g_stop;
static int g_sigpipe[2] = {-1, -1};

// Payload budget shared with the BPF side; 0 means metadata-only capture.
static uint32_t g_payload_limit = EVENT_DATA_LEN - 1;
// Legacy kernels (< 5.8) cannot copy the openat path in the kernel; the fd is
// reported on sys_exit and the broker resolves it through procfs.
static bool g_path_fallback;
// Tracefs probes are created under a per-session group name. A fixed group is
// a greppable signature, so each run draws "gt_" + 6 lowercase alnum. The
// bounded pattern is what makes stale definitions from a SIGKILLed run still
// recognisable and removable at the next start.
static char g_probe_group[16];

static void probe_group_init(void)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    unsigned int seed = (unsigned int)getpid();
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        unsigned int r = 0;
        if (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r))
            seed ^= r;
        close(fd);
    }
    seed ^= (unsigned int)time(NULL);
    unsigned int x = seed | 1u;
    memcpy(g_probe_group, "gt_", 4);
    for (int i = 0; i < 6; i++) {
        x = x * 1664525u + 1013904223u;
        g_probe_group[3 + i] = alphabet[(x >> 16) % 36];
    }
    g_probe_group[9] = '\0';
}

static bool group_is_ours(const char *group)
{
    if (strncmp(group, "gt_", 3) != 0 || strlen(group) != 9)
        return false;
    for (const char *p = group + 3; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')))
            return false;
    return true;
}
// Target identity: the uid filter is what keeps other apps out, and the pid
// list lets the broker look at the maps of the target only.
static uint32_t g_target_uid;
static int g_target_pids[64];
static int g_target_pid_count;
// Set as soon as the target process produced its first event. In "on-sight"
// mode this is the moment the library probes are installed.
static volatile int g_target_seen;
// Children forked from the zygote. Their uid is set a moment after the fork,
// so the broker can recognise the birth of the target and arm the library
// probes before the app runs its own code.
#define MAX_BIRTH_CANDIDATES 32
struct birth_candidate {
    uint32_t pid;
    uint64_t seen_ns;
};
static struct birth_candidate g_birth_candidates[MAX_BIRTH_CANDIDATES];
static int g_birth_count;

static void log_msg(const char *fmt, ...);

static void remember_target_pid(uint32_t pid)
{
    if (!pid)
        return;
    for (int i = 0; i < g_target_pid_count; i++)
        if ((uint32_t)g_target_pids[i] == pid)
            return;
    if (g_target_pid_count >= (int)(sizeof(g_target_pids) / sizeof(g_target_pids[0])))
        return;
    g_target_pids[g_target_pid_count++] = (int)pid;
}

// Remember a process forked from the zygote. The child only gets its app uid
// a moment later, so the candidate is checked again on the next poll.
static void remember_birth_candidate(const struct gt_event *e)
{
    char parent[17] = {};
    memcpy(parent, e->data, EVENT_COMM_LEN);
    parent[EVENT_COMM_LEN] = '\0';
    if (strncmp(parent, "zygote", 6) != 0)
        return;
    uint32_t child = (uint32_t)e->arg1;
    if (!child)
        return;
    for (int i = 0; i < g_birth_count; i++) {
        if (g_birth_candidates[i].pid == child)
            return;
    }
    if (g_birth_count >= MAX_BIRTH_CANDIDATES)
        return;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    g_birth_candidates[g_birth_count].pid = child;
    g_birth_candidates[g_birth_count].seen_ns =
        (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
    g_birth_count++;
    log_msg("zygote fork candidate: pid %u", child);
}

static bool process_effective_uid(uint32_t pid, uint32_t *uid_out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    FILE *status = fopen(path, "r");
    if (!status)
        return false;
    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "Uid:", 4) != 0)
            continue;
        unsigned int real = 0;
        if (sscanf(line + 4, "%u", &real) == 1) {
            *uid_out = (uint32_t)real;
            found = true;
        }
        break;
    }
    fclose(status);
    return found;
}

// Look for a zygote child that has just become the target. This is the
// earliest moment at which the library probes can be installed without
// touching the device before the target exists.
static uint32_t find_birth_target(void)
{
    if (!g_birth_count)
        return 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t now_ns =
        (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
    for (int i = 0; i < g_birth_count;) {
        struct birth_candidate candidate = g_birth_candidates[i];
        uint32_t uid = 0;
        if (!process_effective_uid(candidate.pid, &uid) ||
            now_ns - candidate.seen_ns > 3000000000ull) {
            g_birth_candidates[i] = g_birth_candidates[--g_birth_count];
            continue;
        }
        if (uid == g_target_uid && uid != 0) {
            g_birth_candidates[i] = g_birth_candidates[--g_birth_count];
            remember_target_pid(candidate.pid);
            return candidate.pid;
        }
        i++;
    }
    return 0;
}

static void log_msg(const char *fmt, ...)
{
    va_list ap;
    fputs(LOG_PREFIX, stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    if (!err || errlen == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_sigpipe[1] >= 0) {
        char c = 'x';
        (void)!write(g_sigpipe[1], &c, 1);
    }
}

static int read_file(const char *path, uint8_t **out, size_t *out_size,
                     char *err, size_t errlen)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_err(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        set_err(err, errlen, "stat %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    size_t size = (size_t)st.st_size;
    uint8_t *buf = malloc(size);
    if (!buf) {
        set_err(err, errlen, "out of memory reading %s", path);
        close(fd);
        return -1;
    }
    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, buf + done, size - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            set_err(err, errlen, "read %s: %s", path, strerror(errno));
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        done += (size_t)n;
    }
    close(fd);
    if (done != size) {
        set_err(err, errlen, "short read %s", path);
        free(buf);
        return -1;
    }
    *out = buf;
    *out_size = size;
    return 0;
}

static int write_text(const char *path, const char *text, char *err,
                      size_t errlen)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_APPEND);
    if (fd < 0) {
        set_err(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }
    size_t len = strlen(text);
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, text + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            set_err(err, errlen, "write %s: %s", path, strerror(errno));
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

static int read_int_file(const char *path, int *value, char *err,
                         size_t errlen)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_err(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }
    char buf[64] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    int saved = errno;
    close(fd);
    if (n <= 0) {
        set_err(err, errlen, "read %s: %s", path, strerror(saved));
        return -1;
    }
    char *end = NULL;
    long v = strtol(buf, &end, 0);
    if (end == buf || v < 0 || v > INT32_MAX) {
        set_err(err, errlen, "invalid integer in %s", path);
        return -1;
    }
    *value = (int)v;
    return 0;
}

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

// ---------------------------------------------------------------------------
// Target ELF symbol -> uprobe file offset

static int elf_symbol_offset(const char *path, const char *symbol,
                             uint64_t *file_offset, char *err, size_t errlen)
{
    uint8_t *data = NULL;
    size_t size = 0;
    if (read_file(path, &data, &size, err, errlen) != 0)
        return -1;

    if (size < sizeof(Elf64_Ehdr)) {
        set_err(err, errlen, "%s: file too small", path);
        free(data);
        return -1;
    }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        eh->e_shentsize != sizeof(Elf64_Shdr) || eh->e_shnum == 0 ||
        eh->e_phentsize != sizeof(Elf64_Phdr) || eh->e_phoff == 0 ||
        eh->e_phnum == 0 || eh->e_phoff > size || eh->e_shoff > size ||
        (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > size - eh->e_shoff) {
        set_err(err, errlen, "%s: unsupported ELF layout", path);
        free(data);
        return -1;
    }

    const Elf64_Shdr *sh = (const Elf64_Shdr *)(data + eh->e_shoff);
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(data + eh->e_phoff);
    if ((uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) > size - eh->e_phoff) {
        set_err(err, errlen, "%s: truncated program headers", path);
        free(data);
        return -1;
    }

    for (int si = 0; si < eh->e_shnum; si++) {
        if (sh[si].sh_type != SHT_DYNSYM && sh[si].sh_type != SHT_SYMTAB)
            continue;
        if (sh[si].sh_entsize != sizeof(Elf64_Sym) ||
            sh[si].sh_link >= eh->e_shnum ||
            sh[si].sh_offset > size ||
            sh[si].sh_size > size - sh[si].sh_offset)
            continue;
        const Elf64_Shdr *strsh = &sh[sh[si].sh_link];
        if (strsh->sh_offset > size ||
            strsh->sh_size > size - strsh->sh_offset)
            continue;
        const char *strtab = (const char *)(data + strsh->sh_offset);
        size_t sym_count = sh[si].sh_size / sizeof(Elf64_Sym);
        const Elf64_Sym *syms = (const Elf64_Sym *)(data + sh[si].sh_offset);
        for (size_t k = 0; k < sym_count; k++) {
            const Elf64_Sym *sym = &syms[k];
            if (sym->st_name >= strsh->sh_size || sym->st_shndx == SHN_UNDEF)
                continue;
            if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC &&
                ELF64_ST_TYPE(sym->st_info) != STT_NOTYPE)
                continue;
            if (strcmp(strtab + sym->st_name, symbol) != 0)
                continue;
            uint64_t vaddr = sym->st_value;
            for (int pi = 0; pi < eh->e_phnum; pi++) {
                if (ph[pi].p_type != PT_LOAD)
                    continue;
                if (vaddr >= ph[pi].p_vaddr &&
                    vaddr < ph[pi].p_vaddr + ph[pi].p_filesz) {
                    *file_offset = ph[pi].p_offset + (vaddr - ph[pi].p_vaddr);
                    free(data);
                    return 0;
                }
            }
        }
    }

    set_err(err, errlen, "%s: symbol %s not found", path, symbol);
    free(data);
    return -1;
}

// ---------------------------------------------------------------------------
// BPF object parsing and map relocation

static int section_is_program(const char *name)
{
    return strncmp(name, "tracepoint/", 11) == 0 ||
           strncmp(name, "uprobe/", 7) == 0 ||
           strncmp(name, "uretprobe/", 10) == 0;
}

static void bpf_image_free(struct bpf_image *img)
{
    for (int i = 0; i < img->prog_count; i++)
        free(img->progs[i].insns);
    if (img->owns_file_data)
        free(img->file_data);
    memset(img, 0, sizeof(*img));
}

static int bpf_image_parse(uint8_t *file_data, size_t file_size,
                           const char *source, struct bpf_image *img, char *err,
                           size_t errlen)
{
    img->file_data = file_data;
    img->file_size = file_size;
    const char *path = source;
    const uint8_t *data = img->file_data;
    size_t size = img->file_size;
    if (size < sizeof(Elf64_Ehdr)) {
        set_err(err, errlen, "%s: file too small", path);
        goto fail;
    }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        eh->e_machine != EM_BPF ||
        eh->e_shentsize != sizeof(Elf64_Shdr) || eh->e_shnum == 0 ||
        eh->e_shstrndx >= eh->e_shnum || eh->e_shoff > size ||
        (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > size - eh->e_shoff) {
        set_err(err, errlen, "%s: not a supported BPF ELF object", path);
        goto fail;
    }

    const Elf64_Shdr *sh = (const Elf64_Shdr *)(data + eh->e_shoff);
    const Elf64_Shdr *shstr = &sh[eh->e_shstrndx];
    if (shstr->sh_offset > size || shstr->sh_size > size - shstr->sh_offset) {
        set_err(err, errlen, "%s: invalid section name table", path);
        goto fail;
    }
    const char *names = (const char *)(data + shstr->sh_offset);

    for (int i = 0; i < eh->e_shnum; i++) {
        if (!(sh[i].sh_flags & SHF_EXECINSTR) || sh[i].sh_size == 0)
            continue;
        if (sh[i].sh_name >= shstr->sh_size)
            continue;
        const char *name = names + sh[i].sh_name;
        if (!section_is_program(name))
            continue;
        if (img->prog_count >= MAX_PROGRAMS) {
            set_err(err, errlen, "%s: too many programs", path);
            goto fail;
        }
        if (sh[i].sh_size % sizeof(struct bpf_insn) != 0 ||
            sh[i].sh_offset > size || sh[i].sh_size > size - sh[i].sh_offset) {
            set_err(err, errlen, "%s: invalid program section %s", path, name);
            goto fail;
        }
        struct gt_program *prog = &img->progs[img->prog_count];
        snprintf(prog->section, sizeof(prog->section), "%s", name);
        prog->insns = malloc(sh[i].sh_size);
        if (!prog->insns) {
            set_err(err, errlen, "out of memory");
            goto fail;
        }
        memcpy(prog->insns, data + sh[i].sh_offset, sh[i].sh_size);
        prog->insn_cnt = sh[i].sh_size / sizeof(struct bpf_insn);
        prog->section_size = sh[i].sh_size;
        prog->fd = -1;
        img->prog_count++;
    }

    if (img->prog_count == 0) {
        set_err(err, errlen, "%s: no tracepoint/uprobe programs", path);
        goto fail;
    }
    return 0;

fail:
    bpf_image_free(img);
    return -1;
}

static int bpf_image_load(const char *path, struct bpf_image *img, char *err,
                          size_t errlen)
{
    memset(img, 0, sizeof(*img));
    uint8_t *data = NULL;
    size_t size = 0;
    if (read_file(path, &data, &size, err, errlen) != 0)
        return -1;
    img->owns_file_data = true;
    return bpf_image_parse(data, size, path, img, err, errlen);
}

#ifdef GEETRACE_EMBEDDED_BPF
static int bpf_image_load_embedded(struct bpf_image *img, char *err,
                                   size_t errlen)
{
    memset(img, 0, sizeof(*img));
    return bpf_image_parse((uint8_t *)gt_embedded_bpf, gt_embedded_bpf_size,
                           "embedded", img, err, errlen);
}

static int bpf_image_load_embedded_legacy(struct bpf_image *img, char *err,
                                          size_t errlen)
{
    memset(img, 0, sizeof(*img));
    return bpf_image_parse((uint8_t *)gt_embedded_bpf_legacy,
                           gt_embedded_bpf_legacy_size, "embedded-legacy", img,
                           err, errlen);
}

static int bpf_image_load_embedded_legacy_nostack(struct bpf_image *img,
                                                  char *err, size_t errlen)
{
    memset(img, 0, sizeof(*img));
    return bpf_image_parse((uint8_t *)gt_embedded_bpf_legacy_nostack,
                           gt_embedded_bpf_legacy_nostack_size,
                           "embedded-legacy-nostack", img, err, errlen);
}
#endif

static int bpf_image_patch_maps(struct bpf_image *img, int events_fd,
                                int config_fd, int stats_fd, int pending_fd,
                                char *err, size_t errlen)
{
    const uint8_t *data = img->file_data;
    size_t size = img->file_size;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(data + eh->e_shoff);

    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_REL ||
            sh[i].sh_entsize != sizeof(Elf64_Rel) || sh[i].sh_size == 0)
            continue;
        if (sh[i].sh_offset > size || sh[i].sh_size > size - sh[i].sh_offset)
            continue;
        int target = sh[i].sh_info;
        if (target < 0 || target >= eh->e_shnum)
            continue;
        if (sh[target].sh_offset > size || sh[target].sh_size == 0)
            continue;
        const Elf64_Shdr *shstr = &sh[eh->e_shstrndx];
        if (shstr->sh_offset > size || shstr->sh_size > size - shstr->sh_offset)
            continue;
        if (sh[target].sh_name >= shstr->sh_size)
            continue;
        const char *name = (const char *)(data + shstr->sh_offset) +
                           sh[target].sh_name;
        struct gt_program *prog = NULL;
        for (int p = 0; p < img->prog_count; p++) {
            if (strcmp(img->progs[p].section, name) == 0) {
                prog = &img->progs[p];
                break;
            }
        }
        if (!prog)
            continue;

        if (sh[i].sh_link >= eh->e_shnum) {
            set_err(err, errlen, "%s: relocation has no symbol table",
                    prog->section);
            return -1;
        }
        const Elf64_Shdr *symsh = &sh[sh[i].sh_link];
        if (symsh->sh_entsize != sizeof(Elf64_Sym) ||
            symsh->sh_offset > size ||
            symsh->sh_size > size - symsh->sh_offset ||
            symsh->sh_link >= eh->e_shnum) {
            set_err(err, errlen, "%s: invalid relocation symbol table",
                    prog->section);
            return -1;
        }
        const Elf64_Shdr *strsh = &sh[symsh->sh_link];
        if (strsh->sh_offset > size || strsh->sh_size > size - strsh->sh_offset) {
            set_err(err, errlen, "%s: invalid relocation string table",
                    prog->section);
            return -1;
        }
        const Elf64_Sym *syms = (const Elf64_Sym *)(data + symsh->sh_offset);
        size_t sym_count = symsh->sh_size / sizeof(Elf64_Sym);
        const char *strtab = (const char *)(data + strsh->sh_offset);

        const Elf64_Rel *rels = (const Elf64_Rel *)(data + sh[i].sh_offset);
        size_t rel_count = sh[i].sh_size / sizeof(Elf64_Rel);
        for (size_t r = 0; r < rel_count; r++) {
            uint32_t type = ELF64_R_TYPE(rels[r].r_info);
            if (type != R_BPF_64_64) {
                set_err(err, errlen,
                        "unsupported relocation type %u in %s", type,
                        prog->section);
                return -1;
            }
            uint32_t sym_idx = (uint32_t)(rels[r].r_info >> 32);
            if (sym_idx >= sym_count) {
                set_err(err, errlen, "%s: relocation symbol out of range",
                        prog->section);
                return -1;
            }
            const Elf64_Sym *sym = &syms[sym_idx];
            if (sym->st_name >= strsh->sh_size) {
                set_err(err, errlen, "%s: relocation name out of range",
                        prog->section);
                return -1;
            }
            const char *sym_name = strtab + sym->st_name;
            int map_fd;
            if (strcmp(sym_name, "events") == 0)
                map_fd = events_fd;
            else if (strcmp(sym_name, "config") == 0)
                map_fd = config_fd;
            else if (strcmp(sym_name, "stats") == 0)
                map_fd = stats_fd;
            else if (strcmp(sym_name, "pending") == 0)
                map_fd = pending_fd;
            else {
                set_err(err, errlen, "%s: unknown map symbol '%s'",
                        prog->section, sym_name);
                return -1;
            }

            if (rels[r].r_offset > prog->section_size ||
                prog->section_size - rels[r].r_offset <
                    2 * sizeof(struct bpf_insn)) {
                set_err(err, errlen, "%s: relocation out of range", prog->section);
                return -1;
            }
            struct bpf_insn *insn =
                (struct bpf_insn *)(prog->insns + rels[r].r_offset);
            if (insn->code != (BPF_LD | BPF_IMM | BPF_DW)) {
                set_err(err, errlen, "%s: map relocation is not ld_imm64",
                        prog->section);
                return -1;
            }
            insn->src_reg = BPF_PSEUDO_MAP_FD;
            insn->imm = map_fd;
            insn[1].imm = 0;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Raw bpf()/perf_event_open wrappers

static int bpf_create_map(uint32_t type, uint32_t key_size,
                          uint32_t value_size, uint32_t max_entries,
                          char *err, size_t errlen)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    int fd = (int)syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0)
        set_err(err, errlen, "BPF_MAP_CREATE(type=%u): %s", type,
                strerror(errno));
    return fd;
}

static const char *kernel_release(void)
{
    static char release[128];
    static bool loaded;
    if (!loaded) {
        struct utsname info;
        if (uname(&info) == 0)
            snprintf(release, sizeof(release), "%s", info.release);
        else
            snprintf(release, sizeof(release), "unknown");
        loaded = true;
    }
    return release;
}

static bool kernel_at_least(int want_major, int want_minor)
{
    int major = 0;
    int minor = 0;
    if (sscanf(kernel_release(), "%d.%d", &major, &minor) != 2)
        return true;
    return major > want_major || (major == want_major && minor >= want_minor);
}

// Linux <= 4.19 rejects BPF_PROG_TYPE_KPROBE unless kern_version matches
// LINUX_VERSION_CODE; later kernels dropped the check.
static uint32_t kernel_version_code(void)
{
    static uint32_t code;
    static bool loaded;
    if (!loaded) {
        int major = 0;
        int minor = 0;
        int patch = 0;
        if (sscanf(kernel_release(), "%d.%d.%d", &major, &minor, &patch) >= 2)
            code = ((uint32_t)major << 16) | ((uint32_t)minor << 8) |
                   (uint32_t)patch;
        loaded = true;
    }
    return code;
}

static int bpf_config_set(int fd, uint32_t uid, bool zygote_forks, bool stack,
                          bool raw_openat, bool raw_connect, bool path_fallback,
                          uint32_t payload_limit, char *err, size_t errlen)
{
    uint32_t key = 0;
    struct {
        uint32_t target_uid;
        uint32_t flags;
        uint32_t payload_limit;
    } value = {uid, (zygote_forks ? 1u : 0u) | (stack ? 2u : 0u) |
                        (raw_openat ? 4u : 0u) | (raw_connect ? 8u : 0u) |
                        (path_fallback ? 16u : 0u),
               payload_limit};
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(uintptr_t)&key;
    attr.value = (uint64_t)(uintptr_t)&value;
    attr.flags = BPF_ANY;
    if (syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) != 0) {
        set_err(err, errlen, "BPF_MAP_UPDATE_ELEM(config): %s",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int bpf_stats_read(int fd, uint32_t key, uint64_t *value, char *err,
                          size_t errlen)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(uintptr_t)&key;
    attr.value = (uint64_t)(uintptr_t)value;
    if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) != 0) {
        set_err(err, errlen, "BPF_MAP_LOOKUP_ELEM(stats): %s",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int bpf_load_program(const struct gt_program *prog, uint32_t prog_type,
                            char *err, size_t errlen)
{
    static char log_buf[64 * 1024];
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insn_cnt = (uint32_t)prog->insn_cnt;
    attr.insns = (uint64_t)(uintptr_t)prog->insns;
    attr.license = (uint64_t)(uintptr_t)"GPL";
    if (prog_type == BPF_PROG_TYPE_KPROBE && !kernel_at_least(5, 0))
        attr.kern_version = kernel_version_code();

    int fd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd >= 0)
        return fd;

    attr.log_buf = (uint64_t)(uintptr_t)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;
    memset(log_buf, 0, sizeof(log_buf));
    fd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        set_err(err, errlen, "BPF_PROG_LOAD %s: %s", prog->section,
                strerror(errno));
        if (log_buf[0])
            log_msg("verifier log for %s:\n%s", prog->section, log_buf);
        return -1;
    }
    return fd;
}

static int perf_attach(int prog_fd, int tracepoint_id, const int *cpus,
                       int cpu_count, struct perf_fds *out, char *err,
                       size_t errlen)
{
    // A tracepoint program is registered on the tracepoint itself, so one
    // perf event is enough. Linux 4.19 returns EEXIST if the same program is
    // attached to a second CPU event for the same tracepoint.
    int cpu = cpu_count > 0 ? cpus[0] : 0;
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_TRACEPOINT;
    pe.size = sizeof(pe);
    pe.config = (uint64_t)tracepoint_id;
    pe.sample_period = 1;
    pe.wakeup_events = 1;
    pe.disabled = 1;
    int fd = (int)syscall(__NR_perf_event_open, &pe, -1, cpu, -1,
                          PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        set_err(err, errlen, "perf_event_open(cpu=%d, tp=%d): %s", cpu,
                tracepoint_id, strerror(errno));
        return -1;
    }
    if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0) {
        set_err(err, errlen, "PERF_EVENT_IOC_SET_BPF(cpu=%d): %s", cpu,
                strerror(errno));
        close(fd);
        return -1;
    }
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        set_err(err, errlen, "PERF_EVENT_IOC_ENABLE(cpu=%d): %s", cpu,
                strerror(errno));
        close(fd);
        return -1;
    }
    if (out->count >= MAX_PERF_FDS) {
        set_err(err, errlen, "too many perf fds");
        close(fd);
        return -1;
    }
    out->fds[out->count++] = fd;
    return 0;
}

static int parse_online_cpus(int *cpus, int max, int *count, char *err,
                             size_t errlen)
{
    const char *path = "/sys/devices/system/cpu/online";
    char buf[1024] = {};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int n = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (n <= 0 || n > max) {
            set_err(err, errlen, "cannot determine online CPUs");
            return -1;
        }
        for (int i = 0; i < n; i++)
            cpus[i] = i;
        *count = n;
        return 0;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        set_err(err, errlen, "read %s failed", path);
        return -1;
    }

    int c = 0;
    char *p = buf;
    while (*p) {
        while (*p == ',' || isspace((unsigned char)*p))
            p++;
        if (!*p)
            break;
        char *end = NULL;
        long start = strtol(p, &end, 10);
        if (end == p)
            break;
        long stop = start;
        p = end;
        if (*p == '-') {
            p++;
            stop = strtol(p, &end, 10);
            if (end == p)
                break;
            p = end;
        }
        if (start < 0 || stop < start || stop >= max) {
            set_err(err, errlen, "invalid online CPU range");
            return -1;
        }
        for (long v = start; v <= stop && c < max; v++)
            cpus[c++] = (int)v;
        if (*p == ',')
            p++;
    }
    if (c == 0) {
        set_err(err, errlen, "no online CPUs parsed");
        return -1;
    }
    *count = c;
    return 0;
}

// ---------------------------------------------------------------------------
// Tracefs and uprobes

static const char *find_tracefs(const char *explicit_path)
{
    static char chosen[256];
    const char *candidates[3] = {explicit_path, "/sys/kernel/tracing",
                                 "/sys/kernel/debug/tracing"};
    for (int i = 0; i < 3; i++) {
        if (!candidates[i] || !candidates[i][0])
            continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/events", candidates[i]);
        if (file_exists(path)) {
            snprintf(chosen, sizeof(chosen), "%s", candidates[i]);
            return chosen;
        }
    }
    return NULL;
}

static int tracepoint_id(const char *tracefs, const char *group,
                         const char *event, int *id, char *err, size_t errlen)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/events/%s/%s/id", tracefs, group, event);
    return read_int_file(path, id, err, errlen);
}

static bool tracepoint_available(const char *tracefs, const char *group,
                                 const char *event)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/events/%s/%s/id", tracefs, group, event);
    return access(path, R_OK) == 0;
}

static int uprobe_event_id(const char *tracefs, const char *group,
                           const char *event, int *id, char *err,
                           size_t errlen)
{
    return tracepoint_id(tracefs, group, event, id, err, errlen);
}

static int uprobe_write(const char *tracefs, const char *line, char *err,
                        size_t errlen)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/uprobe_events", tracefs);
    return write_text(path, line, err, errlen);
}

static int uprobe_remove(const char *tracefs, const char *spec)
{
    char line[128];
    snprintf(line, sizeof(line), "-:%s\n", spec);
    char path[512];
    snprintf(path, sizeof(path), "%s/uprobe_events", tracefs);
    // Removal of a missing event is harmless.
    (void)write_text(path, line, NULL, 0);
    return 0;
}

static int uprobe_create(const char *tracefs, const char *group,
                         const char *event, const char *lib_path,
                         uint64_t offset, bool is_return, char *err,
                         size_t errlen)
{
    char spec[64];
    snprintf(spec, sizeof(spec), "%s/%s", group, event);
    uprobe_remove(tracefs, spec);

    char line[1024];
    snprintf(line, sizeof(line), "%c:%s %s:0x%llx\n",
             is_return ? 'r' : 'p', spec, lib_path,
             (unsigned long long)offset);
    if (uprobe_write(tracefs, line, err, errlen) != 0) {
        // Retry once after an explicit removal for stale definitions.
        uprobe_remove(tracefs, spec);
        if (uprobe_write(tracefs, line, err, errlen) != 0)
            return -1;
    }
    return 0;
}

// Remove uprobe definitions left behind by an earlier run (SIGKILL, lost
// connection, dead battery). Anything whose group matches the session pattern
// is ours; other groups are never touched.
static void uprobe_clean_stale(const char *tracefs)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/uprobe_events", tracefs);
    // read_file() sizes the buffer via fstat(), which reports 0 for tracefs
    // files; read until EOF instead.
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    size_t cap = 4096;
    size_t size = 0;
    char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        return;
    }
    for (;;) {
        if (size + 1 >= cap) {
            cap *= 2;
            char *grown = realloc(buf, cap);
            if (!grown) {
                free(buf);
                close(fd);
                return;
            }
            buf = grown;
        }
        ssize_t n = read(fd, buf + size, cap - size - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        size += (size_t)n;
    }
    close(fd);
    buf[size] = '\0';
    char *line = buf;
    char *end = buf + size;
    while (line < end) {
        char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        line[len] = '\0';
        // Line format: "p:<group>/<event> <object>:0x<offset> [opts]"
        char *spec = NULL;
        if ((line[0] == 'p' || line[0] == 'r') && line[1] == ':')
            spec = line + 2;
        if (spec) {
            char *space = strchr(spec, ' ');
            if (space)
                *space = '\0';
            char *slash = strchr(spec, '/');
            if (slash) {
                *slash = '\0';
                bool ours = group_is_ours(spec);
                *slash = '/';
                if (ours)
                    uprobe_remove(tracefs, spec);
            }
        }
        line += len + 1;
    }
    free(buf);
}

// ---------------------------------------------------------------------------
// Ring buffer

static void ringbuf_close(struct ringbuf *rb)
{
    if (rb->consumer_map && rb->consumer_map != MAP_FAILED)
        munmap(rb->consumer_map, rb->page_size);
    if (rb->producer_map && rb->producer_map != MAP_FAILED)
        munmap(rb->producer_map, rb->page_size);
    if (rb->data_map && rb->data_map != MAP_FAILED)
        munmap(rb->data_map, 2 * rb->max_entries);
    if (rb->map_fd >= 0)
        close(rb->map_fd);
    memset(rb, 0, sizeof(*rb));
    rb->map_fd = -1;
}

static int ringbuf_open(struct ringbuf *rb, int map_fd, size_t max_entries,
                        char *err, size_t errlen)
{
    memset(rb, 0, sizeof(*rb));
    rb->map_fd = map_fd;
    rb->max_entries = max_entries;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        set_err(err, errlen, "cannot determine page size");
        return -1;
    }
    rb->page_size = (size_t)page;
    if ((max_entries & (max_entries - 1)) != 0 ||
        max_entries % rb->page_size != 0) {
        set_err(err, errlen, "ringbuf size must be page-aligned power of two");
        return -1;
    }

    rb->consumer_map = mmap(NULL, rb->page_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, map_fd, 0);
    if (rb->consumer_map == MAP_FAILED) {
        set_err(err, errlen, "mmap consumer: %s", strerror(errno));
        goto fail;
    }
    rb->producer_map = mmap(NULL, rb->page_size, PROT_READ, MAP_SHARED, map_fd,
                            (off_t)rb->page_size);
    if (rb->producer_map == MAP_FAILED) {
        set_err(err, errlen, "mmap producer: %s", strerror(errno));
        goto fail;
    }
    rb->data_map = mmap(NULL, 2 * rb->max_entries, PROT_READ, MAP_SHARED,
                        map_fd, (off_t)(2 * rb->page_size));
    if (rb->data_map == MAP_FAILED) {
        set_err(err, errlen, "mmap data: %s", strerror(errno));
        goto fail;
    }
    rb->consumer = (volatile uint64_t *)rb->consumer_map;
    rb->producer = (volatile uint64_t *)rb->producer_map;
    rb->data = (uint8_t *)rb->data_map;
    return 0;

fail:
    // The caller keeps ownership of map_fd on failure.
    rb->map_fd = -1;
    ringbuf_close(rb);
    return -1;
}

// ---------------------------------------------------------------------------
// Perf event buffer (kernels without BPF ringbuf, e.g. Linux 4.19)

static void perf_reader_close(struct perf_reader *pr)
{
    for (int i = 0; i < pr->cpu_count; i++) {
        if (pr->cpu[i].map && pr->cpu[i].map != MAP_FAILED)
            munmap(pr->cpu[i].map, pr->cpu[i].map_len);
        if (pr->cpu[i].fd >= 0)
            close(pr->cpu[i].fd);
        pr->cpu[i].map = NULL;
        pr->cpu[i].fd = -1;
    }
    pr->cpu_count = 0;
}

static int perf_map_update(int map_fd, int cpu, int event_fd, char *err,
                           size_t errlen)
{
    uint32_t key = (uint32_t)cpu;
    uint32_t value = (uint32_t)event_fd;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)&key;
    attr.value = (uint64_t)(uintptr_t)&value;
    attr.flags = BPF_ANY;
    if (syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) != 0) {
        set_err(err, errlen, "BPF_MAP_UPDATE_ELEM(events, cpu=%d): %s", cpu,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int perf_reader_open(struct perf_reader *pr, int map_fd, const int *cpus,
                            int cpu_count, char *err, size_t errlen)
{
    memset(pr, 0, sizeof(*pr));
    for (int i = 0; i < MAX_CPUS; i++)
        pr->cpu[i].fd = -1;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        set_err(err, errlen, "cannot determine page size");
        return -1;
    }

    for (int i = 0; i < cpu_count && i < MAX_CPUS; i++) {
        int cpu = cpus[i];
        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(pe));
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_BPF_OUTPUT;
        pe.sample_type = PERF_SAMPLE_RAW;
        pe.sample_period = 1;
        pe.wakeup_events = 1;
        pe.disabled = 1;
        int fd = (int)syscall(__NR_perf_event_open, &pe, -1, cpu, -1,
                              PERF_FLAG_FD_CLOEXEC);
        if (fd < 0) {
            set_err(err, errlen, "perf_event_open(output, cpu=%d): %s", cpu,
                    strerror(errno));
            if (pr->cpu_count > 0) {
                log_msg("%s (continuing with %d CPUs)", err, pr->cpu_count);
                continue;
            }
            goto fail;
        }
        size_t map_len = ((size_t)PERF_DATA_PAGES + 1) * (size_t)page;
        void *map = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                         0);
        if (map == MAP_FAILED) {
            set_err(err, errlen, "mmap(perf cpu=%d): %s", cpu,
                    strerror(errno));
            close(fd);
            if (pr->cpu_count > 0) {
                log_msg("%s (continuing with %d CPUs)", err, pr->cpu_count);
                continue;
            }
            goto fail;
        }
        if (perf_map_update(map_fd, cpu, fd, err, errlen) != 0) {
            munmap(map, map_len);
            close(fd);
            if (pr->cpu_count > 0) {
                log_msg("%s (continuing with %d CPUs)", err, pr->cpu_count);
                continue;
            }
            goto fail;
        }
        struct perf_reader_cpu *slot = &pr->cpu[pr->cpu_count];
        slot->fd = fd;
        slot->map = map;
        slot->map_len = map_len;
        slot->page_size = (size_t)page;
        pr->cpu_count++;
        if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
            set_err(err, errlen, "PERF_EVENT_IOC_ENABLE(cpu=%d): %s", cpu,
                    strerror(errno));
            goto fail;
        }
    }
    if (pr->cpu_count == 0) {
        set_err(err, errlen, "no perf output event could be opened");
        goto fail;
    }
    return 0;

fail:
    perf_reader_close(pr);
    return -1;
}

static size_t round_up8(size_t v)
{
    return (v + 7) & ~(size_t)7;
}

// ---------------------------------------------------------------------------
// JSONL output

static FILE *g_out;
static char g_output_buffer[1024 * 1024];
static uint64_t g_seq;
static const char *g_session;
static uint64_t g_location_offsets[EV_MAX];
static bool g_location_offset_set[EV_MAX];

static void json_escape(const uint8_t *s, size_t n)
{
    fputc('"', g_out);
    for (size_t i = 0; i < n && s[i]; i++) {
        uint8_t c = s[i];
        if (c == '"' || c == '\\') {
            fputc('\\', g_out);
            fputc(c, g_out);
        } else if (c == '\n') {
            fputs("\\n", g_out);
        } else if (c == '\r') {
            fputs("\\r", g_out);
        } else if (c == '\t') {
            fputs("\\t", g_out);
        } else if (c >= 0x20 && c < 0x7f) {
            fputc(c, g_out);
        } else {
            fprintf(g_out, "\\u%04x", c);
        }
    }
    fputc('"', g_out);
}

static void json_hex(const uint8_t *s, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    fputc('"', g_out);
    while (n) {
        char encoded[256];
        size_t count = n < sizeof(encoded) / 2 ? n : sizeof(encoded) / 2;
        for (size_t i = 0; i < count; i++) {
            encoded[i * 2] = hex[s[i] >> 4];
            encoded[i * 2 + 1] = hex[s[i] & 0xf];
        }
        fwrite(encoded, 2, count, g_out);
        s += count;
        n -= count;
    }
    fputc('"', g_out);
}

static uint64_t g_real_base_ns;
static uint64_t g_mono_base_ns;

static void iso_time(uint64_t mono_ns, char *buf, size_t len)
{
    uint64_t wall_ns = g_real_base_ns;
    if (mono_ns >= g_mono_base_ns)
        wall_ns += mono_ns - g_mono_base_ns;
    time_t sec = (time_t)(wall_ns / 1000000000ull);
    long nsec = (long)(wall_ns % 1000000000ull);
    struct tm tm;
    gmtime_r(&sec, &tm);
    snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
             tm.tm_min, tm.tm_sec, nsec / 1000000);
}

static void emit_tool_drop(uint64_t count, const char *reason)
{
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    uint64_t mono_ns = (uint64_t)mono.tv_sec * 1000000000ull +
                       (uint64_t)mono.tv_nsec;
    char ts[40];
    iso_time(mono_ns, ts, sizeof(ts));
    fprintf(g_out,
            "{\"schema\":\"geektrace.event.v1\",\"seq\":%llu,"
            "\"session\":\"%s\",\"ts\":\"%s\",\"mono_ns\":%llu,"
            "\"layer\":\"tool\",\"kind\":\"tool.drop\",\"backend\":\"ebpf\","
            "\"confidence\":\"exact\",\"args\":{\"count\":%llu,"
            "\"reason\":\"%s\"},"
            "\"policy\":{\"redacted\":false,\"truncated\":false}}\n",
            (unsigned long long)++g_seq, g_session, ts,
            (unsigned long long)mono_ns, (unsigned long long)count, reason);
}

static void emit_tool_gap(const char *reason, const char *message)
{
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    uint64_t mono_ns = (uint64_t)mono.tv_sec * 1000000000ull +
                       (uint64_t)mono.tv_nsec;
    char ts[40];
    iso_time(mono_ns, ts, sizeof(ts));
    fprintf(g_out,
            "{\"schema\":\"geektrace.event.v1\",\"seq\":%llu,"
            "\"session\":\"%s\",\"ts\":\"%s\",\"mono_ns\":%llu,"
            "\"layer\":\"tool\",\"kind\":\"tool.gap\",\"backend\":\"ebpf\","
            "\"confidence\":\"partial\",\"args\":{\"reason\":",
            (unsigned long long)++g_seq, g_session, ts,
            (unsigned long long)mono_ns);
    json_escape((const uint8_t *)reason, strlen(reason));
    fputs(",\"message\":", g_out);
    json_escape((const uint8_t *)message, strlen(message));
    fputs("},"
          "\"policy\":{\"redacted\":false,\"truncated\":false}}\n",
          g_out);
}

// The capability event states what this device can actually deliver, so a
// report can tell "not observed" apart from "not supported here".
struct capability_info {
    const char *transport;
    const char *user_read;
    const char *path_source;
    const char *uprobe_mode;
    uint32_t payload_limit;
    bool stack_enabled;
    bool stack_supported;
    bool paired_uprobes;
    int probes_attached;
    int probes_total;
    int probes_failed;
    const char *libssl;
    const char *libcrypto;
    const char *libraries;
    int library_copies;
    int lib_copy_limit;
    int shared_copies;
};

// Defined after g_attached_libs; forward declaration for the capability event.
static int count_shared_copies(void);

static void emit_tool_capability(const struct capability_info *info)
{
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    uint64_t mono_ns = (uint64_t)mono.tv_sec * 1000000000ull +
                       (uint64_t)mono.tv_nsec;
    char ts[40];
    iso_time(mono_ns, ts, sizeof(ts));
    fprintf(g_out,
            "{\"schema\":\"geektrace.event.v1\",\"seq\":%llu,"
            "\"session\":\"%s\",\"ts\":\"%s\",\"mono_ns\":%llu,"
            "\"layer\":\"tool\",\"kind\":\"tool.capability\",\"backend\":\"ebpf\","
            "\"confidence\":\"exact\",\"args\":{"
            "\"transport\":\"%s\",\"user_read\":\"%s\",\"path_source\":\"%s\","
            "\"uprobe_mode\":\"%s\","
            "\"payload_limit\":%u,\"stack\":%s,\"stack_supported\":%s,"
            "\"paired_uprobes\":%s,\"probes_attached\":%d,\"probes_total\":%d,"
            "\"probes_failed\":%d,\"libssl\":",
            (unsigned long long)++g_seq, g_session, ts,
            (unsigned long long)mono_ns, info->transport, info->user_read,
            info->path_source, info->uprobe_mode, info->payload_limit,
            info->stack_enabled ? "true" : "false",
            info->stack_supported ? "true" : "false",
            info->paired_uprobes ? "true" : "false", info->probes_attached,
            info->probes_total, info->probes_failed);
    if (info->libssl)
        json_escape((const uint8_t *)info->libssl, strlen(info->libssl));
    else
        fputs("null", g_out);
    fputs(",\"libcrypto\":", g_out);
    if (info->libcrypto)
        json_escape((const uint8_t *)info->libcrypto, strlen(info->libcrypto));
    else
        fputs("null", g_out);
    fputs(",\"libraries\":", g_out);
    if (info->libraries && info->libraries[0])
        json_escape((const uint8_t *)info->libraries, strlen(info->libraries));
    else
        fputs("null", g_out);
    fprintf(g_out, ",\"library_copies\":%d", info->library_copies);
    fprintf(g_out, ",\"lib_copy_limit\":%d", info->lib_copy_limit);
    fprintf(g_out, ",\"shared_copies\":%d", info->shared_copies);
    fputs("},"
          "\"policy\":{\"redacted\":false,\"truncated\":false,"
          "\"capture_status\":\"not_applicable\",\"payload_bytes\":0}}\n",
          g_out);
}

struct map_range {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char path[512];
};

// Extract the mapped file path from one /proc/<pid>/maps line. The line has
// five leading fields (address, permissions, offset, device, inode); an
// anonymous mapping has no path at all.
static const char *maps_line_path(const char *line)
{
    const char *cursor = line;
    for (int field = 0; field < 5; field++) {
        const char *space = strchr(cursor, ' ');
        if (!space)
            return NULL;
        cursor = space;
        while (*cursor == ' ')
            cursor++;
    }
    if (!*cursor)
        return NULL;
    return cursor;
}

static size_t read_map_ranges(uint32_t pid, struct map_range **out)
{
    *out = NULL;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps)
        return 0;
    size_t capacity = 1024;
    size_t count = 0;
    struct map_range *ranges = calloc(capacity, sizeof(*ranges));
    if (!ranges) {
        fclose(maps);
        return 0;
    }
    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        if (count == capacity) {
            size_t next = capacity * 2;
            struct map_range *grown = realloc(ranges, next * sizeof(*ranges));
            if (!grown) {
                fclose(maps);
                *out = ranges;
                return count;
            }
            ranges = grown;
            capacity = next;
        }
        struct map_range range = {};
        int path_pos = 0;
        if (sscanf(line, "%llx-%llx %*4s %llx %*s %*u %n",
                   (unsigned long long *)&range.start,
                   (unsigned long long *)&range.end,
                   (unsigned long long *)&range.offset, &path_pos) < 3)
            continue;
        const char *name = maps_line_path(line);
        if (name) {
            char trimmed[512];
            snprintf(trimmed, sizeof(trimmed), "%s", name);
            trimmed[strcspn(trimmed, "\r\n")] = '\0';
            snprintf(range.path, sizeof(range.path), "%s", trimmed);
        }
        ranges[count++] = range;
    }
    fclose(maps);
    *out = ranges;
    return count;
}

// The maps file is sorted by start address, so a binary search resolves a
// program counter without walking every mapping.
static const struct map_range *find_range_for_pc(const struct map_range *ranges,
                                                 size_t count, uint64_t pc)
{
    size_t low = 0;
    size_t high = count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (pc < ranges[mid].start) {
            high = mid;
        } else if (pc >= ranges[mid].end) {
            low = mid + 1;
        } else {
            return &ranges[mid];
        }
    }
    return NULL;
}

#define MAP_CACHE_SLOTS 8
#define MAP_REFRESH_INTERVAL_NS 100000000ull

struct map_cache_entry {
    uint32_t pid;
    uint64_t last_used;
    uint64_t refreshed_ns;
    struct map_range *ranges;
    size_t count;
    bool loaded;
};

static struct map_cache_entry g_map_cache[MAP_CACHE_SLOTS];
static uint64_t g_map_cache_clock;

static const struct map_range *cached_map_ranges(const struct gt_event *e,
                                                 bool refresh,
                                                 size_t *range_count)
{
    int selected = -1;
    int empty = -1;
    int oldest = 0;
    for (int i = 0; i < MAP_CACHE_SLOTS; i++) {
        if (g_map_cache[i].pid == e->pid)
            selected = i;
        if (!g_map_cache[i].pid && empty < 0)
            empty = i;
        if (g_map_cache[i].last_used < g_map_cache[oldest].last_used)
            oldest = i;
    }
    if (selected < 0)
        selected = empty >= 0 ? empty : oldest;
    struct map_cache_entry *entry = &g_map_cache[selected];
    if (entry->pid != e->pid) {
        free(entry->ranges);
        memset(entry, 0, sizeof(*entry));
        entry->pid = e->pid;
    }
    entry->last_used = ++g_map_cache_clock;
    bool refresh_due = refresh &&
        (!entry->refreshed_ns || e->ts_ns < entry->refreshed_ns ||
         e->ts_ns - entry->refreshed_ns >= MAP_REFRESH_INTERVAL_NS);
    if (!entry->loaded || refresh_due) {
        struct map_range *ranges = NULL;
        size_t count = read_map_ranges(e->pid, &ranges);
        free(entry->ranges);
        entry->ranges = ranges;
        entry->count = count;
        entry->refreshed_ns = e->ts_ns;
        entry->loaded = true;
    }
    *range_count = entry->count;
    return entry->ranges;
}

static void free_map_cache(void)
{
    for (int i = 0; i < MAP_CACHE_SLOTS; i++)
        free(g_map_cache[i].ranges);
}

static void emit_stack(const struct gt_event *e)
{
    fputs(",\"stack\":[", g_out);
    uint32_t depth = e->stack_depth;
    if (depth > EVENT_STACK_DEPTH)
        depth = EVENT_STACK_DEPTH;
    struct map_range const *ranges = NULL;
    size_t range_count = 0;
    if (depth) {
        ranges = cached_map_ranges(e, false, &range_count);
        for (uint32_t i = 0; i < depth; i++) {
            if (!find_range_for_pc(ranges, range_count, e->stack[i])) {
                ranges = cached_map_ranges(e, true, &range_count);
                break;
            }
        }
    }
    for (uint32_t i = 0; i < depth; i++) {
        uint64_t pc = e->stack[i];
        const struct map_range *match =
            find_range_for_pc(ranges, range_count, pc);
        fprintf(g_out, "%s{\"pc\":\"0x%llx\",\"resolved\":%s", i ? "," : "",
                (unsigned long long)pc, match ? "true" : "false");
        if (match) {
            uint64_t offset = match->offset + pc - match->start;
            fputs(",\"module\":", g_out);
            json_escape((const uint8_t *)match->path, strlen(match->path));
            fprintf(g_out, ",\"file_offset\":\"0x%llx\"",
                    (unsigned long long)offset);
        }
        fputc('}', g_out);
    }
    fputc(']', g_out);
}

static void emit_correlation(const struct gt_event *e, const char *layer)
{
    fputs(",\"correlation\":{", g_out);
    if (strcmp(layer, "net") == 0 || strcmp(layer, "crypto") == 0) {
        uint64_t entry_ts = e->arg2 ? e->arg2 : e->ts_ns;
        fprintf(g_out, "\"call_id\":\"%u-%u-%llu\"",
                e->pid, e->tid, (unsigned long long)entry_ts);
        if (e->kind == EV_SSL_WRITE || e->kind == EV_SSL_READ) {
            if (e->arg1)
                fprintf(g_out, ",\"connection_id\":\"ssl:%u:0x%llx\"",
                        e->pid, (unsigned long long)e->arg1);
        } else if (e->kind == EV_CONNECT) {
            fprintf(g_out, ",\"socket_id\":\"fd:%u:%d\"",
                    e->pid, (int32_t)e->arg0);
        } else if (strcmp(layer, "crypto") == 0 && e->arg1 &&
                   e->kind != EV_EVP_DIGEST_ONESHOT) {
            // EVP_Digest's second argument is the data pointer, not an
            // EVP_CTX, so it must not be published as a context id.
            fprintf(g_out, ",\"context_id\":\"ctx:%u:0x%llx\"",
                    e->pid, (unsigned long long)e->arg1);
        }
    }
    fputc('}', g_out);
}

static void emit_envelope(const struct gt_event *e, const char *layer,
                          const char *kind, const char *location_module,
                          const char *location_symbol, bool truncated,
                          void (*emit_args)(const struct gt_event *))
{
    char ts[40];
    iso_time(e->ts_ns, ts, sizeof(ts));
    fprintf(g_out,
            "{\"schema\":\"geektrace.event.v1\",\"seq\":%llu,"
            "\"session\":\"%s\",\"ts\":\"%s\",\"mono_ns\":%llu,"
            "\"layer\":\"%s\",\"kind\":\"%s\",\"backend\":\"ebpf\","
            "\"confidence\":\"exact\",\"pid\":%u,\"tid\":%u,\"uid\":%u,"
            "\"comm\":",
            (unsigned long long)++g_seq, g_session, ts,
            (unsigned long long)e->ts_ns, layer, kind, e->pid, e->tid,
            e->uid);
    json_escape((const uint8_t *)e->comm, sizeof(e->comm));
    fputs(",\"thread\":", g_out);
    json_escape((const uint8_t *)e->comm, sizeof(e->comm));
    if (location_symbol) {
        fputs(",\"location\":{\"module\":", g_out);
        json_escape((const uint8_t *)location_module,
                    strlen(location_module));
        if (e->kind < EV_MAX && g_location_offset_set[e->kind])
            fprintf(g_out, ",\"file_offset\":\"0x%llx\"",
                    (unsigned long long)g_location_offsets[e->kind]);
        fputs(",\"symbol\":", g_out);
        json_escape((const uint8_t *)location_symbol,
                    strlen(location_symbol));
        fputc('}', g_out);
    }
    fputs(",\"args\":", g_out);
    emit_args(e);
    emit_correlation(e, layer);
    emit_stack(e);
    int64_t payload_len = e->kind == EV_CONNECT ? (int64_t)e->arg1
                                                : (int64_t)(int32_t)e->arg0;
    bool payload_event = strcmp(layer, "net") == 0 || strcmp(layer, "crypto") == 0;
    // The kernel never tells us the real length of a path, so a full buffer can
    // still be a truncated path. Everything else is derived from the length
    // the syscall reported.
    const char *capture_status = "not_applicable";
    if (strcmp(layer, "file") == 0) {
        if (e->dlen == 0)
            capture_status = "read_failed";
        else if (e->dlen >= EVENT_DATA_LEN - 1)
            capture_status = "truncated";
        else
            capture_status = "captured";
    } else if (payload_event) {
        if (g_payload_limit == 0)
            capture_status = "metadata_only";
        else if (payload_len <= 0)
            capture_status = "empty";
        else if (e->dlen == 0)
            capture_status = "read_failed";
        else if ((int64_t)e->dlen < payload_len)
            capture_status = "truncated";
        else
            capture_status = "captured";
    }
    truncated = strcmp(capture_status, "truncated") == 0;
    uint64_t omitted = payload_event && payload_len > (int64_t)e->dlen
                           ? (uint64_t)payload_len - e->dlen
                           : 0;
    bool sensitive = e->dlen > 0 && payload_event;
    fprintf(g_out,
            ",\"policy\":{\"redacted\":false,\"sensitive\":%s,"
            "\"truncated\":%s,\"sampled\":false,\"omitted_bytes\":%llu,"
            "\"capture_status\":\"%s\",\"payload_bytes\":%u},"
            "\"evidence_ids\":[]}\n",
            sensitive ? "true" : "false", truncated ? "true" : "false",
            (unsigned long long)omitted, capture_status, (unsigned)e->dlen);
}

static void emit_detection(const struct gt_event *e, const char *category,
                           const char *rule, const char *confidence,
                           uint64_t evidence_seq)
{
    char ts[40];
    iso_time(e->ts_ns, ts, sizeof(ts));
    fprintf(g_out,
            "{\"schema\":\"geektrace.event.v1\",\"seq\":%llu,"
            "\"session\":\"%s\",\"ts\":\"%s\",\"mono_ns\":%llu,"
            "\"layer\":\"detect\",\"kind\":\"detect.finding\","
            "\"backend\":\"ebpf\",\"confidence\":\"%s\",\"pid\":%u,"
            "\"tid\":%u,\"uid\":%u,\"comm\":",
            (unsigned long long)++g_seq, g_session, ts,
            (unsigned long long)e->ts_ns, confidence, e->pid, e->tid, e->uid);
    json_escape((const uint8_t *)e->comm, sizeof(e->comm));
    fputs(",\"thread\":", g_out);
    json_escape((const uint8_t *)e->comm, sizeof(e->comm));
    fprintf(g_out,
            ",\"args\":{\"category\":\"%s\",\"verdict\":\"observed\","
            "\"rule\":\"%s\",\"path\":",
            category, rule);
    json_escape(e->data, e->dlen);
    fprintf(g_out,
            "},\"correlation\":{},\"stack\":[],"
            "\"policy\":{\"redacted\":false,\"sensitive\":false,"
            "\"truncated\":false,\"sampled\":false,\"omitted_bytes\":0},"
            "\"evidence_ids\":[%llu]}\n",
            (unsigned long long)evidence_seq);
}

static void detect_open_path(const struct gt_event *e, uint64_t evidence_seq)
{
    static const char *root_paths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap",
    };
    char path[EVENT_DATA_LEN + 1];
    uint32_t length = e->dlen <= EVENT_DATA_LEN ? e->dlen : EVENT_DATA_LEN;
    memcpy(path, e->data, length);
    path[length] = '\0';
    for (size_t i = 0; i < sizeof(root_paths) / sizeof(root_paths[0]); i++) {
        if (strcmp(path, root_paths[i]) == 0) {
            emit_detection(e, "root", "root_path_open", "exact", evidence_seq);
            return;
        }
    }
    if (strstr(path, "frida") || strstr(path, "xposed") ||
        strstr(path, "lsposed") || strstr(path, "zygisk") ||
        strcmp(path, "/proc/self/maps") == 0) {
        emit_detection(e, "hook_integrity", "hook_artifact_path_open",
                       "inferred", evidence_seq);
        return;
    }
    size_t path_len = strlen(path);
    if (strncmp(path, "/proc/", 6) == 0 && path_len >= 7 &&
        strcmp(path + path_len - 7, "/status") == 0) {
        emit_detection(e, "debugger", "proc_status_open", "inferred",
                       evidence_seq);
        return;
    }
    if (strcmp(path, "/proc/net/dev") == 0 ||
        strcmp(path, "/proc/net/route") == 0 ||
        strcmp(path, "/proc/net/ipv6_route") == 0 ||
        strcmp(path, "/sys/class/net") == 0) {
        emit_detection(e, "network_state", "network_state_path_open", "exact",
                       evidence_seq);
    }
}

static void args_fork(const struct gt_event *e)
{
    fprintf(g_out,
            "{\"ppid\":%u,\"parent_pid\":%u,\"child_pid\":%u,\"parent_comm\":",
            (uint32_t)e->arg0, (uint32_t)e->arg0, (uint32_t)e->arg1);
    json_escape((const uint8_t *)e->data, EVENT_COMM_LEN);
    fputs(",\"child_comm\":", g_out);
    json_escape((const uint8_t *)e->data + EVENT_COMM_LEN, EVENT_COMM_LEN);
    fputc('}', g_out);
}

static void args_openat(const struct gt_event *e)
{
    fputs("{\"dfd\":", g_out);
    fprintf(g_out, "%d,\"flags\":\"0x%x\"", (int32_t)e->arg0,
            (uint32_t)e->arg1);
    if (e->reserved == GT_EVENT_SOURCE_PROC_FD) {
        int32_t result = (int32_t)e->ret;
        if (result >= 0) {
            fprintf(g_out, ",\"fd\":%d,\"path_source\":\"proc_fd\"", result);
        } else {
            const char *text = result > -4096 ? strerror(-result)
                                              : "unknown error";
            fputs(",\"result\":", g_out);
            fprintf(g_out, "%d,\"error\":", result);
            json_escape((const uint8_t *)text, strlen(text));
        }
    }
    fputs(",\"path\":", g_out);
    json_escape(e->data, e->dlen);
    fputc('}', g_out);
}

static void args_connect(const struct gt_event *e)
{
    uint16_t family = 0;
    if (e->dlen >= sizeof(family))
        memcpy(&family, e->data, sizeof(family));
    fprintf(g_out, "{\"fd\":%d,\"family\":%u", (int32_t)e->arg0, family);
    char address[INET6_ADDRSTRLEN];
    if (family == AF_INET && e->dlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in value;
        memcpy(&value, e->data, sizeof(value));
        if (inet_ntop(AF_INET, &value.sin_addr, address, sizeof(address)))
            fprintf(g_out, ",\"address\":\"%s\",\"port\":%u", address,
                    (unsigned)ntohs(value.sin_port));
    } else if (family == AF_INET6 && e->dlen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 value;
        memcpy(&value, e->data, sizeof(value));
        if (inet_ntop(AF_INET6, &value.sin6_addr, address, sizeof(address)))
            fprintf(g_out, ",\"address\":\"%s\",\"port\":%u", address,
                    (unsigned)ntohs(value.sin6_port));
    } else if (family == AF_UNIX && e->dlen > 2 && e->data[2]) {
        fputs(",\"address\":", g_out);
        json_escape(e->data + 2, e->dlen - 2);
    } else {
        fputs(",\"sockaddr_hex\":", g_out);
        json_hex(e->data, e->dlen);
    }
    fputc('}', g_out);
}

static void args_ssl_write(const struct gt_event *e)
{
    fprintf(g_out,
            "{\"dir\":\"out\",\"phase\":\"entry\",\"len\":%llu,"
            "\"input_len\":%llu,\"ssl\":\"0x%llx\",\"plaintext_head_hex\":",
            (unsigned long long)e->arg0, (unsigned long long)e->arg0,
            (unsigned long long)e->arg1);
    json_hex(e->data, e->dlen);
    fputc('}', g_out);
}

static void args_ssl_read(const struct gt_event *e)
{
    fprintf(g_out,
            "{\"dir\":\"in\",\"phase\":\"return\",\"len\":%d,\"ret\":%d,"
            "\"output_len\":%d,\"ssl\":\"0x%llx\",\"plaintext_head_hex\":",
            (int32_t)e->arg0, (int32_t)e->ret, (int32_t)e->arg0,
            (unsigned long long)e->arg1);
    if ((int32_t)e->arg0 > 0)
        json_hex(e->data, e->dlen);
    else
        json_hex(e->data, 0);
    fputc('}', g_out);
}

static void args_evp_cipher(const struct gt_event *e, const char *fn,
                            const char *dir)
{
    fprintf(g_out,
            "{\"fn\":\"%s\",\"dir\":\"%s\",\"phase\":\"entry\","
            "\"input_len\":%llu,\"ctx\":\"0x%llx\",\"input_head_hex\":",
            fn, dir, (unsigned long long)e->arg0,
            (unsigned long long)e->arg1);
    json_hex(e->data, e->dlen);
    fputc('}', g_out);
}

static void args_evp_encrypt(const struct gt_event *e)
{
    args_evp_cipher(e, "EVP_EncryptUpdate", "encrypt");
}

static void args_evp_decrypt(const struct gt_event *e)
{
    args_evp_cipher(e, "EVP_DecryptUpdate", "decrypt");
}

static void args_evp_cipher_return(const struct gt_event *e, const char *fn,
                                   const char *dir)
{
    fprintf(g_out,
            "{\"fn\":\"%s\",\"dir\":\"%s\",\"phase\":\"return\","
            "\"ret\":%d,\"output_len\":%u,\"ctx\":\"0x%llx\","
            "\"output_head_hex\":",
            fn, dir, (int32_t)e->ret, (uint32_t)e->arg0,
            (unsigned long long)e->arg1);
    json_hex(e->data, e->dlen);
    fputc('}', g_out);
}

static void args_evp_encrypt_return(const struct gt_event *e)
{
    args_evp_cipher_return(e, "EVP_EncryptUpdate", "encrypt");
}

static void args_evp_decrypt_return(const struct gt_event *e)
{
    args_evp_cipher_return(e, "EVP_DecryptUpdate", "decrypt");
}

static void args_evp_md_update(const struct gt_event *e, const char *fn,
                               const char *dir)
{
    fprintf(g_out,
            "{\"fn\":\"%s\",\"dir\":\"%s\",\"phase\":\"entry\","
            "\"input_len\":%llu,\"ctx\":\"0x%llx\",\"input_head_hex\":",
            fn, dir, (unsigned long long)e->arg0,
            (unsigned long long)e->arg1);
    json_hex(e->data, e->dlen);
    fputc('}', g_out);
}

static void args_evp_digest(const struct gt_event *e)
{
    args_evp_md_update(e, "EVP_DigestUpdate", "digest");
}

static void args_evp_sign_update(const struct gt_event *e)
{
    args_evp_md_update(e, "EVP_DigestSignUpdate", "sign");
}

static void args_evp_verify_update(const struct gt_event *e)
{
    args_evp_md_update(e, "EVP_DigestVerifyUpdate", "verify");
}

static void args_evp_digest_oneshot(const struct gt_event *e)
{
    fprintf(g_out,
            "{\"fn\":\"EVP_Digest\",\"dir\":\"digest\",\"phase\":\"entry\","
            "\"input_len\":%llu,\"data\":\"0x%llx\",\"input_head_hex\":",
            (unsigned long long)e->arg0, (unsigned long long)e->arg1);
    json_hex(e->data, e->dlen);
    fputc('}', g_out);
}

// Legacy kernels (< 5.8) cannot copy the openat path into the event, so the
// kernel reports the fd on sys_exit and the broker resolves it through procfs.
// This is the same information a tracer would read from /proc; it never
// touches target memory and adds no target-side work.
static void resolve_openat_path(struct gt_event *e)
{
    if (!g_path_fallback || e->reserved != GT_EVENT_SOURCE_PROC_FD)
        return;
    int32_t fd = (int32_t)e->ret;
    if (fd < 0)
        return;
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%u/fd/%d", e->pid, fd);
    char target[EVENT_DATA_LEN + 1];
    ssize_t n = readlink(link_path, target, sizeof(target) - 1);
    if (n <= 0)
        return;
    target[n] = '\0';
    uint32_t copy = (uint32_t)n;
    if (copy > EVENT_DATA_LEN)
        copy = EVENT_DATA_LEN;
    memcpy(e->data, target, copy);
    e->dlen = copy;
}

static void handle_event(const struct gt_event *e)
{
    bool truncated = false;
    if (e->uid == g_target_uid) {
        remember_target_pid(e->pid);
        if (!g_target_seen) {
            g_target_seen = 1;
            log_msg("target seen: pid %u uid %u", e->pid, e->uid);
        }
    }
    switch (e->kind) {
    case EV_FORK:
        emit_envelope(e, "process", "process.fork", NULL, NULL, false,
                      args_fork);
        remember_birth_candidate(e);
        break;
    case EV_OPENAT: {
        struct gt_event resolved = *e;
        resolve_openat_path(&resolved);
        emit_envelope(&resolved, "file", "file.open", NULL, NULL, false,
                      args_openat);
        detect_open_path(&resolved, g_seq);
        break;
    }
    case EV_CONNECT:
        truncated = e->arg1 > e->dlen;
        emit_envelope(e, "net", "net.connect", NULL, NULL, truncated,
                      args_connect);
        break;
    case EV_SSL_WRITE:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "net", "net.tls_write", "libssl.so", "SSL_write",
                      truncated, args_ssl_write);
        break;
    case EV_SSL_READ:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "net", "net.tls_read", "libssl.so", "SSL_read",
                      truncated, args_ssl_read);
        break;
    case EV_EVP_ENCRYPT:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.evp_update", "libcrypto.so",
                      "EVP_EncryptUpdate", truncated, args_evp_encrypt);
        break;
    case EV_EVP_DIGEST:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.evp_update", "libcrypto.so",
                      "EVP_DigestUpdate", truncated, args_evp_digest);
        break;
    case EV_EVP_DECRYPT:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.evp_update", "libcrypto.so",
                      "EVP_DecryptUpdate", truncated, args_evp_decrypt);
        break;
    case EV_EVP_ENCRYPT_RET:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.evp_update", "libcrypto.so",
                      "EVP_EncryptUpdate", truncated, args_evp_encrypt_return);
        break;
    case EV_EVP_DECRYPT_RET:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.evp_update", "libcrypto.so",
                      "EVP_DecryptUpdate", truncated, args_evp_decrypt_return);
        break;
    case EV_EVP_DIGEST_ONESHOT:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.digest", "libcrypto.so",
                      "EVP_Digest", truncated, args_evp_digest_oneshot);
        break;
    case EV_EVP_SIGN_UPDATE:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.sign_update", "libcrypto.so",
                      "EVP_DigestSignUpdate", truncated,
                      args_evp_sign_update);
        break;
    case EV_EVP_VERIFY_UPDATE:
        truncated = (int32_t)e->arg0 > (int32_t)e->dlen;
        emit_envelope(e, "crypto", "crypto.verify_update", "libcrypto.so",
                      "EVP_DigestVerifyUpdate", truncated,
                      args_evp_verify_update);
        break;
    default: {
        char ts[40];
        iso_time(e->ts_ns, ts, sizeof(ts));
        fprintf(g_out,
                "{\"schema\":\"geektrace.event.v1\",\"seq\":%llu,"
                "\"session\":\"%s\",\"ts\":\"%s\",\"mono_ns\":%llu,"
                "\"layer\":\"tool\",\"kind\":\"tool.unknown_probe\","
                "\"backend\":\"ebpf\",\"confidence\":\"partial\","
                "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
                (unsigned long long)++g_seq, g_session, ts,
                (unsigned long long)e->ts_ns, e->pid, e->tid, e->uid);
        json_escape((const uint8_t *)e->comm, sizeof(e->comm));
        fprintf(g_out, ",\"args\":{\"kind\":%u},"
                       "\"policy\":{\"redacted\":false,\"truncated\":true}}\n",
                e->kind);
        break;
    }
    }
}

static uint64_t ringbuf_drain(struct ringbuf *rb)
{
    uint64_t consumed = 0;
    uint64_t cons = __atomic_load_n(rb->consumer, __ATOMIC_ACQUIRE);
    uint64_t prod = __atomic_load_n(rb->producer, __ATOMIC_ACQUIRE);
    const uint64_t mask = rb->max_entries - 1;

    while (cons < prod) {
        uint32_t len = *(uint32_t *)(rb->data + (cons & mask));
        if (len & 0x80000000u) // BUSY
            break;
        uint32_t actual = len & 0x3fffffffu;
        size_t total = round_up8((size_t)actual + 8);
        if (prod - cons < total)
            break;
        if (!(len & 0x40000000u) && actual >= sizeof(struct gt_event)) {
            const struct gt_event *e = (const struct gt_event *)(
                rb->data + (cons & mask) + 8);
            handle_event(e);
            consumed++;
        }
        cons += total;
        __atomic_store_n(rb->consumer, cons, __ATOMIC_RELEASE);
    }
    return consumed;
}

// True while the producer still has events waiting. The broker keeps
// draining instead of sleeping so a burst does not overflow the ring buffer.
static bool ringbuf_pending(const struct ringbuf *rb)
{
    uint64_t cons = __atomic_load_n(rb->consumer, __ATOMIC_ACQUIRE);
    uint64_t prod = __atomic_load_n(rb->producer, __ATOMIC_ACQUIRE);
    return cons < prod;
}

static bool perf_ring_copy(const uint8_t *base, size_t offset, size_t size,
                           uint64_t pos, void *dst, size_t len)
{
    if (len > size)
        return false;
    size_t start = (size_t)(pos % size);
    size_t first = size - start;
    if (first > len)
        first = len;
    memcpy(dst, base + offset + start, first);
    if (first < len)
        memcpy((uint8_t *)dst + first, base + offset, len - first);
    return true;
}

static uint64_t perf_reader_drain(struct perf_reader *pr)
{
    uint64_t consumed = 0;

    for (int i = 0; i < pr->cpu_count; i++) {
        struct perf_reader_cpu *slot = &pr->cpu[i];
        struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)slot->map;
        uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
        uint64_t tail = meta->data_tail;
        if (head == tail)
            continue;

        const uint8_t *base = (const uint8_t *)meta;
        size_t offset = meta->data_offset ? (size_t)meta->data_offset
                                          : slot->page_size;
        size_t size = meta->data_size ? (size_t)meta->data_size
                                      : slot->map_len - slot->page_size;
        if (!size || offset + size > slot->map_len) {
            __atomic_store_n(&meta->data_tail, head, __ATOMIC_RELEASE);
            continue;
        }

        while (tail < head) {
            struct perf_event_header hdr;
            if (!perf_ring_copy(base, offset, size, tail, &hdr, sizeof(hdr))) {
                tail = head;
                break;
            }
            if (hdr.size < sizeof(hdr) || hdr.size > size) {
                __atomic_store_n(&meta->data_tail, head, __ATOMIC_RELEASE);
                return consumed;
            }
            if (hdr.type == PERF_RECORD_SAMPLE &&
                hdr.size >= sizeof(hdr) + sizeof(uint32_t)) {
                uint32_t raw_len = 0;
                perf_ring_copy(base, offset, size, tail + sizeof(hdr),
                               &raw_len, sizeof(raw_len));
                if (raw_len >= sizeof(struct gt_event) &&
                    (uint64_t)sizeof(hdr) + sizeof(raw_len) + raw_len <=
                        hdr.size) {
                    struct gt_event e;
                    if (perf_ring_copy(base, offset, size,
                                       tail + sizeof(hdr) + sizeof(raw_len),
                                       &e, sizeof(e))) {
                        handle_event(&e);
                        consumed++;
                    }
                }
            } else if (hdr.type == PERF_RECORD_LOST &&
                       hdr.size >= sizeof(hdr) + sizeof(uint64_t) * 2) {
                struct {
                    uint64_t id;
                    uint64_t lost;
                } lost = {};
                if (perf_ring_copy(base, offset, size, tail + sizeof(hdr),
                                   &lost, sizeof(lost)))
                    pr->lost += lost.lost;
            }
            tail += hdr.size;
        }
        __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
    }
    return consumed;
}

// ---------------------------------------------------------------------------
// Attach plan

struct attach_plan {
    const char *probe_suffix;
    const char *lib_name;
    const char *symbol;
    const char *event;
    uint32_t event_kind;
    bool is_return;
};

static const struct attach_plan g_uprobe_plan[] = {
    {"ssl_write", "ssl", "SSL_write", "gt_ssl_write", EV_SSL_WRITE, false},
    {"ssl_read", "ssl", "SSL_read", "gt_ssl_read", EV_SSL_READ, false},
    {"ssl_read", "ssl", "SSL_read", "gt_ssl_read_ret", EV_SSL_READ, true},
    {"evp_encrypt", "crypto", "EVP_EncryptUpdate", "gt_evp_encrypt", EV_EVP_ENCRYPT, false},
    {"evp_encrypt", "crypto", "EVP_EncryptUpdate", "gt_evp_encrypt_ret", EV_EVP_ENCRYPT_RET, true},
    {"evp_decrypt", "crypto", "EVP_DecryptUpdate", "gt_evp_decrypt", EV_EVP_DECRYPT, false},
    {"evp_decrypt", "crypto", "EVP_DecryptUpdate", "gt_evp_decrypt_ret", EV_EVP_DECRYPT_RET, true},
    {"evp_digest", "crypto", "EVP_DigestUpdate", "gt_evp_digest", EV_EVP_DIGEST, false},
    {"evp_digest_oneshot", "crypto", "EVP_Digest", "gt_evp_digest_oneshot", EV_EVP_DIGEST_ONESHOT, false},
    {"evp_sign_update", "crypto", "EVP_DigestSignUpdate",
     "gt_evp_sign_update", EV_EVP_SIGN_UPDATE, false},
    {"evp_verify_update", "crypto", "EVP_DigestVerifyUpdate",
     "gt_evp_verify_update", EV_EVP_VERIFY_UPDATE, false},
};

// Some tracefs implementations accept only one uprobe event per address: the
// second definition either replaces the first or fails with EBUSY. Probe the
// running kernel once so paired entry/return probes are only used where they
// can actually attach.
static bool tracefs_supports_paired_uprobes(const char *tracefs, const char *lib,
                                            uint64_t offset)
{
    char line[1024];
    char probe_spec[2][48];
    snprintf(probe_spec[0], sizeof(probe_spec[0]), "%s/gt_probe_p",
             g_probe_group);
    snprintf(probe_spec[1], sizeof(probe_spec[1]), "%s/gt_probe_r",
             g_probe_group);
    int id = -1;

    uprobe_remove(tracefs, probe_spec[0]);
    uprobe_remove(tracefs, probe_spec[1]);
    snprintf(line, sizeof(line), "p:%s/gt_probe_p %s:0x%llx\n", g_probe_group,
             lib, (unsigned long long)offset);
    if (uprobe_write(tracefs, line, NULL, 0) != 0)
        return false;
    snprintf(line, sizeof(line), "r:%s/gt_probe_r %s:0x%llx\n", g_probe_group,
             lib, (unsigned long long)offset);
    bool ok = uprobe_write(tracefs, line, NULL, 0) == 0;
    if (ok && (uprobe_event_id(tracefs, g_probe_group, "gt_probe_p", &id, NULL,
                                0) != 0 ||
               uprobe_event_id(tracefs, g_probe_group, "gt_probe_r", &id, NULL,
                               0) != 0))
        ok = false;
    uprobe_remove(tracefs, probe_spec[0]);
    uprobe_remove(tracefs, probe_spec[1]);
    return ok;
}

static const char *discover_lib(const char *name, char *buf, size_t buflen)
{
    const char *candidates[4];
    if (strcmp(name, "ssl") == 0) {
        candidates[0] = "/apex/com.android.conscrypt/lib64/libssl.so";
        candidates[1] = "/system/lib64/libssl.so";
        candidates[2] = "/system/lib/libssl.so";
        candidates[3] = NULL;
    } else {
        // The public library is what an app's own native code links against;
        // the Conscrypt copy is the fallback for apps that only use the Java
        // TLS provider.
        candidates[0] = "/system/lib64/libcrypto.so";
        candidates[1] = "/apex/com.android.conscrypt/lib64/libcrypto.so";
        candidates[2] = "/system/lib/libcrypto.so";
        candidates[3] = NULL;
    }
    for (int i = 0; candidates[i]; i++) {
        if (file_exists(candidates[i])) {
            snprintf(buf, buflen, "%s", candidates[i]);
            return buf;
        }
    }
    return NULL;
}

static const char *suffix_of(const char *section)
{
    const char *slash = strrchr(section, '/');
    return slash ? slash + 1 : section;
}

// ---------------------------------------------------------------------------
// Probe attachment
//
// A uprobe replaces the first instruction of the probed function with a trap.
// That patch lives in the library file's code page, so it is shared by every
// process that maps the library. Two rules keep the footprint minimal:
//   1. a library probe is attached only after the target process is known to
//      map that library, so libraries the target never uses stay untouched;
//   2. the probe is attached to the exact file the target loaded, which also
//      covers an app that ships its own BoringSSL instead of using the system
//      copy. The system copy is only used when the target maps it.

struct attach_ctx {
    struct bpf_image *image;
    const char *tracefs;
    const int *cpus;
    int cpu_count;
    struct perf_fds *perf;
    struct uprobe_state *uprobes;
    int *uprobe_count;
    int attached_programs;
    int total_programs;
    int failed_programs;
    int tracepoint_programs;
    bool raw_needed;
    bool raw_openat;
    bool raw_connect;
    bool path_fallback;
    bool paired_ssl;
    bool paired_crypto;
    // One program instance per attached library copy. The same probe section is
    // loaded again for every copy of the library the target uses.
    int extra_fds[128];
    int extra_fd_count;
};

static const struct attach_plan *find_attach_plan(const char *section)
{
    const char *suffix = suffix_of(section);
    bool want_return = strncmp(section, "uretprobe/", 10) == 0;
    for (size_t p = 0; p < sizeof(g_uprobe_plan) / sizeof(g_uprobe_plan[0]); p++) {
        if (strcmp(suffix, g_uprobe_plan[p].probe_suffix) == 0 &&
            g_uprobe_plan[p].is_return == want_return)
            return &g_uprobe_plan[p];
    }
    return NULL;
}

static int attach_tracepoint_programs(struct attach_ctx *ctx, char *err,
                                      size_t errlen)
{
    for (int i = 0; i < ctx->image->prog_count; i++) {
        struct gt_program *prog = &ctx->image->progs[i];
        if (strncmp(prog->section, "tracepoint/", 11) != 0)
            continue;
        if (strcmp(prog->section, "tracepoint/raw_syscalls/sys_enter") == 0 &&
            !ctx->raw_needed) {
            log_msg("skip %s: specific syscall tracepoints available",
                    prog->section);
            continue;
        }
        if (strcmp(prog->section, "tracepoint/syscalls/sys_enter_openat") == 0 &&
            ctx->raw_openat) {
            log_msg("skip %s: raw_syscalls in use", prog->section);
            continue;
        }
        if (strcmp(prog->section, "tracepoint/syscalls/sys_enter_connect") == 0 &&
            ctx->raw_connect) {
            log_msg("skip %s: raw_syscalls in use", prog->section);
            continue;
        }
        if (strcmp(prog->section, "tracepoint/raw_syscalls/sys_exit") == 0 &&
            !ctx->path_fallback) {
            log_msg("skip %s: openat path fallback inactive", prog->section);
            continue;
        }
        ctx->total_programs++;
        prog->fd = bpf_load_program(prog, BPF_PROG_TYPE_TRACEPOINT, err, errlen);
        if (prog->fd < 0) {
            log_msg("skip %s: %s", prog->section, err);
            ctx->failed_programs++;
            continue;
        }
        int tracepoint = -1;
        char group[64] = {};
        char event[64] = {};
        if (sscanf(prog->section, "tracepoint/%63[^/]/%63s", group, event) != 2) {
            log_msg("skip %s: bad section name", prog->section);
            ctx->failed_programs++;
            continue;
        }
        if (tracepoint_id(ctx->tracefs, group, event, &tracepoint, err,
                          errlen) != 0) {
            log_msg("skip %s: %s", prog->section, err);
            ctx->failed_programs++;
            continue;
        }
        if (perf_attach(prog->fd, tracepoint, ctx->cpus, ctx->cpu_count, ctx->perf,
                        err, errlen) != 0) {
            log_msg("skip %s: %s", prog->section, err);
            ctx->failed_programs++;
            continue;
        }
        prog->attached = 1;
        ctx->attached_programs++;
        ctx->tracepoint_programs++;
        log_msg("attached %s", prog->section);
    }
    return 0;
}

// Tracefs event names must be unique per attachment: reusing a name while its
// perf event is active fails with EBUSY on 4.19 and silently detaches the
// earlier probe on 5.10, so every library copy gets its own event.
static uint32_t g_uprobe_event_seq;

static int attach_library_probes(struct attach_ctx *ctx, const char *lib_kind,
                                  const char *lib_path, char *err, size_t errlen)
{
    bool *paired = strcmp(lib_kind, "ssl") == 0 ? &ctx->paired_ssl
                                                 : &ctx->paired_crypto;
    const char *probe_symbol =
        strcmp(lib_kind, "ssl") == 0 ? "SSL_write" : "EVP_DigestUpdate";
    // The pairing probe is per library copy: one kernel may accept an entry
    // and a return probe on the same address, another may not.
    bool paired_here = false;
    uint64_t probe_offset = 0;
    if (elf_symbol_offset(lib_path, probe_symbol, &probe_offset, err, errlen) == 0)
        paired_here = tracefs_supports_paired_uprobes(ctx->tracefs, lib_path,
                                                      probe_offset);
    else
        *paired = false;
    if (paired_here)
        *paired = true;
    log_msg("tracefs uprobe pairing (%s, %s): %s", lib_kind, lib_path,
            paired_here ? "entry+return supported"
                        : "one event per address only; return probes disabled");

    int attached = 0;
    for (int i = 0; i < ctx->image->prog_count; i++) {
        struct gt_program *prog = &ctx->image->progs[i];
        if (strncmp(prog->section, "uprobe/", 7) != 0 &&
            strncmp(prog->section, "uretprobe/", 10) != 0)
            continue;
        const struct attach_plan *plan = find_attach_plan(prog->section);
        if (!plan) {
            log_msg("skip %s: unknown uprobe", prog->section);
            continue;
        }
        if (strcmp(plan->lib_name, lib_kind) != 0)
            continue;
        if (plan->is_return && !paired_here) {
            log_msg("skip %s: this tracefs accepts one uprobe event per "
                    "address, so the entry probe keeps %s",
                    prog->section, plan->symbol);
            continue;
        }
        uint64_t offset = 0;
        if (elf_symbol_offset(lib_path, plan->symbol, &offset, err, errlen) != 0) {
            log_msg("skip %s: %s", prog->section, err);
            continue;
        }
        if (*ctx->uprobe_count >= MAX_UPROBES) {
            log_msg("skip %s: too many uprobes", prog->section);
            continue;
        }
        char event_name[64];
        snprintf(event_name, sizeof(event_name), "%s_%u", plan->event,
                 ++g_uprobe_event_seq);
        // Every library copy needs its own program instance: the same probe
        // section is attached to a different file each time.
        struct gt_program instance = *prog;
        instance.fd = -1;
        ctx->total_programs++;
        int fd = bpf_load_program(&instance, BPF_PROG_TYPE_KPROBE, err, errlen);
        if (fd < 0) {
            log_msg("skip %s: %s", prog->section, err);
            ctx->failed_programs++;
            continue;
        }
        if (uprobe_create(ctx->tracefs, g_probe_group, event_name, lib_path,
                          offset, plan->is_return, err, errlen) != 0) {
            log_msg("skip %s: %s", prog->section, err);
            ctx->failed_programs++;
            close(fd);
            continue;
        }
        int tracepoint = -1;
        char spec[64];
        snprintf(spec, sizeof(spec), "%s/%s", g_probe_group, event_name);
        if (uprobe_event_id(ctx->tracefs, g_probe_group, event_name,
                            &tracepoint, err, errlen) != 0) {
            log_msg("skip %s: %s", prog->section, err);
            ctx->failed_programs++;
            uprobe_remove(ctx->tracefs, spec);
            close(fd);
            continue;
        }
        if (perf_attach(fd, tracepoint, ctx->cpus, ctx->cpu_count, ctx->perf,
                        err, errlen) != 0) {
            log_msg("skip %s: %s", prog->section, err);
            ctx->failed_programs++;
            uprobe_remove(ctx->tracefs, spec);
            close(fd);
            continue;
        }
        if (ctx->extra_fd_count <
            (int)(sizeof(ctx->extra_fds) / sizeof(ctx->extra_fds[0])))
            ctx->extra_fds[ctx->extra_fd_count++] = fd;
        struct uprobe_state *state = &ctx->uprobes[*ctx->uprobe_count];
        snprintf(state->spec, sizeof(state->spec), "%s", spec);
        snprintf(state->id_path, sizeof(state->id_path),
                 "%s/events/%s/%s/id", ctx->tracefs, g_probe_group, event_name);
        (*ctx->uprobe_count)++;
        if (plan->event_kind < EV_MAX && !g_location_offset_set[plan->event_kind]) {
            g_location_offsets[plan->event_kind] = offset;
            g_location_offset_set[plan->event_kind] = true;
        }
        ctx->attached_programs++;
        attached++;
        log_msg("%s %s @ %s+0x%llx", plan->is_return ? "uretprobe" : "uprobe",
                plan->symbol, lib_path, (unsigned long long)offset);
    }
    return attached;
}

static bool process_has_uid(int pid, uint32_t uid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *status = fopen(path, "r");
    if (!status)
        return false;
    char line[256];
    bool match = false;
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "Uid:", 4) != 0)
            continue;
        unsigned int real = 0;
        unsigned int effective = 0;
        unsigned int fs_uid = 0;
        unsigned int saved = 0;
        if (sscanf(line + 4, "%u %u %u %u", &real, &effective, &fs_uid, &saved) ==
            4)
            match = (effective == uid || real == uid);
        break;
    }
    fclose(status);
    return match;
}

// An app-bundled copy of the library is the code the target really runs, so
// it wins over the system copy.
// Pick the library copy with the smallest blast radius. A file under /data
// is mapped by this app only, the public /system copy is mapped by whoever
// links it, the Conscrypt copy is shared by every app that talks TLS, and
// the ART copy is mapped by every app on the device.
static int library_priority(const char *path)
{
    if (strncmp(path, "/data/", 6) == 0)
        return 4;
    if (strncmp(path, "/system/", 8) == 0)
        return 3;
    if (strncmp(path, "/apex/com.android.conscrypt/", 28) == 0)
        return 2;
    if (strncmp(path, "/apex/", 6) == 0)
        return 1;
    return 0;
}

static bool find_library_in_pid(int pid, const char *basename, char *out,
                                 size_t out_size)
{
    // The maps file of a real app process has thousands of lines, so the
    // lookup streams the file and keeps the best match instead of keeping a
    // bounded copy of it.
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps)
        return false;
    int best = -1;
    char best_path[512] = {};
    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        const char *name = maps_line_path(line);
        if (!name)
            continue;
        char trimmed[512];
        snprintf(trimmed, sizeof(trimmed), "%s", name);
        trimmed[strcspn(trimmed, "\r\n")] = '\0';
        const char *base = strrchr(trimmed, '/');
        base = base ? base + 1 : trimmed;
        if (strcmp(base, basename) != 0)
            continue;
        int priority = library_priority(trimmed);
        if (priority > best) {
            best = priority;
            snprintf(best_path, sizeof(best_path), "%s", trimmed);
        }
    }
    fclose(maps);
    if (best < 0)
        return false;
    snprintf(out, out_size, "%s", best_path);
    return true;
}

// Libraries that are already probed. The same probe section is loaded again
// for every copy, so each copy is tracked separately.
static char g_attached_libs[MAX_ATTACHED_LIBS][512];
static int g_attached_lib_count;
// One flag per library kind: the standard locations are only used when the
// kind was never probed, otherwise the copy the target actually uses wins.
static bool g_ssl_probed;
static bool g_crypto_probed;

// The copies that are probed when the target has not mapped the library yet.
// The Conscrypt copy is where the Java crypto provider ends up, the public
// system copy is what an app's own native code links against.
static const char *const g_ssl_candidates[] = {
    "/apex/com.android.conscrypt/lib64/libssl.so",
    "/system/lib64/libssl.so",
    NULL,
};
static const char *const g_crypto_candidates[] = {
    "/apex/com.android.conscrypt/lib64/libcrypto.so",
    "/system/lib64/libcrypto.so",
    NULL,
};

// Copies under /data belong to this app only; every other copy is mapped by
// other processes too, so its breakpoints are a system wide footprint.
static int count_shared_copies(void)
{
    int shared = 0;
    for (int i = 0; i < g_attached_lib_count; i++)
        if (strncmp(g_attached_libs[i], "/data/", 6) != 0)
            shared++;
    return shared;
}

static bool library_already_attached(const char *path)
{
    for (int i = 0; i < g_attached_lib_count; i++)
        if (strcmp(g_attached_libs[i], path) == 0)
            return true;
    return false;
}

static void remember_attached_library(const char *path)
{
    if (library_already_attached(path))
        return;
    if (g_attached_lib_count >= MAX_ATTACHED_LIBS)
        return;
    snprintf(g_attached_libs[g_attached_lib_count], sizeof(g_attached_libs[0]), "%s",
             path);
    g_attached_lib_count++;
}

// The list of probed library copies, so the report shows exactly which code
// pages carry a breakpoint.
static void attached_libraries_string(char *out, size_t out_size)
{
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < g_attached_lib_count; i++) {
        size_t len = strlen(g_attached_libs[i]);
        if (used + len + 2 >= out_size)
            break;
        if (used) {
            out[used++] = ',';
            out[used] = '\0';
        }
        memcpy(out + used, g_attached_libs[i], len);
        used += len;
        out[used] = '\0';
    }
}

// The ART copy of the crypto library is mapped by every app on the device, so
// probing it would add a trap to the whole system for no gain. The /system
// copies are worse: a uprobe on /system/lib64/libcrypto.so was measured to
// abort unrelated system processes inside BoringSSL's FIPS integrity
// self-test, so they are only probed when the exact path is passed with
// --libssl/--libcrypto.
static bool library_is_shared_system_copy(const char *path)
{
    return strncmp(path, "/apex/com.android.art/", 22) == 0 ||
           strncmp(path, "/system/lib/", 12) == 0 ||
           strncmp(path, "/system/lib64/", 14) == 0;
}

static void log_system_copy_skip(const char *kind, const char *path)
{
    static bool logged_ssl;
    static bool logged_crypto;
    bool *logged = strcmp(kind, "ssl") == 0 ? &logged_ssl : &logged_crypto;
    if (*logged)
        return;
    *logged = true;
    log_msg("skip %s: shared /system copy (a uprobe on libcrypto trips the "
            "BoringSSL FIPS self-test in system processes); pass --%s PATH "
            "to force",
            path, strcmp(kind, "ssl") == 0 ? "libssl" : "libcrypto");
}

// Collect every copy of the library the process has mapped, best candidate
// first. A target usually maps two usable copies: the Conscrypt one that the
// Java crypto provider uses and the public system one that native code links
// against.
static int find_library_copies_in_pid(int pid, const char *basename,
                                      char out[][512], int max)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps)
        return 0;
    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        const char *name = maps_line_path(line);
        if (!name)
            continue;
        char trimmed[512];
        snprintf(trimmed, sizeof(trimmed), "%s", name);
        trimmed[strcspn(trimmed, "\r\n")] = '\0';
        const char *base = strrchr(trimmed, '/');
        base = base ? base + 1 : trimmed;
        if (strcmp(base, basename) != 0)
            continue;
        bool known = false;
        for (int i = 0; i < count; i++)
            if (strcmp(out[i], trimmed) == 0)
                known = true;
        if (known)
            continue;
        if (count < max) {
            snprintf(out[count], 512, "%s", trimmed);
            count++;
        }
    }
    fclose(maps);
    // Order by footprint: an app private copy first, then the public system
    // copy, then the Conscrypt copy.
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (library_priority(out[j]) > library_priority(out[i])) {
                char swap[512];
                snprintf(swap, sizeof(swap), "%s", out[i]);
                snprintf(out[i], 512, "%s", out[j]);
                snprintf(out[j], 512, "%s", swap);
            }
        }
    }
    return count;
}

// Attach the probes to every usable copy of the library. When the target has
// not mapped the library yet, the standard locations are used so the crypto of
// the first request is not missed.
static int attach_library_kind(struct attach_ctx *ctx, const char *kind,
                                const char *basename,
                                const char *const *candidates, bool use_fallback,
                                int max_copies, char *err, size_t errlen)
{
    int attached = 0;
    if (max_copies < 1)
        max_copies = 1;
    char copies[4][512];
    for (int i = 0; i < g_target_pid_count; i++) {
        int count = find_library_copies_in_pid(g_target_pids[i], basename, copies, 4);
        for (int c = 0; c < count; c++) {
            if (attached >= max_copies)
                break;
            if (library_already_attached(copies[c]))
                continue;
            if (library_is_shared_system_copy(copies[c])) {
                log_system_copy_skip(kind, copies[c]);
                continue;
            }
            if (attach_library_probes(ctx, kind, copies[c], err, errlen) > 0) {
                remember_attached_library(copies[c]);
                attached++;
            }
        }
    }
    if (attached) {
        if (strcmp(kind, "ssl") == 0)
            g_ssl_probed = true;
        else
            g_crypto_probed = true;
        return attached;
    }
    bool *probed = strcmp(kind, "ssl") == 0 ? &g_ssl_probed : &g_crypto_probed;
    if (*probed || !use_fallback)
        return 0;
    for (int i = 0; candidates && candidates[i]; i++) {
        if (attached >= max_copies)
            break;
        if (library_already_attached(candidates[i]))
            continue;
        if (library_is_shared_system_copy(candidates[i])) {
            log_system_copy_skip(kind, candidates[i]);
            continue;
        }
        if (!file_exists(candidates[i]))
            continue;
        if (attach_library_probes(ctx, kind, candidates[i], err, errlen) > 0) {
            remember_attached_library(candidates[i]);
            attached++;
        }
    }
    if (attached) {
        if (strcmp(kind, "ssl") == 0)
            g_ssl_probed = true;
        else
            g_crypto_probed = true;
    }
    return attached;
}

static bool find_target_library(const char *basename, char *out, size_t out_size)
{
    bool found = false;
    int best = -1;
    for (int i = 0; i < g_target_pid_count; i++) {
        char candidate[512] = {};
        if (!find_library_in_pid(g_target_pids[i], basename, candidate,
                                 sizeof(candidate)))
            continue;
        int priority = library_priority(candidate);
        if (priority > best) {
            best = priority;
            snprintf(out, out_size, "%s", candidate);
            found = true;
        }
    }
    if (found)
        return true;
    if (g_target_pid_count > 0)
        return false;
    // The target pid is not known yet: look the uid up. This is the only
    // place that scans /proc, it runs at most every couple of seconds, and
    // it stops as soon as one target pid is known.
    DIR *proc = opendir("/proc");
    if (!proc)
        return false;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;
        int pid = atoi(entry->d_name);
        if (!process_has_uid(pid, g_target_uid))
            continue;
        remember_target_pid((uint32_t)pid);
        char candidate[512] = {};
        if (!find_library_in_pid(pid, basename, candidate, sizeof(candidate)))
            continue;
        int priority = library_priority(candidate);
        if (priority > best) {
            best = priority;
            snprintf(out, out_size, "%s", candidate);
            found = true;
        }
    }
    closedir(proc);
    return found;
}

static int valid_session(const char *session)
{
    size_t len = strlen(session);
    if (len == 0 || len >= 64)
        return 0;
    for (size_t i = 0; i < len; i++) {
        char c = session[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int resolve_app_uid(const char *package, uint32_t *uid, char *err,
                           size_t errlen)
{
    FILE *packages = popen("cmd package list packages -U 2>/dev/null", "r");
    if (packages) {
        char line[1024];
        while (fgets(line, sizeof(line), packages)) {
            char name[256];
            unsigned long value;
            if (sscanf(line, "package:%255s uid:%lu", name, &value) == 2 &&
                strcmp(name, package) == 0 && value <= UINT32_MAX) {
                *uid = (uint32_t)value;
                pclose(packages);
                return 0;
            }
        }
        pclose(packages);
    }

    const char *prefixes[] = {"/data/user/0/", "/data/data/"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s%s", prefixes[i], package);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            *uid = (uint32_t)st.st_uid;
            return 0;
        }
    }
    set_err(err, errlen,
            "cannot resolve uid for %s (install the app or set uid in config)",
            package);
    return -1;
}

struct broker_options {
    char bpf_path[512];
    char tracefs[512];
    char libssl[512];
    char libcrypto[512];
    char out_path[512];
    char package[256];
    char session[64];
    int duration;
    uint32_t target_uid;
    uint32_t payload_limit;
    bool uid_set;
    bool zygote_forks;
    bool stack;
    bool eager_uprobes;
    int prearm;
    int lib_copies;
};

// When the library probes are installed.
//   on-sight : as soon as the target process is observed, before its own
//              code runs (default; nothing is patched while the device idles)
//   eager    : right when the broker starts (widest coverage, widest footprint)
//   lazy     : only after the target maps the library (narrowest coverage)
enum prearm_mode {
    PREARM_ON_SIGHT = 0,
    PREARM_EAGER = 1,
    PREARM_LAZY = 2,
};

static const char *prearm_name(int mode)
{
    switch (mode) {
    case PREARM_EAGER:
        return "eager";
    case PREARM_LAZY:
        return "lazy";
    default:
        return "on-sight";
    }
}

static void options_init(struct broker_options *options)
{
    memset(options, 0, sizeof(*options));
    snprintf(options->out_path, sizeof(options->out_path), "-");
    snprintf(options->package, sizeof(options->package), "com.geektrace.bench");
    options->payload_limit = EVENT_DATA_LEN - 1;
    // Two copies covers the Java (Conscrypt) and the native (system) crypto
    // library without touching the ART copy that every app shares.
    options->lib_copies = 2;
    options->prearm = PREARM_ON_SIGHT;
}

static int option_string(char *dest, size_t dest_size, const char *value,
                         bool allow_empty, char *err, size_t errlen)
{
    size_t len = strlen(value);
    if ((!allow_empty && len == 0) || len >= dest_size) {
        set_err(err, errlen, "invalid or overlong option value");
        return -1;
    }
    memcpy(dest, value, len + 1);
    return 0;
}

static int option_number(const char *value, uint32_t max, uint32_t *out,
                         char *err, size_t errlen)
{
    if (!value[0] || value[0] == '-' || value[0] == '+') {
        set_err(err, errlen, "invalid non-negative integer: %s", value);
        return -1;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long number = strtoull(value, &end, 10);
    if (errno || !end || *end != '\0' || number > max) {
        set_err(err, errlen, "invalid integer: %s", value);
        return -1;
    }
    *out = (uint32_t)number;
    return 0;
}

static int option_bool(const char *value, bool *out, char *err, size_t errlen)
{
    if (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0) {
        *out = true;
    } else if (strcmp(value, "false") == 0 || strcmp(value, "no") == 0 ||
               strcmp(value, "0") == 0) {
        *out = false;
    } else {
        set_err(err, errlen, "expected true/false, got: %s", value);
        return -1;
    }
    return 0;
}

static int set_option(struct broker_options *options, const char *key,
                      const char *value, char *err, size_t errlen)
{
    if (strcmp(key, "package") == 0)
        return option_string(options->package, sizeof(options->package), value,
                             false, err, errlen);
    if (strcmp(key, "out") == 0)
        return option_string(options->out_path, sizeof(options->out_path), value,
                             false, err, errlen);
    if (strcmp(key, "session") == 0)
        return option_string(options->session, sizeof(options->session), value,
                             true, err, errlen);
    if (strcmp(key, "bpffile") == 0)
        return option_string(options->bpf_path, sizeof(options->bpf_path), value,
                             true, err, errlen);
    if (strcmp(key, "tracefs") == 0)
        return option_string(options->tracefs, sizeof(options->tracefs), value,
                             true, err, errlen);
    if (strcmp(key, "libssl") == 0)
        return option_string(options->libssl, sizeof(options->libssl), value,
                             true, err, errlen);
    if (strcmp(key, "libcrypto") == 0)
        return option_string(options->libcrypto, sizeof(options->libcrypto), value,
                             true, err, errlen);
    if (strcmp(key, "uid") == 0) {
        if (!value[0]) {
            options->uid_set = false;
            options->target_uid = 0;
            return 0;
        }
        options->uid_set = true;
        return option_number(value, UINT32_MAX, &options->target_uid, err, errlen);
    }
    if (strcmp(key, "duration") == 0) {
        uint32_t duration;
        if (option_number(value, INT32_MAX, &duration, err, errlen) != 0)
            return -1;
        options->duration = (int)duration;
        return 0;
    }
    if (strcmp(key, "zygote_forks") == 0)
        return option_bool(value, &options->zygote_forks, err, errlen);
    if (strcmp(key, "stack") == 0)
        return option_bool(value, &options->stack, err, errlen);
    if (strcmp(key, "payload_limit") == 0) {
        uint32_t limit;
        if (option_number(value, EVENT_DATA_LEN - 1, &limit, err, errlen) != 0)
            return -1;
        options->payload_limit = limit;
        return 0;
    }
    if (strcmp(key, "eager_uprobes") == 0)
        return option_bool(value, &options->eager_uprobes, err, errlen);
    if (strcmp(key, "prearm") == 0) {
        if (strcmp(value, "on-sight") == 0) {
            options->prearm = PREARM_ON_SIGHT;
            return 0;
        }
        if (strcmp(value, "eager") == 0) {
            options->prearm = PREARM_EAGER;
            return 0;
        }
        if (strcmp(value, "lazy") == 0) {
            options->prearm = PREARM_LAZY;
            return 0;
        }
        set_err(err, errlen, "prearm must be on-sight, eager or lazy");
        return -1;
    }
    if (strcmp(key, "lib_copies") == 0) {
        int copies = atoi(value);
        if (copies < 1 || copies > 4) {
            set_err(err, errlen, "lib_copies must be between 1 and 4");
            return -1;
        }
        options->lib_copies = copies;
        return 0;
    }
    // Unknown keys are a warning, not an error: a configuration file written
    // for a newer broker must still start an older one.
    log_msg("warning: unknown option: %s", key);
    return 0;
}

static char *trim(char *text)
{
    while (isspace((unsigned char)*text))
        text++;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return text;
}

static int load_config(const char *path, struct broker_options *options,
                       char *err, size_t errlen)
{
    FILE *file = fopen(path, "r");
    if (!file) {
        set_err(err, errlen, "open config %s: %s", path, strerror(errno));
        return -1;
    }
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    int line_number = 0;
    int result = 0;
    while ((length = getline(&line, &capacity, file)) >= 0) {
        (void)length;
        line_number++;
        char *text = trim(line);
        if (!text[0] || text[0] == '#' || text[0] == ';')
            continue;
        char *equals = strchr(text, '=');
        if (!equals) {
            set_err(err, errlen, "%s:%d: expected key = value", path, line_number);
            result = -1;
            break;
        }
        *equals = '\0';
        char *key = trim(text);
        char *value = trim(equals + 1);
        if (!key[0] || set_option(options, key, value, err, errlen) != 0) {
            if (key[0]) {
                char detail[512];
                snprintf(detail, sizeof(detail), "%s", err);
                set_err(err, errlen, "%s:%d: %s", path, line_number, detail);
            } else {
                set_err(err, errlen, "%s:%d: empty option name", path,
                        line_number);
            }
            result = -1;
            break;
        }
    }
    free(line);
    fclose(file);
    return result;
}

static int valid_package(const char *package)
{
    size_t len = strlen(package);
    if (len == 0)
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)package[i];
        if (!isalnum(c) && c != '.' && c != '_')
            return 0;
    }
    return 1;
}

static int default_events_path(char *out, size_t out_size, const char *argv0,
                               char *err, size_t errlen)
{
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) {
        if (snprintf(exe, sizeof(exe), "%s", argv0) >= (int)sizeof(exe)) {
            set_err(err, errlen, "executable path is too long");
            return -1;
        }
    } else {
        exe[n] = '\0';
    }
    char *slash = strrchr(exe, '/');
    if (!slash) {
        set_err(err, errlen, "cannot determine output directory");
        return -1;
    }
    *slash = '\0';
    if (snprintf(out, out_size, "%s/events.jsonl", exe) >= (int)out_size) {
        set_err(err, errlen, "output path is too long");
        return -1;
    }
    return 0;
}

static void print_usage(const char *program)
{
    printf("usage: %s -f PACKAGE [--stack]\n"
           "\n"
           "Runs in the foreground like frida-server. Open and operate the app\n"
           "manually, then press Ctrl-C to clean up and exit. events.jsonl is\n"
           "written beside the executable; diagnostics stay on the terminal.\n"
           "\n"
           "Advanced options: [--config PATH] [--package NAME] [--uid N]\n"
           "[--duration SEC] [--out PATH] [--session ID] [--bpffile PATH]\n"
           "[--tracefs PATH] [--libssl PATH] [--libcrypto PATH]\n"
           "[--zygote-forks|--no-zygote-forks] [--stack|--no-stack]\n"
           "[--payload-limit BYTES] [--eager-uprobes]\n"
           "\n"
           "payload-limit caps how many bytes are copied out of the target\n"
           "process (0 = metadata only, no target memory is read). Library\n"
           "probes are attached only once the target actually maps the library,\n"
           "so untouched libraries keep an unmodified code page; use\n"
           "--eager-uprobes to attach them at startup instead. Shared /system\n"
           "copies are skipped by default (a uprobe on system libcrypto aborts\n"
           "system processes in BoringSSL's FIPS self-test); pass\n"
           "--libssl/--libcrypto PATH to probe an exact file anyway.\n",
           program);
}

int main(int argc, char **argv)
{
    struct broker_options options;
    options_init(&options);
    char err[512] = {};
    const char *config_path = NULL;
    bool follow = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc || config_path) {
                fprintf(stderr, "--config requires one path and may appear once\n");
                return 2;
            }
            config_path = argv[++i];
        }
    }
    if (config_path && load_config(config_path, &options, err, sizeof(err)) != 0) {
        fprintf(stderr, "%s\n", err);
        return 2;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--config") == 0) {
            i++;
            continue;
        }
        if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 >= argc || follow) {
                fprintf(stderr, "-f requires one package and may appear once\n");
                return 2;
            }
            follow = true;
            if (set_option(&options, "package", argv[++i], err, sizeof(err)) != 0) {
                fprintf(stderr, "%s\n", err);
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--zygote-forks") == 0) {
            options.zygote_forks = true;
            continue;
        }
        if (strcmp(argv[i], "--no-zygote-forks") == 0) {
            options.zygote_forks = false;
            continue;
        }
        if (strcmp(argv[i], "--stack") == 0) {
            options.stack = true;
            continue;
        }
        if (strcmp(argv[i], "--no-stack") == 0) {
            options.stack = false;
            continue;
        }
        if (strcmp(argv[i], "--payload-limit") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--payload-limit requires a byte count\n");
                return 2;
            }
            if (set_option(&options, "payload_limit", argv[++i], err,
                           sizeof(err)) != 0) {
                fprintf(stderr, "%s\n", err);
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--lib-copies") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--lib-copies requires a count\n");
                return 2;
            }
            if (set_option(&options, "lib_copies", argv[++i], err,
                           sizeof(err)) != 0) {
                fprintf(stderr, "%s\n", err);
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--eager-uprobes") == 0) {
            options.eager_uprobes = true;
            options.prearm = PREARM_EAGER;
            continue;
        }
        if (strcmp(argv[i], "--pre-arm") == 0 && i + 1 < argc) {
            const char *mode = argv[++i];
            if (strcmp(mode, "on-sight") == 0) {
                options.prearm = PREARM_ON_SIGHT;
            } else if (strcmp(mode, "eager") == 0) {
                options.prearm = PREARM_EAGER;
            } else if (strcmp(mode, "lazy") == 0) {
                options.prearm = PREARM_LAZY;
            } else {
                log_msg("invalid --pre-arm %s (on-sight, eager or lazy)", mode);
                return 2;
            }
            continue;
        }
        if (strncmp(argv[i], "--", 2) != 0 || i + 1 >= argc ||
            set_option(&options, argv[i] + 2, argv[i + 1], err, sizeof(err)) != 0) {
            fprintf(stderr, "invalid argument: %s", argv[i]);
            if (err[0])
                fprintf(stderr, ": %s", err);
            fputc('\n', stderr);
            return 2;
        }
        i++;
    }

#ifndef GEETRACE_EMBEDDED_BPF
    if (!options.bpf_path[0]) {
        fprintf(stderr, "this build requires --bpffile (see --help)\n");
        return 2;
    }
#endif
    if (!valid_package(options.package)) {
        fprintf(stderr, "invalid package (allowed: A-Z a-z 0-9 . _)\n");
        return 2;
    }
    if (options.session[0] && !valid_session(options.session)) {
        fprintf(stderr, "invalid session (allowed: A-Z a-z 0-9 . _ -; max 63)\n");
        return 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "geektraced must run as root\n");
        return 1;
    }

    if (follow && strcmp(options.out_path, "-") == 0 &&
        default_events_path(options.out_path, sizeof(options.out_path), argv[0],
                            err, sizeof(err)) != 0) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }

    const char *bpf_path = options.bpf_path[0] ? options.bpf_path : NULL;
    const char *tracefs_opt = options.tracefs[0] ? options.tracefs : NULL;
    const char *libssl = options.libssl[0] ? options.libssl : NULL;
    const char *libcrypto = options.libcrypto[0] ? options.libcrypto : NULL;
    const char *out_path = options.out_path;
    const char *package = options.package;
    const char *session_opt = options.session[0] ? options.session : NULL;
    int duration = options.duration;
    uint32_t target_uid = options.target_uid;
    int uid_set = options.uid_set;

    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);

    if (!uid_set) {
        if (resolve_app_uid(package, &target_uid, err, sizeof(err)) != 0) {
            log_msg("%s", err);
            return 1;
        }
    }
    log_msg("target uid: %u (%s)", target_uid,
            uid_set ? "explicit uid" : package);
    if (target_uid == 0)
        log_msg("warning: target uid is 0; this captures every root process");
    g_target_uid = target_uid;
    g_payload_limit = options.payload_limit;
    log_msg("payload limit: %u bytes per event (0 = metadata only)",
            g_payload_limit);

    char session[64];
    struct timespec now;
    struct timespec mono_now;
    clock_gettime(CLOCK_MONOTONIC, &mono_now);
    clock_gettime(CLOCK_REALTIME, &now);
    g_mono_base_ns = (uint64_t)mono_now.tv_sec * 1000000000ull +
                     (uint64_t)mono_now.tv_nsec;
    g_real_base_ns = (uint64_t)now.tv_sec * 1000000000ull +
                     (uint64_t)now.tv_nsec;
    if (session_opt) {
        snprintf(session, sizeof(session), "%s", session_opt);
    } else {
        struct tm tm;
        gmtime_r(&now.tv_sec, &tm);
        snprintf(session, sizeof(session), "%04d%02d%02d-%02d%02d%02d-poc",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                 tm.tm_min, tm.tm_sec);
    }
    g_session = session;
    g_seq = 0;

    g_out = strcmp(out_path, "-") == 0 ? stdout : fopen(out_path, "w");
    if (!g_out) {
        fprintf(stderr, "cannot open output %s: %s\n", out_path,
                strerror(errno));
        return 1;
    }
    setvbuf(g_out, g_output_buffer, _IOFBF, sizeof(g_output_buffer));

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    if (pipe(g_sigpipe) != 0) {
        fprintf(stderr, "pipe: %s\n", strerror(errno));
        if (g_out != stdout)
            fclose(g_out);
        return 1;
    }
    fcntl(g_sigpipe[0], F_SETFL, O_NONBLOCK);
    fcntl(g_sigpipe[1], F_SETFL, O_NONBLOCK);

    int ret = 1;
    struct bpf_image image;
    memset(&image, 0, sizeof(image));
    int image_loaded = 0;
    int events_fd = -1;
    int use_legacy = 0;
    bool legacy_no_stack = false;
    int config_fd = -1;
    int stats_fd = -1;
    int pending_fd = -1;
    struct perf_fds perf;
    memset(&perf, 0, sizeof(perf));
    struct uprobe_state uprobes[MAX_UPROBES];
    int uprobe_count = 0;
    memset(uprobes, 0, sizeof(uprobes));
    struct ringbuf rb;
    memset(&rb, 0, sizeof(rb));
    rb.map_fd = -1;
    int ring_open = 0;
    struct perf_reader preader;
    memset(&preader, 0, sizeof(preader));
    int perf_open = 0;
    const char *tracefs = NULL;

    tracefs = find_tracefs(tracefs_opt);
    if (!tracefs) {
        log_msg("tracefs not found (tried /sys/kernel/tracing and "
                "/sys/kernel/debug/tracing)");
        goto out;
    }
    log_msg("tracefs: %s", tracefs);
    probe_group_init();
    uprobe_clean_stale(tracefs);

    bool tp_openat = tracepoint_available(tracefs, "syscalls",
                                          "sys_enter_openat");
    bool tp_connect = tracepoint_available(tracefs, "syscalls",
                                           "sys_enter_connect");
    bool raw_openat = !tp_openat;
    bool raw_connect = !tp_connect;
    bool raw_needed = raw_openat || raw_connect;
    log_msg("syscall source: openat=%s connect=%s",
            tp_openat ? "syscalls" : "raw_syscalls",
            tp_connect ? "syscalls" : "raw_syscalls");

    int load_result;
#ifdef GEETRACE_EMBEDDED_BPF
    if (bpf_path) {
        load_result = bpf_image_load(bpf_path, &image, err, sizeof(err));
        if (load_result == 0) {
            events_fd = bpf_create_map(BPF_MAP_TYPE_RINGBUF, 0, 0,
                                       RINGBUF_BYTES, err, sizeof(err));
            if (events_fd < 0) {
                log_msg("%s", err);
                log_msg("external BPF objects require ringbuf (Linux 5.8+); "
                        "omit --bpffile to use the embedded dual image");
            }
        }
    } else {
        events_fd = bpf_create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, RINGBUF_BYTES,
                                   err, sizeof(err));
        if (events_fd >= 0) {
            load_result = bpf_image_load_embedded(&image, err, sizeof(err));
        } else {
            log_msg("ringbuf unavailable on kernel %s (%s); using perf buffer",
                    kernel_release(), err);
            events_fd = bpf_create_map(BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                                       sizeof(uint32_t), sizeof(uint32_t),
                                       MAX_CPUS, err, sizeof(err));
            if (events_fd < 0) {
                log_msg("perf event array: %s", err);
                goto out;
            }
            use_legacy = 1;
            legacy_no_stack = !kernel_at_least(4, 18);
            if (legacy_no_stack)
                log_msg("kernel %s predates bpf_get_stack (Linux 4.18); "
                        "loading probe image without stack capture",
                        kernel_release());
            load_result = legacy_no_stack
                              ? bpf_image_load_embedded_legacy_nostack(
                                    &image, err, sizeof(err))
                              : bpf_image_load_embedded_legacy(
                                    &image, err, sizeof(err));
        }
    }
#else
    load_result = bpf_image_load(bpf_path, &image, err, sizeof(err));
    if (load_result == 0) {
        events_fd = bpf_create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, RINGBUF_BYTES,
                                   err, sizeof(err));
        if (events_fd < 0)
            log_msg("%s", err);
    }
#endif
    if (load_result != 0) {
        log_msg("load %s: %s", bpf_path ? bpf_path : "embedded BPF", err);
        goto out;
    }
    if (events_fd < 0)
        goto out;
    image_loaded = 1;
    log_msg("bpf object: %s (%d programs)",
            bpf_path ? bpf_path
                     : (legacy_no_stack ? "embedded-legacy-nostack"
                                        : (use_legacy ? "embedded-legacy"
                                                      : "embedded")),
            image.prog_count);
    log_msg("event transport: %s (kernel %s)",
            use_legacy ? "perf buffer" : "ringbuf", kernel_release());
    if (use_legacy)
        log_msg("legacy helpers: perf_event_output=25 probe_read=4 "
                "probe_read_str=45%s",
                legacy_no_stack ? " (stack capture disabled)" : "");
    bool path_fallback = false;
    if (use_legacy) {
        path_fallback = tracepoint_available(tracefs, "raw_syscalls",
                                             "sys_exit");
        if (path_fallback)
            log_msg("openat path fallback: sys_exit + /proc/<pid>/fd");
        else
            log_msg("openat path fallback unavailable: "
                    "raw_syscalls/sys_exit missing");
    }
    g_path_fallback = path_fallback;
    // struct gt_config { u32 target_uid; u32 flags; u32 payload_limit; }
    config_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), 12, 1,
                               err, sizeof(err));
    if (config_fd < 0) {
        log_msg("%s", err);
        goto out;
    }
    if (bpf_config_set(config_fd, target_uid, options.zygote_forks,
                       options.stack, raw_openat, raw_connect, path_fallback,
                       options.payload_limit, err, sizeof(err)) != 0) {
        log_msg("%s", err);
        goto out;
    }
    log_msg("config: uid=%u zygote_forks=%d stack=%d payload_limit=%u "
            "path_fallback=%d prearm=%s",
            target_uid, options.zygote_forks, options.stack,
            options.payload_limit, path_fallback, prearm_name(options.prearm));
    stats_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
                              sizeof(uint64_t), 4, err, sizeof(err));
    if (stats_fd < 0) {
        log_msg("%s", err);
        goto out;
    }
    pending_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(uint64_t),
                                sizeof(struct gt_pending), 10240, err,
                                sizeof(err));
    if (pending_fd < 0) {
        log_msg("%s", err);
        goto out;
    }
    if (bpf_image_patch_maps(&image, events_fd, config_fd, stats_fd,
                             pending_fd, err, sizeof(err)) != 0) {
        log_msg("%s", err);
        goto out;
    }

    int cpus[MAX_CPUS];
    int cpu_count = 0;
    if (parse_online_cpus(cpus, MAX_CPUS, &cpu_count, err, sizeof(err)) != 0) {
        log_msg("%s", err);
        goto out;
    }
    log_msg("online CPUs: %d", cpu_count);

    if (use_legacy) {
        if (perf_reader_open(&preader, events_fd, cpus, cpu_count, err,
                             sizeof(err)) != 0) {
            log_msg("perf reader: %s", err);
            emit_tool_gap("perf_reader_failed", err);
            goto out;
        }
        perf_open = 1;
        log_msg("perf output CPUs: %d/%d", preader.cpu_count, cpu_count);
        if (preader.cpu_count < cpu_count) {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "perf output registered on %d of %d CPUs; events from "
                     "unregistered CPUs cannot be captured",
                     preader.cpu_count, cpu_count);
            emit_tool_gap("perf_cpu_partial", msg);
        }
    }

    char attached_libs[2048] = {};

    struct attach_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.image = &image;
    ctx.tracefs = tracefs;
    ctx.cpus = cpus;
    ctx.cpu_count = cpu_count;
    ctx.perf = &perf;
    ctx.uprobes = uprobes;
    ctx.uprobe_count = &uprobe_count;
    ctx.raw_needed = raw_needed;
    ctx.raw_openat = raw_openat;
    ctx.raw_connect = raw_connect;
    ctx.path_fallback = path_fallback;

    // An explicitly configured library is the user's decision, so it is
    // attached right away. Otherwise the probe follows the pre-arm policy:
    // "eager" attaches at start, "on-sight" attaches as soon as the target is
    // observed, "lazy" waits until the target maps the library.
    if (options.eager_uprobes && options.prearm == PREARM_ON_SIGHT)
        options.prearm = PREARM_EAGER;
    bool pending_ssl = false;
    bool pending_crypto = false;
    const char *ssl_path = NULL;
    const char *crypto_path = NULL;
    if (libssl)
        ssl_path = libssl;
    if (libcrypto)
        crypto_path = libcrypto;
    if (!ssl_path)
        pending_ssl = true;
    if (!crypto_path)
        pending_crypto = true;

    attach_tracepoint_programs(&ctx, err, sizeof(err));
    if (ssl_path) {
        if (attach_library_probes(&ctx, "ssl", ssl_path, err, sizeof(err)) > 0)
            remember_attached_library(ssl_path);
        pending_ssl = false;
    } else if (options.prearm == PREARM_EAGER) {
        // TLS is the cheap part: one Conscrypt copy is enough, the system
        // copy is rarely used by apps and only doubles the footprint.
        if (attach_library_kind(&ctx, "ssl", "libssl.so", g_ssl_candidates, true,
                                1, err, sizeof(err)) > 0)
            pending_ssl = false;
    }
    if (crypto_path) {
        if (attach_library_probes(&ctx, "crypto", crypto_path, err, sizeof(err)) > 0)
            remember_attached_library(crypto_path);
        pending_crypto = false;
    } else if (options.prearm == PREARM_EAGER) {
        if (attach_library_kind(&ctx, "crypto", "libcrypto.so", g_crypto_candidates,
                                true, options.lib_copies, err, sizeof(err)) > 0)
            pending_crypto = false;
    }

    if (ctx.attached_programs == 0) {
        log_msg("no probe attached; aborting");
        emit_tool_gap("no_probe_attached",
                      "all probes failed to attach; see broker.log");
        goto out;
    }
    if (ctx.tracepoint_programs == 0)
        emit_tool_gap("no_syscall_probe",
                      "no syscall tracepoint attached; only library probes are "
                      "active");
    bool paired_uprobes = ctx.paired_ssl || ctx.paired_crypto;
    attached_libraries_string(attached_libs, sizeof(attached_libs));
    {
        struct capability_info info = {
            .transport = use_legacy ? "perf-buffer" : "ringbuf",
            .user_read = use_legacy ? "kernel-only" : "binary+str",
            .path_source = use_legacy ? (path_fallback ? "proc_fd" : "none")
                                      : "kernel",
            .uprobe_mode = prearm_name(options.prearm),
            .payload_limit = g_payload_limit,
            .stack_enabled = options.stack,
            .stack_supported = !legacy_no_stack,
            .paired_uprobes = paired_uprobes,
            .probes_attached = ctx.attached_programs,
            .probes_total = ctx.total_programs,
            .probes_failed = ctx.failed_programs,
            .libssl = ssl_path,
            .libcrypto = crypto_path,
            .libraries = attached_libs,
            .library_copies = g_attached_lib_count,
            .lib_copy_limit = options.lib_copies,
            .shared_copies = count_shared_copies(),
        };
        emit_tool_capability(&info);
    }
    if (use_legacy && !path_fallback)
        emit_tool_gap("path_fallback_unavailable",
                      "raw_syscalls/sys_exit is missing on this kernel; "
                      "file.open events carry dfd/flags but no path");

    if (!use_legacy) {
        if (ringbuf_open(&rb, events_fd, RINGBUF_BYTES, err, sizeof(err)) != 0) {
            log_msg("ringbuf: %s", err);
            goto out;
        }
        ring_open = 1;
    }

    if (duration > 0)
        log_msg("session %s; capturing %s for %ds", g_session, package, duration);
    else
        log_msg("session %s; waiting for %s (stop with SIGTERM)", g_session,
                package);
    if (legacy_no_stack && options.stack) {
        char msg[200];
        snprintf(msg, sizeof(msg),
                 "kernel %s predates bpf_get_stack (Linux 4.18); stack capture "
                 "is unavailable, events carry no stack",
                 kernel_release());
        log_msg("%s", msg);
        emit_tool_gap("stack_unsupported", msg);
    }
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    struct timespec last_scan;
    memset(&last_scan, 0, sizeof(last_scan));
    int scan_interval = 1;
    bool missing_library_reported = false;
    char active_ssl[512] = {};
    char active_crypto[512] = {};
    uint64_t total = 0;
    while (!g_stop) {
        uint64_t drained = use_legacy ? perf_reader_drain(&preader)
                                     : ringbuf_drain(&rb);
        total += drained;
        bool events_pending = !use_legacy && ringbuf_pending(&rb);
        if (drained && !events_pending)
            fflush(g_out);
        if (events_pending)
            continue;
        // "on-sight": the library probes go in at the earliest moment the
        // target exists. A zygote child that just received the target uid is
        // the earliest signal there is; the target's own first event is the
        // fallback. An app normally has not loaded its native code yet, so the
        // crypto of the very first request is still caught while the device
        // was left untouched before the target appeared.
        if (options.prearm == PREARM_ON_SIGHT && !g_target_seen) {
            uint32_t born = find_birth_target();
            if (born) {
                log_msg("target process born (pid %u); arming library probes",
                        born);
                g_target_seen = 1;
            }
        }
        if (options.prearm == PREARM_ON_SIGHT && g_target_seen) {
            if (pending_ssl &&
                attach_library_kind(&ctx, "ssl", "libssl.so", g_ssl_candidates,
                                    true, 1, err, sizeof(err)) > 0)
                pending_ssl = false;
            if (pending_crypto &&
                attach_library_kind(&ctx, "crypto", "libcrypto.so",
                                    g_crypto_candidates, true,
                                    options.lib_copies, err, sizeof(err)) > 0)
                pending_crypto = false;
        }
        // Lazy library attachment: a library probe is installed only once the
        // target is known to map that library, so a library the target never
        // uses keeps an unmodified code page for every other process.
        if (pending_ssl || pending_crypto) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed = (long)(now.tv_sec - start.tv_sec);
            if (now.tv_sec - last_scan.tv_sec >= scan_interval) {
                last_scan = now;
                if (pending_ssl &&
                    attach_library_kind(&ctx, "ssl", "libssl.so", g_ssl_candidates,
                                        options.prearm != PREARM_LAZY,
                                        1, err, sizeof(err)) > 0)
                    pending_ssl = false;
                if (pending_crypto &&
                    attach_library_kind(&ctx, "crypto", "libcrypto.so",
                                        g_crypto_candidates,
                                        options.prearm != PREARM_LAZY,
                                        options.lib_copies, err, sizeof(err)) > 0)
                    pending_crypto = false;
                if ((pending_ssl || pending_crypto) && elapsed > 30 &&
                    !missing_library_reported) {
                    missing_library_reported = true;
                    emit_tool_gap("library_not_attached",
                                  "no attachable libssl.so/libcrypto.so copy is "
                                  "mapped yet (shared /system copies are skipped "
                                  "unless --libssl/--libcrypto is given); library "
                                  "probes stay detached and TLS/crypto events are "
                                  "absent");
                }
                if (elapsed > 60)
                    scan_interval = 5;
            }
        }
        if (duration > 0) {
            struct timespec cur;
            clock_gettime(CLOCK_MONOTONIC, &cur);
            if (cur.tv_sec - start.tv_sec >= duration)
                break;
        }
        if (use_legacy) {
            struct pollfd pfds[MAX_CPUS + 1];
            int nfds = 0;
            pfds[nfds].fd = g_sigpipe[0];
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
            for (int i = 0; i < preader.cpu_count; i++) {
                pfds[nfds].fd = preader.cpu[i].fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                nfds++;
            }
            int pr = poll(pfds, (nfds_t)nfds, 50);
            if (pr < 0 && errno != EINTR)
                break;
            if (pfds[0].revents & POLLIN) {
                char drain[32];
                while (read(g_sigpipe[0], drain, sizeof(drain)) > 0)
                    ;
            }
        } else {
            struct pollfd pfds[2] = {
                {.fd = rb.map_fd, .events = POLLIN},
                {.fd = g_sigpipe[0], .events = POLLIN},
            };
            int pr = poll(pfds, 2, 50);
            if (pr < 0 && errno != EINTR)
                break;
            if (pfds[1].revents & POLLIN) {
                char drain[32];
                while (read(g_sigpipe[0], drain, sizeof(drain)) > 0)
                    ;
            }
        }
    }
    total += use_legacy ? perf_reader_drain(&preader) : ringbuf_drain(&rb);
    uint64_t lost_events = 0;
    char stats_err[256] = {};
    if (bpf_stats_read(stats_fd, 0, &lost_events, stats_err,
                       sizeof(stats_err)) != 0) {
        log_msg("drop stats unavailable: %s", stats_err);
        emit_tool_gap("stats_read_failed", stats_err);
    } else if (lost_events > 0 && !use_legacy) {
        log_msg("ringbuf reported %llu failed event writes",
                (unsigned long long)lost_events);
        emit_tool_drop(lost_events, "ringbuf_full");
    } else if (lost_events > 0) {
        log_msg("perf output reported %llu failed event writes",
                (unsigned long long)lost_events);
    }
    {
        uint64_t stack_fails = 0, read_fails = 0, map_fails = 0;
        bpf_stats_read(stats_fd, 1, &stack_fails, NULL, 0);
        bpf_stats_read(stats_fd, 2, &read_fails, NULL, 0);
        bpf_stats_read(stats_fd, 3, &map_fails, NULL, 0);
        if (stack_fails || read_fails || map_fails)
            log_msg("probe counters: stack_fail=%llu read_fail=%llu map_fail=%llu",
                    (unsigned long long)stack_fails,
                    (unsigned long long)read_fails,
                    (unsigned long long)map_fails);
    }
    if (use_legacy) {
        // PERF_RECORD_LOST is the authoritative queue-loss count; helper
        // failures beyond it indicate events that never reached a ring
        // (for example a missing CPU registration).
        if (preader.lost > 0) {
            log_msg("perf ring lost %llu samples",
                    (unsigned long long)preader.lost);
            emit_tool_drop(preader.lost, "perf_ring_lost");
        }
        if (lost_events > preader.lost) {
            uint64_t other = lost_events - preader.lost;
            log_msg("perf output failed %llu times without a ring-loss record",
                    (unsigned long long)other);
            emit_tool_drop(other, "perf_output_failed");
        }
    }
    if (options.stack) {
        uint64_t stack_failures = 0;
        if (bpf_stats_read(stats_fd, 1, &stack_failures, stats_err,
                           sizeof(stats_err)) == 0 && stack_failures > 0) {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "user stack capture failed for %llu focus events",
                     (unsigned long long)stack_failures);
            emit_tool_gap("stack_capture_failed", msg);
        }
    }
    uint64_t read_failures = 0;
    if (bpf_stats_read(stats_fd, 2, &read_failures, stats_err,
                       sizeof(stats_err)) == 0 && read_failures > 0) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "user memory reads failed for %llu paths or payloads; affected events contain no fabricated bytes",
                 (unsigned long long)read_failures);
        emit_tool_gap("user_read_failed", msg);
    }
    uint64_t pending_failures = 0;
    if (bpf_stats_read(stats_fd, 3, &pending_failures, stats_err,
                       sizeof(stats_err)) == 0 && pending_failures > 0) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "entry/return state could not be saved for %llu calls; return payloads may be missing",
                 (unsigned long long)pending_failures);
        emit_tool_gap("pending_state_failed", msg);
    }
    {
        attached_libraries_string(attached_libs, sizeof(attached_libs));
        struct capability_info info = {
            .transport = use_legacy ? "perf-buffer" : "ringbuf",
            .user_read = use_legacy ? "kernel-only" : "binary+str",
            .path_source = use_legacy ? (path_fallback ? "proc_fd" : "none")
                                      : "kernel",
            .uprobe_mode = prearm_name(options.prearm),
            .payload_limit = g_payload_limit,
            .stack_enabled = options.stack,
            .stack_supported = !legacy_no_stack,
            .paired_uprobes = ctx.paired_ssl || ctx.paired_crypto,
            .probes_attached = ctx.attached_programs,
            .probes_total = ctx.total_programs,
            .probes_failed = ctx.failed_programs,
            .libssl = active_ssl[0] ? active_ssl : ssl_path,
            .libcrypto = active_crypto[0] ? active_crypto : crypto_path,
            .libraries = attached_libs,
            .library_copies = g_attached_lib_count,
            .lib_copy_limit = options.lib_copies,
            .shared_copies = count_shared_copies(),
        };
        emit_tool_capability(&info);
    }
    if (ctx.failed_programs > 0) {
        char msg[200];
        snprintf(msg, sizeof(msg),
                 "attached %d probes, %d failed to attach; see broker.log",
                 ctx.attached_programs, ctx.failed_programs);
        log_msg("%s", msg);
        emit_tool_gap("probe_attach_partial", msg);
    } else if (!options.eager_uprobes && (pending_ssl || pending_crypto)) {
        // Library probes still waiting for the target to map the library:
        // expected in on-sight mode, not a failed attachment.
        log_msg("attached %d probes; library probes still pending",
                ctx.attached_programs);
    }
    if (fflush(g_out) != 0) {
        log_msg("flush events: %s", strerror(errno));
        goto out;
    }
    log_msg("events written: %llu", (unsigned long long)total);
    ret = 0;

out:
    // Stop sources before removing the dynamic uprobe definitions.
    for (int i = 0; i < perf.count; i++)
        close(perf.fds[i]);
    for (int i = 0; i < uprobe_count; i++)
        uprobe_remove(tracefs, uprobes[i].spec);
    for (int i = 0; i < image.prog_count; i++)
        if (image.progs[i].fd >= 0)
            close(image.progs[i].fd);
    for (int i = 0; i < ctx.extra_fd_count; i++)
        close(ctx.extra_fds[i]);
    if (ring_open)
        ringbuf_close(&rb);
    if (perf_open)
        perf_reader_close(&preader);
    if (!ring_open && events_fd >= 0)
        close(events_fd);
    if (config_fd >= 0)
        close(config_fd);
    if (stats_fd >= 0)
        close(stats_fd);
    if (pending_fd >= 0)
        close(pending_fd);
    if (image_loaded)
        bpf_image_free(&image);
    free_map_cache();
    if (g_out && g_out != stdout)
        fclose(g_out);
    if (g_sigpipe[0] >= 0)
        close(g_sigpipe[0]);
    if (g_sigpipe[1] >= 0)
        close(g_sigpipe[1]);
    return ret;
}
