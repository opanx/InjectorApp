/*
 * Panxcz Injector - Ptrace .so injector for Android ARM64
 * Based on GameGuardian-style injection approach.
 *
 * Usage: injector <pid> <path_to_so>
 * Requires root.
 *
 * Flow:
 *   1. ptrace attach to target game process
 *   2. mmap memory in target for shellcode + dlopen path
 *   3. Write ARM64 shellcode that calls dlopen(path, RTLD_NOW)
 *   4. Execute shellcode → .so loaded → constructor fires → ImGui overlay
 *   5. Detach
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>

struct pt_regs2 {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static int pt_getregs(pid_t pid, struct pt_regs2 *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int pt_setregs(pid_t pid, struct pt_regs2 *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

/* ARM64 instruction builders */
static uint32_t movz_x0(uint16_t v) { return 0xD2800000 | ((uint32_t)v << 5); }
static uint32_t movk_x0_16(uint16_t v) { return 0xF2A00000 | ((uint32_t)v << 5); }
static uint32_t movk_x0_32(uint16_t v) { return 0xF2C00000 | ((uint32_t)v << 5); }
static uint32_t movz_x1(uint16_t v) { return 0xD2800001 | ((uint32_t)v << 5); }
static uint32_t movz_x8(uint16_t v) { return 0xD2800008 | ((uint32_t)v << 5); }
static uint32_t movk_x8_16(uint16_t v) { return 0xF2A00008 | ((uint32_t)v << 5); }
static uint32_t movk_x8_32(uint16_t v) { return 0xF2C00008 | ((uint32_t)v << 5); }

static int do_inject(pid_t pid, const char *path) {
    struct pt_regs2 regs, backup;
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_ATTACH");
        return -1;
    }
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] Target not stopped\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    printf("[+] Attached to PID %d\n", pid);

    if (pt_getregs(pid, &regs) < 0) {
        perror("[-] PTRACE_GETREGSET");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    backup = regs;

    /* Write BKPT at current PC */
    unsigned long orig_pc = regs.pc;
    long orig_text = ptrace(PTRACE_PEEKDATA, pid, orig_pc, NULL);
    ptrace(PTRACE_POKEDATA, pid, orig_pc, (orig_text & ~0xFFFFFFFF) | 0xD4200000);

    /* mmap(NULL, 0x2000, PROT_RWX, MAP_PRIVATE|ANON, -1, 0) */
    regs.pc = orig_pc;
    regs.regs[8] = 222;   /* __NR_mmap */
    regs.regs[0] = 0;
    regs.regs[1] = 0x2000;
    regs.regs[2] = 7;
    regs.regs[3] = 0x22;
    regs.regs[4] = (uint64_t)-1;
    regs.regs[5] = 0;
    pt_setregs(pid, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) { fprintf(stderr, "[-] mmap failed\n"); goto fail; }

    pt_getregs(pid, &regs);
    unsigned long mmap_ret = regs.regs[0];
    ptrace(PTRACE_POKEDATA, pid, orig_pc, orig_text);
    regs.pc = orig_pc;
    pt_setregs(pid, &regs);

    if (mmap_ret < 0x1000 || mmap_ret > 0x7FFFFFFFF000ULL) {
        fprintf(stderr, "[-] mmap invalid: 0x%lx\n", mmap_ret);
        goto fail;
    }
    printf("[+] mmap: 0x%lx\n", mmap_ret);

    /* Write path string */
    size_t path_len = strlen(path) + 1;
    for (size_t i = 0; i < path_len; i += 8) {
        char buf[8] = {0};
        memcpy(buf, path + i, (path_len - i) > 8 ? 8 : (path_len - i));
        long word; memcpy(&word, buf, 8);
        ptrace(PTRACE_POKEDATA, pid, mmap_ret + i, word);
    }

    /* Find libc base */
    char maps_file[64];
    snprintf(maps_file, sizeof(maps_file), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_file, "r");
    if (!f) goto fail;
    unsigned long libc_base = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            sscanf(line, "%lx-", &libc_base);
            break;
        }
    }
    fclose(f);
    if (!libc_base) { fprintf(stderr, "[-] libc not found\n"); goto fail; }

    /* Resolve dlopen */
    void *local_sym = dlsym(RTLD_DEFAULT, "dlopen");
    Dl_info info;
    if (!local_sym || !dladdr(local_sym, &info)) goto fail;
    unsigned long dlopen_addr = libc_base + ((unsigned long)local_sym - (unsigned long)info.dli_fbase);
    printf("[+] dlopen: 0x%lx\n", dlopen_addr);

    /* Write shellcode */
    unsigned long sc_addr = mmap_ret + 0x1000;
    uint32_t sc[] = {
        movz_x0((uint16_t)(mmap_ret & 0xFFFF)),
        movk_x0_16((uint16_t)((mmap_ret >> 16) & 0xFFFF)),
        movk_x0_32((uint16_t)((mmap_ret >> 32) & 0xFFFF)),
        movz_x1(2),  /* RTLD_NOW */
        movz_x8((uint16_t)(dlopen_addr & 0xFFFF)),
        movk_x8_16((uint16_t)((dlopen_addr >> 16) & 0xFFFF)),
        movk_x8_32((uint16_t)((dlopen_addr >> 32) & 0xFFFF)),
        0xD63F0100,  /* blr x8 */
        0xD4200000,  /* brk #0 */
    };
    for (int i = 0; i < 9; i++)
        ptrace(PTRACE_POKEDATA, pid, sc_addr + i * 4, sc[i]);

    /* Execute */
    regs.pc = sc_addr;
    regs.regs[0] = mmap_ret;
    regs.regs[1] = 2;
    regs.regs[8] = dlopen_addr;
    pt_setregs(pid, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        pt_getregs(pid, &regs);
        unsigned long ret = regs.regs[0];
        printf("[+] dlopen: 0x%lx %s\n", ret, ret ? "OK" : "FAIL");
    } else {
        fprintf(stderr, "[-] Signal: %d\n", WSTOPSIG(status));
    }

    pt_setregs(pid, &backup);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;

fail:
    pt_setregs(pid, &backup);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
}

static void list_processes(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return;
    printf("\n  PID      PACKAGE\n  -------- --------------------------------\n");
    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = atoi(ent->d_name);
        if (pid <= 0) continue;
        char cmd_path[64];
        snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", pid);
        FILE *f = fopen(cmd_path, "r");
        if (!f) continue;
        char cmdline[256] = {0};
        fgets(cmdline, sizeof(cmdline), f);
        fclose(f);
        if (!cmdline[0]) continue;
        char pkg[128] = "";
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *mf = fopen(maps_path, "r");
        if (mf) {
            char mline[512];
            while (fgets(mline, sizeof(mline), mf)) {
                char *p = strstr(mline, "/data/app/");
                if (p) {
                    p += 10;
                    char *dash = strrchr(p, '-');
                    if (dash) {
                        size_t len = dash - p;
                        if (len > 0 && len < sizeof(pkg)) { strncpy(pkg, p, len); pkg[len] = 0; }
                    }
                    break;
                }
            }
            fclose(mf);
        }
        if (pkg[0])
            printf("  %-8d %s\n", pid, pkg);
    }
    closedir(proc);
}

int main(int argc, char *argv[]) {
    printf("\n  Panxcz Injector v1.1\n  By Panxcz & Freebuff\n\n");

    if (argc == 1) {
        list_processes();
        printf("\n  Usage: %s <pid> <path/to/library.so>\n\n", argv[0]);
        return 0;
    }
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <path_to_so>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char *so_path = argv[2];
    if (pid <= 0) { fprintf(stderr, "[-] Invalid PID\n"); return 1; }
    if (access(so_path, R_OK) < 0) { fprintf(stderr, "[-] Cannot access %s\n", so_path); return 1; }

    printf("[*] PID: %d  SO: %s\n", pid, so_path);
    return do_inject(pid, so_path) == 0 ? 0 : 1;
}
