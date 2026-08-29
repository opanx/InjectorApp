/*
 * Panxcz Injector v1.0 - Ptrace .so injector for Android ARM64
 * Uses PTRACE_GETREGSET/SETREGSET (Android doesn't have GETREGS/SETREGS)
 *
 * Usage: injector <pid> <path_to_so>
 * Requires root.
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
static uint32_t movz_x0(uint16_t imm16) {
    return 0xD2800000 | ((uint32_t)imm16 << 5);
}
static uint32_t movk_x0_16(uint16_t imm16) {
    return 0xF2A00000 | ((uint32_t)imm16 << 5);
}
static uint32_t movk_x0_32(uint16_t imm16) {
    return 0xF2C00000 | ((uint32_t)imm16 << 5);
}
static uint32_t movz_x8(uint16_t imm16) {
    return 0xD2800008 | ((uint32_t)imm16 << 5);
}
static uint32_t movk_x8_16(uint16_t imm16) {
    return 0xF2A00008 | ((uint32_t)imm16 << 5);
}
static uint32_t movk_x8_32(uint16_t imm16) {
    return 0xF2C00008 | ((uint32_t)imm16 << 5);
}

static int inject_so(pid_t pid, const char *path) {
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

    /* Write BRK at current PC */
    unsigned long orig_pc = regs.pc;
    long orig_text = ptrace(PTRACE_PEEKDATA, pid, orig_pc, NULL);
    long brk_text = (orig_text & ~0xFFFFFFFF) | 0xD4200000;
    ptrace(PTRACE_POKEDATA, pid, orig_pc, brk_text);

    /* mmap in target: mmap(NULL, 0x2000, 7, 0x22, -1, 0) */
    regs.pc = orig_pc;
    regs.regs[8] = 222;    /* __NR_mmap */
    regs.regs[0] = 0;
    regs.regs[1] = 0x2000;
    regs.regs[2] = 7;      /* PROT_READ|WRITE|EXEC */
    regs.regs[3] = 0x22;   /* MAP_PRIVATE|ANONYMOUS */
    regs.regs[4] = (uint64_t)-1;
    regs.regs[5] = 0;
    pt_setregs(pid, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] mmap failed (signal %d)\n", WSTOPSIG(status));
        goto fail;
    }

    pt_getregs(pid, &regs);
    unsigned long mmap_ret = regs.regs[0];
    printf("[+] mmap in target: 0x%lx\n", mmap_ret);

    /* Restore PC */
    ptrace(PTRACE_POKEDATA, pid, orig_pc, orig_text);
    regs.pc = orig_pc;
    pt_setregs(pid, &regs);

    if (mmap_ret < 0x1000 || mmap_ret > 0x7FFFFFFFF000ULL) {
        fprintf(stderr, "[-] mmap invalid: 0x%lx\n", mmap_ret);
        goto fail;
    }

    /* Write path string */
    size_t path_len = strlen(path) + 1;
    for (size_t i = 0; i < path_len; i += 8) {
        char buf[8] = {0};
        memcpy(buf, path + i, (path_len - i) > 8 ? 8 : (path_len - i));
        long word;
        memcpy(&word, buf, 8);
        ptrace(PTRACE_POKEDATA, pid, mmap_ret + i, word);
    }
    printf("[+] Path written at 0x%lx\n", mmap_ret);

    /* Find libc base in target */
    char maps_file[64];
    snprintf(maps_file, sizeof(maps_file), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_file, "r");
    if (!f) { perror("[-] fopen maps"); goto fail; }

    unsigned long libc_base = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            sscanf(line, "%lx-", &libc_base);
            break;
        }
    }
    fclose(f);

    if (!libc_base) {
        fprintf(stderr, "[-] Cannot find libc in target\n");
        goto fail;
    }
    printf("[+] Target libc base: 0x%lx\n", libc_base);

    /* Calculate dlopen offset */
    void *local_sym = dlsym(RTLD_DEFAULT, "dlopen");
    Dl_info info;
    if (!local_sym || !dladdr(local_sym, &info)) {
        fprintf(stderr, "[-] Cannot resolve local dlopen\n");
        goto fail;
    }
    unsigned long dlopen_offset = (unsigned long)local_sym - (unsigned long)info.dli_fbase;
    unsigned long dlopen_addr = libc_base + dlopen_offset;
    printf("[+] dlopen in target: 0x%lx\n", dlopen_addr);

    /* Write shellcode */
    unsigned long sc_addr = mmap_ret + 0x1000;
    uint32_t sc[12];
    int n = 0;
    sc[n++] = movz_x0((uint16_t)(mmap_ret & 0xFFFF));
    sc[n++] = movk_x0_16((uint16_t)((mmap_ret >> 16) & 0xFFFF));
    sc[n++] = movk_x0_32((uint16_t)((mmap_ret >> 32) & 0xFFFF));
    sc[n++] = 0xD2800041;  /* movz x1, #2 */
    sc[n++] = movz_x8((uint16_t)(dlopen_addr & 0xFFFF));
    sc[n++] = movk_x8_16((uint16_t)((dlopen_addr >> 16) & 0xFFFF));
    sc[n++] = movk_x8_32((uint16_t)((dlopen_addr >> 32) & 0xFFFF));
    sc[n++] = 0xD63F0100;  /* blr x8 */
    sc[n++] = 0xD4200000;  /* brk #0 */

    for (int i = 0; i < n; i++) {
        ptrace(PTRACE_POKEDATA, pid, sc_addr + i * 4, sc[i]);
    }
    printf("[+] Shellcode written at 0x%lx\n", sc_addr);

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
        printf("[+] dlopen returned: 0x%lx\n", ret);
        if (ret != 0) {
            printf("[+] SUCCESS! Library loaded in PID %d\n", pid);
        } else {
            fprintf(stderr, "[-] dlopen returned NULL\n");
        }
    } else {
        fprintf(stderr, "[-] Unexpected signal: %d\n", WSTOPSIG(status));
    }

    pt_setregs(pid, &backup);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[+] Detached from PID %d\n", pid);
    return 0;

fail:
    pt_setregs(pid, &backup);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
}

static void list_processes(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return;

    printf("\n=== Panxcz Injector - Process List ===\n\n");
    printf("%-8s  %-35s  %s\n", "PID", "PACKAGE", "CMDLINE");
    printf("---------------------------------------------------------------\n");

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
                        if (len > 0 && len < sizeof(pkg)) {
                            strncpy(pkg, p, len);
                            pkg[len] = 0;
                        }
                    }
                    break;
                }
            }
            fclose(mf);
        }

        if (pkg[0] || strstr(cmdline, "com.")) {
            printf("%-8d  %-35s  %s\n", pid, pkg[0] ? pkg : "(native)", cmdline);
        }
    }
    closedir(proc);
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("\n  ====================================\n");
    printf("    Panxcz Injector v1.0\n");
    printf("    By Panxcz & Freebuff\n");
    printf("  ====================================\n\n");

    if (argc == 1) {
        list_processes();
        printf("Usage: %s <pid> <path/to/library.so>\n", argv[0]);
        printf("Example: %s 12345 /data/local/tmp/libTool.so\n", argv[0]);
        return 0;
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <path_to_so>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char *so_path = argv[2];

    if (pid <= 0) {
        fprintf(stderr, "[-] Invalid PID: %s\n", argv[1]);
        return 1;
    }
    if (access(so_path, R_OK) < 0) {
        fprintf(stderr, "[-] Cannot access %s: %s\n", so_path, strerror(errno));
        return 1;
    }

    printf("[*] Target PID: %d\n", pid);
    printf("[*] Library:    %s\n", so_path);
    printf("[*] Starting injection...\n\n");

    return inject_so(pid, so_path) == 0 ? 0 : 1;
}
