#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <limits.h>

struct CHRONOS_FUNC_DATA {
    uint64_t* regs;
    uint64_t* params;
    uint8_t params_cnt;
};

char CHRONOS_MAGIC[] = "CHRONOSDUMP";

void dump_process(struct CHRONOS_FUNC_DATA* func_data) {
    uint64_t sym_addr = (uint64_t) dlsym(RTLD_NEXT, "%CHRONOS_TARGET_NAME%");
    if(!sym_addr) fprintf(stderr, "Function with name '%s' was not found by dynamic loader... You will need to define start address of Qiling instance manually when running.", "%CHRONOS_TARGET_NAME%");

    FILE* dump_file = fopen("%CHRONOS_DUMP_FILE%", "wb");

    // CHRONOS MAGIC
    fwrite(CHRONOS_MAGIC, strlen(CHRONOS_MAGIC), 1, dump_file);

    // ADDRESS OF TARGET FUNCTION
    fwrite(&sym_addr, sizeof(sym_addr), 1, dump_file);

    // REGISTERS
    for(uint8_t reg_i = 0; reg_i < 21; reg_i++) fwrite(&func_data->regs[reg_i], sizeof(func_data->regs[reg_i]), 1, dump_file);

    // PARAMS
    fwrite(&func_data->params_cnt, sizeof(func_data->params_cnt), 1, dump_file);
    for(uint8_t param_i = 0; param_i < func_data->params_cnt; param_i++) fwrite(&func_data->params[param_i], sizeof(func_data->params[param_i]), 1, dump_file);

    // BRK POSITION
    unsigned long long int curr_brk = (unsigned long long int) sbrk(0);
    fwrite(&curr_brk, sizeof(curr_brk), 1, dump_file);

    // FILE DESCRIPTORS
    const char* fds_dir_path = "/proc/self/fd/";
    const char* fdinfo_dir_path = "/proc/self/fdinfo/";
    DIR* fds_dir = opendir(fds_dir_path);
    struct dirent *entry;
    char fd_path[PATH_MAX];
    char fdinfo_path[PATH_MAX];
    char file_name[PATH_MAX];
    char zero_c = 0;
    while ((entry = readdir(fds_dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        uint32_t fd_num = atoi(entry->d_name);
        snprintf(fd_path, sizeof(fd_path), "%s%s", fds_dir_path, entry->d_name);
        snprintf(fdinfo_path, sizeof(fdinfo_path), "%s%s", fdinfo_dir_path, entry->d_name);
        ssize_t file_name_len = readlink(fd_path, file_name, sizeof(file_name) - 1);
        if (strstr(file_name, "/dev/pts/") || strstr(file_name, "/proc/") || !strncmp(file_name, "%CHRONOS_DUMP_FILE%", file_name_len)) continue;
        FILE *fdinfo_file = fopen(fdinfo_path, "r");
        if (fdinfo_file == NULL) continue;
        char fdinfo_line[256];
        uint64_t file_pos = 0;
        unsigned int flags = 0;
        unsigned char pos_found = 0, flags_found = 0;
        while (fgets(fdinfo_line, sizeof(fdinfo_line), fdinfo_file)) {
            if (sscanf(fdinfo_line, "pos: %ld", &file_pos) == 1) {
                pos_found = 1;
            }
            if (sscanf(fdinfo_line, "flags: %o", &flags) == 1) {
                flags_found = 1;
            }
        }
        fclose(fdinfo_file);
        if(!pos_found || !flags_found) continue;
        fwrite(file_name, file_name_len, 1, dump_file);
        fwrite(&zero_c, 1, 1, dump_file);
        fwrite(&fd_num, sizeof(fd_num), 1, dump_file);
        fwrite(&flags, sizeof(flags), 1, dump_file);
        fwrite(&file_pos, sizeof(file_pos), 1, dump_file);
    }
    fwrite(&zero_c, 1, 1, dump_file);
    closedir(fds_dir);
    
    // DUMP MEMORY MAPPINGS
    FILE* maps_file = fopen("/proc/self/maps", "r");
    char line[256];
    unsigned long start_addr, end_addr, curr_addr;
    char perms[5];
    char mapping_name[256];
    while (fgets(line, sizeof(line), maps_file) != NULL) {
        if (strstr(line, "[vvar]") || strstr(line, "[vsyscall]")) continue;
        unsigned int sscanf_res = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start_addr, &end_addr, perms, mapping_name);
        if (sscanf_res == 3) strcpy(mapping_name, "[anon]");
        if (sscanf_res >= 3) {
            if (perms[0] != 'r') continue;
            fwrite(mapping_name, 256, 1, dump_file);
            fwrite(&start_addr, sizeof(start_addr), 1, dump_file);
            fwrite(&end_addr, sizeof(end_addr), 1, dump_file);
            curr_addr = start_addr;
            unsigned short buf_sz = 1024;
            while(curr_addr < end_addr) {
                if(end_addr - curr_addr < buf_sz) buf_sz = end_addr - curr_addr;
                char* buf = (char*) curr_addr;
                fwrite(buf, buf_sz, 1, dump_file);
                curr_addr += buf_sz;
            }
        }
    }
    fclose(maps_file);

    fclose(dump_file);
}

void %CHRONOS_TARGET_NAME%(%CHRONOS_TARGET_SIGNATURE_PARAMS%) {
    uint64_t regs[21];
    __asm__ volatile (
        "mov %%rax, %0\n\t"
        "mov %%rbx, %1\n\t"
        "mov %%rcx, %2\n\t"
        "mov %%rdx, %3\n\t"
        "mov %%rdi, %4\n\t"
        "mov %%rsi, %5\n\t"
        "movq (%%rbp), %6\n\t" // RBP (points on itself)
        "mov %%rbp, %7\n\t" // RSP (with offset 8)
        "mov %%r8, %8\n\t"
        "mov %%r9, %9\n\t"
        "mov %%r10, %10\n\t"
        "mov %%r11, %11\n\t"
        : "=r" (regs[0]), "=r" (regs[1]), "=r" (regs[2]), "=r" (regs[3]),
          "=r" (regs[4]), "=r" (regs[5]), "=r" (regs[6]), "=r" (regs[7]),
          "=r" (regs[8]), "=r" (regs[9]), "=r" (regs[10]), "=r" (regs[11])
    );
    regs[7] += 8;
    __asm__ volatile (
        "mov %%r12, %0\n\t"
        "mov %%r13, %1\n\t"
        "mov %%r14, %2\n\t"
        "mov %%r15, %3\n\t"
        "mov %%cs, %4\n\t"
        "mov %%ds, %5\n\t"
        "mov %%ss, %6\n\t"
        "rdfsbase %7\n\t"
        "rdgsbase %8\n\t"
        : "=r" (regs[12]), "=r" (regs[13]), "=r" (regs[14]), "=r" (regs[15]),
          "=r" (regs[16]), "=r" (regs[17]), "=r" (regs[18]), "=r" (regs[19]),
          "=r" (regs[20])
    );
    printf("[LIBHOOK_DUMP] STARTING DUMP...\n");
    uint64_t params[] = {%CHRONOS_TARGET_NOTYPE_PARAMS%};
    struct CHRONOS_FUNC_DATA func_data = {
        regs,
        params,
        %CHRONOS_TARGET_PARAMS_COUNT%
    };
    dump_process(&func_data);
    printf("[LIBHOOK_DUMP] DUMPED! EXITING.\n");
    exit(0);
}
