# Write Up

## Bugku

### 1.   pwn2

![](截图\1.1.png)

1. ida查看主函数，发现read函数处栈溢出

![](截图\1.2.png)

2. gdb调试，写入100个字符让栈溢出

![](截图\1.3.png)

3. 查看溢出点

![](截图\1.4.png)

4. 查找shell地址

![](截图\1.5.png)

5. 构造payload得到flag

### 2.   图穷匕见

![](截图\2.1.png)

1. 查看文件尾发现后面还有很多内容，复制出去

![](截图\2.2.png)

2. 对后半段内容进行进制转换得到一些作图得坐标

![](截图\2.3.png)

![](截图\2.4.png)

3. 在linux中使用工具gnuplot进行作图得到二维码，扫码得flag

### 3.   convert

![](截图\3.1.png)

1. 打开原文件发现全是二进制，想到转换为16进制

![](截图\3.2.png)

2. 转换为16进制发现为rar文件，将rar文件导出解压得到一张图片

![](截图\3.3.png)

![](截图\3.4.png)

3. 在图片属性中发现base64加密，解密得flag

### 4.   听首音乐

![](截图\4.1.png)

1. 使用Audacity打开，发现可能为莫斯解密

![](截图\4.2.png)

2. 莫斯解密得flag

### 5.   怀疑人生

![](截图\5.1.png)

1. 先查看ctf1.zip发现有密码，直接暴力破解，得到txt文件中一段base64加密，解密后继续Unicode解密得到第一段flag

![](截图\5.2.png)

![](截图\5.3.png)

2. 打开ctf2.jpg发现图片后半段有zip文件，导出zip解压得到txt文件，发现是ook编码，[在线解密网站](https://www.splitbrain.org/services/ook)，解密后发现还是base58加密，继续解密得到第二段flag

![](截图\5.4.png)

![](截图\5.5.png)

![](截图\5.6.png)

3. 扫描二维码得第三段flag

### 6.   不简单的压缩包

![](截图\6.1.png)

1. 发现压缩包不对劲，直接binwalk发现解压出另外一个压缩包，对这个压缩包暴力破解得到提示说第一个压缩包密码50位

![](截图\6.2.png)

![](截图\6.3.png)

![](截图\6.4.png)

2. 查找资料找到kali的/usr/share/wordlist下有一个非常牛逼的字典 rockyou，添加字典得到密码50个a，解压出flag.swf

![](截图\6.5.png)

![](截图\6.6.png)

3. 使用JPEXS Free Flash Decompiler打开发现怪异之处，16进制转字符得到flag

### 7.   各种绕过

![](截图\7.1.png)

sha1比较数组漏洞：get传入uname[]=1&id=margin，然后post传入passwd[]=2 即可绕过

### 8.   web8

![](截图\8.1.png)

![](截图\8.2.png)

根据题目提示可知有flag.txt文件，进入文件发现文件内容flags，源码要传入文件且令ac等于文件内容，get传入即可

### 9.   细心

![](截图\9.1.png)

![](截图\9.2.png)

1. 扫后台发现新网址resusl.php，进入发现提示

![](截图\9.3.png)

![](截图\9.4.png)

2. 根据提示get传入x=password即可，password为admin

### 10.   求getshell

![](截图\10.1.png)

根据题目上传jpg抓包改文件名，经过尝试发现只有php5可以，还需通过大小写绕过请求头得Content-Type

### 11.   简单的社工尝试

![](截图\11.1.png)

1. 先用百度识图没有识别出，用谷歌识别出github上的地址

![](截图\11.2.png)

![](截图\11.3.png)

2. 进入发现微博地址，进入后发现flag地址c.bugku.com/13211.txt(不过进不去)

### 12.   strpos数组绕过

![](截图\12.1.png)

![](截图\12.2.png)

直接看源码，首先得让ctf为数字，其次要绕过strpos()函数，strpos() 函数查找字符串在另一字符串中第一次出现的位置。它不能对数组处理，如果是数组则返回null,null，也就不等于FALSE，构造payload后get传入即可

### 13.   来自宇宙的信号

![](截图\19.1.png)

搜索银河语言，出来对照翻译即可得到flag{nopqrst}

### 14.   数字验证正则绕过

![](截图\20.1.png)

![](截图\20.2.png)

![](截图\20.3.png)

根据分析构造payload即可，刚开始以为password就行，最后发现得flag

## i春秋

### 1.   Classical CrackMe

![](截图\13.1.png)

![](截图\13.2.png)

查壳后发现.net，使用IL Spy在主函数处发现端倪，base64解密得到flag

### 2.   FindKey

![](截图\14.1.png)

![](截图\14.2.png)

1. 拿到文件不知道是什么，拿去linux中file以下得知是python已经编译的文件，反编译之后得到关键代码，反向操作即可

![](截图\14.3.png)

2. flag长度为17进行逆向操作，然后ord(flag[i]) + pwda[i] & 255 != lookup[(i + pwdb[i])]操作，反向操作得到flag

### 3.   流量分析

![](截图\15.1.png)

![](截图\15.4.png)

1. 使用wireshark进行分析，在http的post里找到jsfuck编码，拖到浏览器console解码得到Thi5_my_p@ssW0rd

![](截图\15.2.png)

![](截图\15.3.png)

2. 使用winhex分析log文件，发现16进制一大串，导出发现rar文件，想到前面的解码，解密rar文件成功，得到flag

### 4.   Do you know upload？

![](截图\16.1.png)

![](截图\16.2.png)

1. 上传一句话木马抓包修改文件后缀，蚁剑连接

![](截图\16.3.png)

![](截图\16.4.png)

2. 发现文件中有config.php文件，进入发现数据库账号密码，蚁剑连接发现flag

### 5.   shellcode



![](截图\17.1.png)![](截图\17.2.png)

使用notepad++打开文件，复制下文件内容，使用[shellcodeexec](https://github.com/inquisb/shellcodeexec)打开文件内容得到flag

### 6.   加密的文档

![](截图\18.1.png)

1. 发现zip伪加密，修改09为00，解压后发现docx文件

![](截图\18.2.png)

2. 使用winhex打开docx文件发现zip文件头，修改文件后缀为zip

![](截图\18.3.png)

3. 解压zip文件在解压文件media文件夹中发现flag