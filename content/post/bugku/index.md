+++
date = '2026-01-03T23:49:27+08:00'
draft = true
title = 'Bugku'
+++


做了20题左右，仅记录了几道略难的题目。
![](img0.png)
## source


![](img1.png)
查看源码，发现一个类似flag的内容，尝试了一下不对，

用网页开发者工具查看cookie，也没有东西
尝试用目录扫描工具，dirsearch扫一下
![](img2.png)
发现有 .git 隐藏文件夹（它用来记录当前项目所有的版本历史，也能恢复代码到某次版本下）   那怎么把这个 .git 文件夹弄到本地来呢


使用kali自带的wget命令，
wget -r https://你的服务器网站地址/.git

![](img3.png)
发现一共有两次git提交
一次是d256328
一次是e0b8e8e
回滚到d256328，发现flag.txt被删除了，但实际上只要 .git 文件夹还在，任何人都可以通过 git log和 git show 找回被删除的敏感文件
使用ll命令查看后发现没有flag文件
![](img4.png)
输入git show d25632查看改动情况
![](img5.png)
发现这是一个假的flag

使用git reflog
![](img6.png)

发现还有很多历史版本，
然后使用git show xxxx挨个扫
发现果然flag藏在其中
![](img8.png)


## 本地管理员
查看源码：
![](img9.png)

发现一个编码，解码后是test123，不知道是密码还是账号
试一下
![](img10.png)
发现ip禁止访问，有提示是要本地管理员登录，所以尝试把ip改为127.0.0.1
用bp抓包重放，添加X-Forwarded-For:127.0.0.1字段
![](img11.png)
回显变了，说明ip是对的，要修改密码账号信息才可以
，然后试了一下admin就成功了
![](img12.png)


## game1
猜测玩游戏得到一定分数就可以获得flag，抓包然后修改score为10000，不行
因为后面有个sign值，sign值的作用，进行签名，把数据做了加密后产生的，后台会把提交过去的数据做相同处理产生 sign 值和你发过去的 sign 值做判断，不一致则数据是被篡改了

![](img13.png)


查看源码，sign值是如何生成的
发现是base64

![](img14.png)

![](img15.png)

把生成的加密结果放入bp发现还是不行
继续分析源码，发现有一个自定义的base.js，应该是自设的编码机制
然后直接在浏览器控制台调用函数，解码后的内容复制到bp的sign

![](img16.png)
![](img17.png)成功拿到flag 
flag{42febc48bc0404dc97ad61dab97d7d6d}


