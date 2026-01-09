+++
date = '2026-01-03T23:49:27+08:00'
draft = true
title = 'Bugku'
+++

# 12.29-1.4号
做了20题左右，仅记录了几道略难的题目。
![](img0.png)
## source


![](img1.png)
查看源码，发现一个类似flag的内容，尝试了一下不对，

用网页开发者工具查看cookie，也没有东西
尝试用目录扫描工具，dirsearch扫一下
![](img2.png)
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
![](img17.png)成功拿到flag 
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
