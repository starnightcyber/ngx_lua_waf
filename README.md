## ngx_lua_waf_x

### Preface

ngx_lua_waf_x 基于[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)

主要调整有：

```
个人阅读代码，增加注释，调整格式；
补充一些基本规则，规则集源自owasp核心规则集；
修正已知的bug；
在个人能力范围内，尽量接收在原项目上的PR；
```

### 功能
    	
```
防止sql注入，本地包含，部分溢出，fuzzing测试，XSS，SSRF等web攻击；
防止svn/备份之类文件泄漏;
防止ApacheBench之类压力测试工具的攻击；
屏蔽常见的扫描黑客工具，扫描器；
屏蔽异常的网络请求；
屏蔽图片附件类目录php执行权限；
防止webshell上传；
```

### 推荐安装

推荐使用lujit2.1做lua支持

ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。

安装参考：[ngx_lua_waf安装使用](https://github.com/starnightcyber/Security-Learning/wiki/ngx_lua_waf%E5%AE%89%E8%A3%85%E4%BD%BF%E7%94%A8)

### 配置文件详细说明

```
RulePath = "/usr/local/nginx/conf/waf/wafconf/"
--规则存放目录
attacklog = "off"
--是否开启攻击信息记录，需要配置logdir
logdir = "/usr/local/nginx/logs/hack/"
--log存储目录，该目录需要用户自己新建，切需要nginx用户的可写权限
UrlDeny="on"
--是否拦截url访问
Redirect="on"
--是否拦截后重定向
CookieMatch = "on"
--是否拦截cookie攻击
postMatch = "on" 
--是否拦截post攻击
whiteModule = "on" 
--是否开启URL白名单
black_fileExt={"php","jsp"}
--填写不允许上传文件后缀类型
ipWhitelist={"127.0.0.1"}
--ip白名单，多个ip用逗号分隔
ipBlocklist={"1.0.0.1"}
--ip黑名单，多个ip用逗号分隔
CCDeny="on"
--是否开启拦截cc攻击(需要nginx.conf的http段增加lua_shared_dict limit 10m;)
CCrate = "100/60"
--设置cc攻击频率，单位为秒.
--默认1分钟同一个IP只能请求同一个地址100次
html=[[Please go away~~]]
--警告内容,可在中括号内自定义
备注:不要乱动双引号，区分大小写
```
        
### 检查规则是否生效

部署完毕可以尝试如下命令：        
```  
curl http://xxxx/test.php?id=../etc/passwd
返回拦截提示页面。如：
“您的请求带有不合法参数，已被网站管理员设置拦截！”
```
注意:默认，本机在白名单不过滤，可自行调整config.lua配置

### 一些说明

规则文件补充，请参考：[owasp-modsecurity-crs](https://github.com/SpiderLabs/owasp-modsecurity-crs)

* wafconf/url：补充自[restricted-files.data](https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.3/dev/rules/restricted-files.data)
* wafconf/user-agent：补充自[scanners-user-agents.data](https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.3/dev/rules/scanners-user-agents.data)


过滤规则在wafconf下，可根据需求自行调整，每条规则需换行，或者用|分割

```
args里面的规则get参数进行过滤的
url是只在get请求url过滤的规则
post是只在post请求过滤的规则
whitelist是白名单，里面的url匹配到不做过滤	
user-agent是对user-agent的过滤规则
```

默认开启了get和post过滤，需要开启cookie过滤的，编辑waf.lua取消部分--注释即可

日志文件名称格式如下:虚拟主机名_sec.log	


## Copyright

<table>
  <tr>
    <td>Weibo</td><td>神奇的魔法师</td>
  </tr>
  <tr>
    <td>Forum</td><td>http://bbs.linuxtone.org/</td>
  </tr>
  <tr>
    <td>Copyright</td><td>Copyright (c) 2013- loveshell</td>
  </tr>
  <tr>
    <td>License</td><td>MIT License</td>
  </tr>
</table>
	
感谢ngx_lua模块的开发者[@agentzh](https://github.com/agentzh/),春哥是我所接触过开源精神最好的人
