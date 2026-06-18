---
title: CTFd 平台搭建指南
date: 2026-06-18 20:55:18
tags:
- CTF
- CTFd
- Docker
---

## 什么是 CTFd

CTFd 是最流行的 CTF 竞赛平台，Python Flask 开发，支持动态分数、队伍管理、题目分类等功能。

## Docker 搭建

```bash
git clone https://github.com/CTFd/CTFd.git
cd CTFd
docker-compose up -d
```

首次访问 `http://服务器IP:8000` 进入初始化页面，设置管理员账号和比赛信息。

## Nginx 反向代理 + HTTPS

```nginx
server {
    listen 443 ssl;
    server_name ctf.yourdomain.com;
    ssl_certificate /etc/ssl/certs/xxx.pem;
    ssl_certificate_key /etc/ssl/private/xxx.key;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 题目管理

| 类型 | 说明 | 适用场景 |
|------|------|---------|
| Standard | 静态 Flag，固定分值 | Web、Misc |
| Dynamic | 动态分数，随解题人数递减 | Pwn、Reverse |
| Docker | 容器化，自动启停 | AWD、Pwn |

## 常用操作

```bash
# 安装 ctfcli——题目发布工具
pip3 install ctfcli

# 发布题目
ctf challenge install ./challenge_dir/

# 导出数据备份
# 后台 → Config → Backup → Export
```
