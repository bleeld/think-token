# Token 双模式快速对比

## 🎯 一句话总结

- **Cookie模式**：后端设置HttpOnly Cookie，更安全，适合传统Web应用
- **前端模式**：Token返回给前端，更灵活，适合前后端分离

---

## 📊 核心对比表

| 对比项 | Cookie模式 | 前端模式 |
|--------|-----------|---------|
| **Token存储** | HttpOnly Cookie | LocalStorage/SessionStorage |
| **JavaScript访问** | ❌ 不可访问 | ✅ 可访问 |
| **XSS防护** | ✅ 天然防护 | ⚠️ 需自行防护 |
| **CSRF防护** | ⚠️ 需要处理 | ✅ 天然免疫 |
| **自动携带** | ✅ 浏览器自动 | ❌ 需手动添加Header |
| **跨域支持** | ⚠️ 复杂配置 | ✅ 简单易用 |
| **适用架构** | MPA、SSR | SPA、前后端分离 |
| **安全性** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **灵活性** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **实现难度** | 简单 | 中等 |

---

## 🔧 配置对比

### Cookie模式

```php
// config/token.php
return [
    'cookie_mode' => true,  // 启用Cookie模式
];
```

```env
# .env
TOKEN_COOKIE_MODE=1
```

### 前端模式（默认）

```php
// config/token.php
return [
    'cookie_mode' => false,  // 或不配置
];
```

```env
# .env
TOKEN_COOKIE_MODE=0
```

---

## 💻 代码对比

### 1. 生成Token

#### Cookie模式
```php
// 后端代码
$result = Token::createToken($userData, true);

// 返回结果
{
    "code": 200,
    "data": {
        "message": "Token has been set in cookies",
        "expires_in": 7200
    }
}

// Token已自动存储在HttpOnly Cookie中
// JavaScript无法读取：console.log(document.cookie) 看不到token
```

#### 前端模式
```php
// 后端代码
$result = Token::createToken($userData, true);

// 返回结果
{
    "code": 200,
    "data": {
        "access_token": "eyJ0eXAiOiJKV1Qi...",
        "refresh_token": "eyJ0eXAiOiJKV1Qi...",
        "token_type": "Bearer",
        "expires_in": 7200,
        "refresh_expires_in": 86400
    }
}

// 前端需要手动保存
localStorage.setItem('access_token', result.data.access_token);
```

---

### 2. 验证Token

#### Cookie模式
```php
// 中间件：从Cookie读取
$accessToken = \think\facade\Cookie::get('access_token');
$result = Token::verifyToken($accessToken);

// 浏览器自动携带Cookie，无需前端处理
```

#### 前端模式
```php
// 中间件：从Header读取
$token = request()->header('Authorization');
$token = str_replace('Bearer ', '', $token);
$result = Token::verifyToken($token);

// 前端需要手动添加Header
// axios.interceptors.request.use(config => {
//     config.headers.Authorization = `Bearer ${token}`;
// });
```

---

### 3. 刷新Token

#### Cookie模式
```php
// 后端自动从Cookie读取refresh_token
$result = Token::swapToken(null, false, true, true);

// 新Token自动更新到Cookie
// 前端无感知
```

#### 前端模式
```php
// 需要传入refresh_token
$refreshToken = input('refresh_token');
$result = Token::swapToken($refreshToken, false, true, false);

// 前端需要手动更新
// localStorage.setItem('access_token', result.data.access_token);
// localStorage.setItem('refresh_token', result.data.refresh_token);
```

---

### 4. 登出

#### Cookie模式
```php
// 撤销Token并清除Cookie
$accessToken = \think\facade\Cookie::get('access_token');
Token::blacklistToken($accessToken);
\think\facade\Cookie::delete('access_token');
\think\facade\Cookie::delete('refresh_token');
```

#### 前端模式
```php
// 撤销Token
$token = str_replace('Bearer ', '', request()->header('Authorization'));
Token::blacklistToken($token);

// 前端清除LocalStorage
// localStorage.removeItem('access_token');
// localStorage.removeItem('refresh_token');
```

---

## 🏆 如何选择？

### 选择 Cookie模式 如果：

✅ 你的项目是传统多页应用（MPA）  
✅ 使用服务端渲染（SSR）  
✅ 对安全性要求极高  
✅ 不需要跨域访问  
✅ 希望简化前端开发  

**典型场景：**
- 企业后台管理系统
- CMS内容管理系统
- 电商网站（PC端）
- 博客、论坛

---

### 选择 前端模式 如果：

✅ 你的项目是单页应用（SPA）  
✅ 前后端完全分离  
✅ 需要跨域访问API  
✅ 移动端H5应用  
✅ 需要灵活控制Token  

**典型场景：**
- Vue/React/Angular应用
- 移动端H5页面
- 小程序
- 开放API平台
- 微服务架构

---

## 🔄 动态切换示例

如果你不确定，可以支持动态切换：

```php
/**
 * 智能登录接口
 */
public function login()
{
    // 从请求中获取期望的模式
    $mode = input('token_mode', 'frontend');
    
    $userData = ['user_id' => 1, 'username' => 'test'];
    $useCookie = ($mode === 'cookie');
    
    // 第四个参数动态指定模式
    $result = Token::createToken($userData, true, null, $useCookie);
    
    return json([
        'code' => 200,
        'data' => $result['data'],
        'mode' => $useCookie ? 'cookie' : 'frontend'
    ]);
}
```

前端调用：
```javascript
// 使用Cookie模式
fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({
        username: 'admin',
        password: '123456',
        token_mode: 'cookie'
    })
});

// 使用前端模式
fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({
        username: 'admin',
        password: '123456',
        token_mode: 'frontend'
    })
});
```

---

## 📝 迁移指南

### 从前端模式迁移到Cookie模式

1. 修改配置：
```php
// config/token.php
'cookie_mode' => true,
```

2. 修改前端代码：
```javascript
// 之前：需要手动保存和发送token
localStorage.setItem('access_token', token);
axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// 现在：浏览器自动处理，只需移除相关代码
// 删除所有localStorage操作
// 删除Authorization header设置
```

3. 修改后端中间件：
```php
// 之前：从Header读取
$token = request()->header('Authorization');

// 现在：从Cookie读取
$token = \think\facade\Cookie::get('access_token');
```

---

### 从Cookie模式迁移到前端模式

1. 修改配置：
```php
// config/token.php
'cookie_mode' => false,
```

2. 添加前端代码：
```javascript
// 登录时保存token
localStorage.setItem('access_token', result.data.access_token);

// 请求时携带token
axios.interceptors.request.use(config => {
    const token = localStorage.getItem('access_token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});
```

3. 修改后端中间件：
```php
// 之前：从Cookie读取
$token = \think\facade\Cookie::get('access_token');

// 现在：从Header读取
$token = request()->header('Authorization');
$token = str_replace('Bearer ', '', $token);
```

---

## ⚡ 性能对比

| 指标 | Cookie模式 | 前端模式 |
|------|-----------|---------|
| 首次加载 | 快（无JS操作） | 快 |
| 请求大小 | +Cookie大小 | +Header大小 |
| 响应大小 | 小 | 大（包含token） |
| 客户端处理 | 无 | 需要JS处理 |
| 总体性能 | 略优 | 略差 |

**结论：** 性能差异微乎其微，主要根据架构需求选择。

---

## 🛡️ 安全对比

### XSS攻击防护

**Cookie模式：**
```
✅ HttpOnly Cookie无法被JavaScript访问
✅ 即使存在XSS漏洞，攻击者也无法窃取token
```

**前端模式：**
```
⚠️ LocalStorage可以被JavaScript访问
⚠️ 如果存在XSS漏洞，token可能被窃取
✅ 需要通过CSP、输入过滤等方式防护
```

### CSRF攻击防护

**Cookie模式：**
```
⚠️ 浏览器自动携带Cookie，可能遭受CSRF
✅ 需要使用SameSite属性或CSRF Token
```

**前端模式：**
```
✅ 需要手动添加Authorization Header
✅ 跨域请求不会自动携带，天然免疫CSRF
```

### 推荐的安全配置

#### Cookie模式
```php
// config/cookie.php
return [
    'httponly' => true,      // 防止XSS
    'secure' => true,        // 仅HTTPS
    'samesite' => 'Lax',     // CSRF防护
    'path' => '/',
];
```

#### 前端模式
```javascript
// 实施Content Security Policy
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">

// 对用户输入进行转义
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
```

---

## 🎯 最终建议

### 新项目

- **企业内部系统** → Cookie模式
- **互联网产品** → 前端模式
- **不确定** → 前端模式（更灵活）

### 老项目改造

- **已有Cookie逻辑** → 保持Cookie模式
- **准备前后端分离** → 迁移到前端模式
- **混合架构** → 使用动态切换

### 特殊场景

- **金融/医疗** → Cookie模式 + HTTPS
- **开放API** → 前端模式
- **移动端H5** → 前端模式
- **SSR应用** → Cookie模式

---

## 📚 相关文档

- [双模式详细使用指南](DUAL_MODE_GUIDE.md)
- [完整API文档](USAGE_EXAMPLE.md)
- [优化报告](OPTIMIZATION_REPORT.md)

---

**记住：** 没有绝对的好坏，只有适不适合。根据你的项目特点选择最合适的模式！
