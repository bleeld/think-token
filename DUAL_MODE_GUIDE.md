# Token 双模式使用指南

## 📋 目录
- [模式说明](#模式说明)
- [配置方式](#配置方式)
- [模式一：Cookie模式](#模式一cookie模式)
- [模式二：前端模式](#模式二前端模式)
- [动态切换模式](#动态切换模式)
- [完整示例](#完整示例)
- [最佳实践](#最佳实践)

---

## 🎯 模式说明

Think-Token 插件提供两种Token管理模式，可以根据项目需求灵活选择：

### 模式对比

| 特性 | Cookie模式 | 前端模式 |
|------|-----------|---------|
| **存储位置** | HttpOnly Cookie | LocalStorage/SessionStorage |
| **安全性** | ⭐⭐⭐⭐⭐ (防XSS) | ⭐⭐⭐ (需自行防护) |
| **便利性** | ⭐⭐⭐⭐ (自动携带) | ⭐⭐⭐⭐⭐ (灵活控制) |
| **适用场景** | 传统Web应用、SSR | SPA、前后端分离、移动端 |
| **CSRF防护** | 需要额外处理 | 不需要 |
| **跨域支持** | 较复杂 | 简单 |
| **推荐度** | 企业级应用 | 现代Web应用 |

---

## ⚙️ 配置方式

### 1. 全局配置（config/token.php）

```php
<?php
return [
    // ... 其他配置 ...
    
    // Token存储模式
    'cookie_mode' => false,  // false=前端模式(默认), true=Cookie模式
];
```

### 2. 环境变量配置（.env）

```env
# Token存储模式：0=前端模式，1=Cookie模式
TOKEN_COOKIE_MODE=0
```

### 3. 运行时动态切换

每个方法都支持 `$useCookie` 参数来覆盖全局配置：

```php
// 临时使用Cookie模式
Token::createToken($data, true, null, true);

// 临时使用前端模式
Token::createToken($data, true, null, false);
```

---

## 🍪 模式一：Cookie模式

### 特点
- ✅ 后端自动设置HttpOnly Cookie
- ✅ JavaScript无法访问，防止XSS攻击
- ✅ 浏览器自动携带Cookie
- ✅ 更安全，适合传统Web应用

### 配置

```php
// config/token.php
return [
    'cookie_mode' => true,  // 启用Cookie模式
];
```

或在 `.env` 中：
```env
TOKEN_COOKIE_MODE=1
```

### 使用示例

#### 1. 生成Token（后端自动设置Cookie）

```php
<?php
namespace app\api\controller;

use think\Token;

class AuthController
{
    /**
     * 用户登录
     */
    public function login()
    {
        $username = input('username');
        $password = input('password');
        
        // 验证用户（省略具体逻辑）
        $user = $this->validateUser($username, $password);
        
        if (!$user) {
            return json(['code' => 400, 'msg' => '用户名或密码错误']);
        }
        
        // 准备用户数据
        $userData = [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role']
        ];
        
        // 生成Token（会自动设置Cookie）
        $result = Token::createToken($userData, true);
        
        if ($result['code'] === 200) {
            return json([
                'code' => 200,
                'msg' => '登录成功',
                'data' => [
                    'message' => $result['data']['message'],
                    'refresh_message' => $result['data']['refresh_message'] ?? null,
                    'expires_in' => $result['data']['expires_in'],
                    'user_info' => [
                        'user_id' => $userData['user_id'],
                        'username' => $userData['username'],
                        'role' => $userData['role']
                    ]
                ]
            ]);
        }
        
        return json(['code' => 500, 'msg' => 'Token生成失败']);
    }
}
```

**返回结果：**
```json
{
    "code": 200,
    "msg": "登录成功",
    "data": {
        "message": "Token has been set in cookies",
        "refresh_message": "Refresh token has been set in cookies",
        "expires_in": 7200,
        "user_info": {
            "user_id": 1,
            "username": "admin",
            "role": "admin"
        }
    }
}
```

**注意：** Token已存储在HttpOnly Cookie中，JavaScript无法读取。

#### 2. 验证Token（从Cookie自动读取）

创建中间件 `app/middleware/CookieAuth.php`：

```php
<?php
namespace app\middleware;

use think\Token;
use think\Response;

class CookieAuth
{
    public function handle($request, \Closure $next)
    {
        // 从Cookie获取token
        $accessToken = \think\facade\Cookie::get('access_token');
        
        if (empty($accessToken)) {
            return Response::create([
                'code' => 401,
                'msg' => '未登录或登录已过期'
            ], 'json', 401);
        }
        
        // 验证token
        $result = Token::verifyToken($accessToken);
        
        if ($result['code'] !== 200) {
            return Response::create([
                'code' => 401,
                'msg' => $result['msg']
            ], 'json', 401);
        }
        
        // 将用户信息注入请求
        $request->userInfo = $result['data'];
        
        return $next($request);
    }
}
```

#### 3. 刷新Token

```php
/**
 * 刷新Token
 */
public function refreshToken()
{
    // Cookie模式下，swapToken会自动从Cookie读取refresh_token
    $result = Token::swapToken(null, false, true, true);
    
    if ($result['code'] === 200) {
        return json([
            'code' => 200,
            'msg' => 'Token刷新成功',
            'data' => [
                'message' => $result['data']['message'],
                'expires_in' => $result['data']['expires_in'],
                'user_data' => $result['data']['user_data']
            ]
        ]);
    }
    
    return json([
        'code' => 401,
        'msg' => $result['msg']
    ], 401);
}
```

#### 4. 自动刷新Token

```php
/**
 * 自动检查并刷新Token
 */
public function autoRefresh()
{
    // Cookie模式下，autoSwapToken会自动从Cookie读取tokens
    $result = Token::autoSwapToken(null, false, true);
    
    if ($result['code'] === 200) {
        if ($result['data']['status'] === 'valid') {
            return json([
                'code' => 200,
                'msg' => 'Token仍然有效',
                'data' => $result['data']['user_data']
            ]);
        } else {
            return json([
                'code' => 200,
                'msg' => 'Token已刷新',
                'data' => $result['data']
            ]);
        }
    }
    
    return json([
        'code' => 401,
        'msg' => $result['msg']
    ], 401);
}
```

#### 5. 登出（撤销Token）

```php
/**
 * 用户登出
 */
public function logout()
{
    $accessToken = \think\facade\Cookie::get('access_token');
    
    if ($accessToken) {
        // 将token加入黑名单
        Token::blacklistToken($accessToken);
        
        // 清除Cookie
        \think\facade\Cookie::delete('access_token');
        \think\facade\Cookie::delete('refresh_token');
    }
    
    return json(['code' => 200, 'msg' => '登出成功']);
}
```

---

## 💻 模式二：前端模式（默认）

### 特点
- ✅ Token返回给前端，前端自行存储
- ✅ 灵活控制存储方式（LocalStorage/SessionStorage）
- ✅ 适合前后端分离架构
- ✅ 易于实现跨域

### 配置

```php
// config/token.php
return [
    'cookie_mode' => false,  // 前端模式（默认）
];
```

### 使用示例

#### 1. 生成Token（返回给前端）

```php
<?php
namespace app\api\controller;

use think\Token;

class AuthController
{
    /**
     * 用户登录
     */
    public function login()
    {
        $username = input('username');
        $password = input('password');
        
        // 验证用户
        $user = $this->validateUser($username, $password);
        
        if (!$user) {
            return json(['code' => 400, 'msg' => '用户名或密码错误']);
        }
        
        // 准备用户数据
        $userData = [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role']
        ];
        
        // 生成Token（返回给前端）
        $result = Token::createToken($userData, true);
        
        if ($result['code'] === 200) {
            return json([
                'code' => 200,
                'msg' => '登录成功',
                'data' => [
                    'access_token' => $result['data']['access_token'],
                    'refresh_token' => $result['data']['refresh_token'],
                    'token_type' => 'Bearer',
                    'expires_in' => $result['data']['expires_in'],
                    'refresh_expires_in' => $result['data']['refresh_expires_in'],
                    'user_info' => [
                        'user_id' => $userData['user_id'],
                        'username' => $userData['username'],
                        'role' => $userData['role']
                    ]
                ]
            ]);
        }
        
        return json(['code' => 500, 'msg' => 'Token生成失败']);
    }
}
```

**返回结果：**
```json
{
    "code": 200,
    "msg": "登录成功",
    "data": {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
        "token_type": "Bearer",
        "expires_in": 7200,
        "refresh_expires_in": 86400,
        "user_info": {
            "user_id": 1,
            "username": "admin",
            "role": "admin"
        }
    }
}
```

#### 2. 前端存储Token（JavaScript）

```javascript
// 登录处理
async function handleLogin(username, password) {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    
    const result = await response.json();
    
    if (result.code === 200) {
        // 保存tokens到LocalStorage
        localStorage.setItem('access_token', result.data.access_token);
        localStorage.setItem('refresh_token', result.data.refresh_token);
        localStorage.setItem('expires_in', result.data.expires_in);
        
        // 保存用户信息
        localStorage.setItem('user_info', JSON.stringify(result.data.user_info));
        
        // 跳转到首页
        window.location.href = '/dashboard';
    } else {
        alert(result.msg);
    }
}
```

#### 3. API请求携带Token

```javascript
// axios拦截器
axios.interceptors.request.use(config => {
    const token = localStorage.getItem('access_token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// 或者使用fetch
async function fetchWithAuth(url, options = {}) {
    const token = localStorage.getItem('access_token');
    
    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };
    
    return fetch(url, { ...defaultOptions, ...options });
}
```

#### 4. 后端验证Token

```php
<?php
namespace app\middleware;

use think\Token;
use think\Response;

class FrontendAuth
{
    public function handle($request, \Closure $next)
    {
        // 从请求头获取token
        $token = $request->header('Authorization');
        
        if (empty($token)) {
            return Response::create([
                'code' => 401,
                'msg' => '未提供认证令牌'
            ], 'json', 401);
        }
        
        // 去除Bearer前缀
        $token = str_replace('Bearer ', '', $token);
        
        // 验证token
        $result = Token::verifyToken($token);
        
        if ($result['code'] !== 200) {
            return Response::create([
                'code' => 401,
                'msg' => $result['msg']
            ], 'json', 401);
        }
        
        // 将用户信息注入请求
        $request->userInfo = $result['data'];
        
        return $next($request);
    }
}
```

#### 5. 刷新Token

```php
/**
 * 刷新Token
 */
public function refreshToken()
{
    $refreshToken = input('refresh_token');
    
    if (empty($refreshToken)) {
        return json(['code' => 400, 'msg' => '请提供refresh_token']);
    }
    
    // 前端模式，需要传入refresh_token
    $result = Token::swapToken($refreshToken, false, true, false);
    
    if ($result['code'] === 200) {
        return json([
            'code' => 200,
            'msg' => 'Token刷新成功',
            'data' => [
                'access_token' => $result['data']['access_token'],
                'refresh_token' => $result['data']['refresh_token'],
                'token_type' => 'Bearer',
                'expires_in' => $result['data']['expires_in'],
                'refresh_expires_in' => $result['data']['refresh_expires_in']
            ]
        ]);
    }
    
    return json([
        'code' => 401,
        'msg' => $result['msg']
    ], 401);
}
```

前端调用：
```javascript
async function refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    
    const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken })
    });
    
    const result = await response.json();
    
    if (result.code === 200) {
        // 保存新tokens
        localStorage.setItem('access_token', result.data.access_token);
        localStorage.setItem('refresh_token', result.data.refresh_token);
        
        return result.data;
    } else {
        // 刷新失败，跳转登录
        localStorage.clear();
        window.location.href = '/login';
        throw new Error(result.msg);
    }
}
```

#### 6. 自动刷新Token

```php
/**
 * 自动检查并刷新Token
 */
public function autoRefresh()
{
    $accessToken = input('access_token');
    $refreshToken = input('refresh_token');
    
    if (empty($accessToken) || empty($refreshToken)) {
        return json(['code' => 400, 'msg' => '请提供tokens']);
    }
    
    // 前端模式，需要传入tokens数组
    $result = Token::autoSwapToken([
        'access_token' => $accessToken,
        'refresh_token' => $refreshToken
    ], false, false);
    
    return json($result);
}
```

前端调用：
```javascript
// 自动刷新管理器
class TokenManager {
    constructor() {
        this.checkInterval = null;
    }
    
    // 启动自动检查
    startAutoCheck() {
        // 每5分钟检查一次
        this.checkInterval = setInterval(() => {
            this.checkAndRefresh();
        }, 5 * 60 * 1000);
    }
    
    // 停止自动检查
    stopAutoCheck() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }
    }
    
    // 检查并刷新
    async checkAndRefresh() {
        const accessToken = localStorage.getItem('access_token');
        const refreshToken = localStorage.getItem('refresh_token');
        
        if (!accessToken || !refreshToken) {
            return;
        }
        
        try {
            const response = await fetch('/api/auth/auto-refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    access_token: accessToken,
                    refresh_token: refreshToken
                })
            });
            
            const result = await response.json();
            
            if (result.code === 200) {
                if (result.data.status === 'valid') {
                    console.log('Token仍然有效');
                } else {
                    // Token已刷新，更新本地存储
                    localStorage.setItem('access_token', result.data.access_token);
                    localStorage.setItem('refresh_token', result.data.refresh_token);
                    console.log('Token已自动刷新');
                }
            } else if (result.code === 401) {
                // 需要重新登录
                this.handleLogout();
            }
        } catch (error) {
            console.error('Token检查失败:', error);
        }
    }
    
    // 处理登出
    handleLogout() {
        this.stopAutoCheck();
        localStorage.clear();
        window.location.href = '/login';
    }
}

// 使用
const tokenManager = new TokenManager();
tokenManager.startAutoCheck();
```

---

## 🔄 动态切换模式

你可以在不同场景下动态切换模式：

### 示例1：根据设备类型切换

```php
/**
 * 智能选择Token模式
 */
public function login()
{
    // 检测设备类型
    $isMobile = request()->isMobile();
    $userAgent = request()->header('User-Agent');
    
    // 移动端使用前端模式，PC端使用Cookie模式
    $useCookie = !$isMobile;
    
    $userData = ['user_id' => 1, 'username' => 'test'];
    
    // 动态指定模式
    $result = Token::createToken($userData, true, null, $useCookie);
    
    return json([
        'code' => 200,
        'msg' => '登录成功',
        'data' => $result['data'],
        'mode' => $useCookie ? 'cookie' : 'frontend'
    ]);
}
```

### 示例2：根据接口类型切换

```php
// API接口 - 使用前端模式
Route::post('api/login', 'AuthController@login')->ext('json');

// Web页面 - 使用Cookie模式  
Route::post('web/login', 'WebAuthController@login');
```

```php
<?php
namespace app\web\controller;

use think\Token;

class WebAuthController
{
    public function login()
    {
        // Web页面强制使用Cookie模式
        $result = Token::createToken($userData, true, null, true);
        
        // 重定向到首页
        return redirect('/index');
    }
}
```

### 示例3：混合模式

```php
/**
 * 同时支持两种模式的登录接口
 */
public function smartLogin()
{
    $mode = input('token_mode', 'frontend'); // frontend 或 cookie
    
    $userData = ['user_id' => 1, 'username' => 'test'];
    $useCookie = ($mode === 'cookie');
    
    $result = Token::createToken($userData, true, null, $useCookie);
    
    return json([
        'code' => 200,
        'msg' => '登录成功',
        'data' => $result['data'],
        'mode' => $mode
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
        token_mode: 'cookie'  // 指定使用Cookie模式
    })
});

// 使用前端模式
fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({
        username: 'admin',
        password: '123456',
        token_mode: 'frontend'  // 指定使用前端模式
    })
});
```

---

## 📚 完整示例

### 项目结构

```
app/
├── api/              # API控制器（前端模式）
│   └── controller/
│       └── Auth.php
├── web/              # Web控制器（Cookie模式）
│   └── controller/
│       └── Auth.php
├── middleware/
│   ├── ApiAuth.php      # API认证中间件
│   └── WebAuth.php      # Web认证中间件
config/
└── token.php         # Token配置
```

### API控制器（前端模式）

```php
<?php
namespace app\api\controller;

use think\Token;

class Auth
{
    /**
     * 登录
     */
    public function login()
    {
        $username = input('username');
        $password = input('password');
        
        // TODO: 验证用户
        
        $userData = [
            'user_id' => 1,
            'username' => $username,
            'role' => 'user'
        ];
        
        // 前端模式（默认）
        $result = Token::createToken($userData, true);
        
        return json([
            'code' => 200,
            'data' => $result['data']
        ]);
    }
    
    /**
     * 刷新Token
     */
    public function refresh()
    {
        $refreshToken = input('refresh_token');
        $result = Token::swapToken($refreshToken);
        
        return json($result);
    }
    
    /**
     * 获取用户信息
     */
    public function userinfo()
    {
        // 从请求中获取用户信息（由中间件注入）
        $userInfo = request()->userInfo;
        
        return json([
            'code' => 200,
            'data' => $userInfo
        ]);
    }
}
```

### Web控制器（Cookie模式）

```php
<?php
namespace app\web\controller;

use think\Token;

class Auth
{
    /**
     * 登录
     */
    public function login()
    {
        $username = input('username');
        $password = input('password');
        
        // TODO: 验证用户
        
        $userData = [
            'user_id' => 1,
            'username' => $username,
            'role' => 'user'
        ];
        
        // Cookie模式
        $result = Token::createToken($userData, true, null, true);
        
        if ($result['code'] === 200) {
            return redirect('/index');
        }
        
        return redirect('/login?error=1');
    }
    
    /**
     * 登出
     */
    public function logout()
    {
        $accessToken = \think\facade\Cookie::get('access_token');
        
        if ($accessToken) {
            Token::blacklistToken($accessToken);
            \think\facade\Cookie::delete('access_token');
            \think\facade\Cookie::delete('refresh_token');
        }
        
        return redirect('/login');
    }
}
```

### API认证中间件

```php
<?php
namespace app\middleware;

use think\Token;

class ApiAuth
{
    public function handle($request, \Closure $next)
    {
        $token = $request->header('Authorization');
        
        if (empty($token)) {
            return json(['code' => 401, 'msg' => '未授权'], 401);
        }
        
        $token = str_replace('Bearer ', '', $token);
        $result = Token::verifyToken($token);
        
        if ($result['code'] !== 200) {
            return json(['code' => 401, 'msg' => $result['msg']], 401);
        }
        
        $request->userInfo = $result['data'];
        return $next($request);
    }
}
```

### Web认证中间件

```php
<?php
namespace app\middleware;

use think\Token;

class WebAuth
{
    public function handle($request, \Closure $next)
    {
        $token = \think\facade\Cookie::get('access_token');
        
        if (empty($token)) {
            return redirect('/login');
        }
        
        $result = Token::verifyToken($token);
        
        if ($result['code'] !== 200) {
            \think\facade\Cookie::delete('access_token');
            \think\facade\Cookie::delete('refresh_token');
            return redirect('/login');
        }
        
        $request->userInfo = $result['data'];
        return $next($request);
    }
}
```

---

## 💡 最佳实践

### 1. 选择合适的模式

**使用Cookie模式的场景：**
- ✅ 传统多页应用（MPA）
- ✅ 服务端渲染（SSR）
- ✅ 对安全性要求极高
- ✅ 不需要跨域

**使用前端模式的场景：**
- ✅ 单页应用（SPA）
- ✅ 前后端完全分离
- ✅ 需要跨域访问
- ✅ 移动端H5应用
- ✅ 需要灵活控制Token

### 2. 安全建议

#### Cookie模式
```php
// config/cookie.php
return [
    'httponly' => true,   // 防止XSS
    'secure' => true,     // 仅HTTPS（生产环境）
    'samesite' => 'Lax',  // CSRF保护
];
```

#### 前端模式
```javascript
// 防止XSS
- 对用户输入进行转义
- 使用Content-Security-Policy
- 定期更新依赖包

// 安全存储
- 考虑使用加密的LocalStorage
- 实现Token自动刷新
- 登出时清除所有Token
```

### 3. 性能优化

```php
// 批量验证时使用缓存
use think\facade\Cache;

function batchVerifyTokens(array $tokens): array
{
    $results = [];
    
    foreach ($tokens as $userId => $token) {
        $cacheKey = 'token_verify_' . md5($token);
        
        $cached = Cache::get($cacheKey, 300); // 缓存5分钟
        if ($cached !== false) {
            $results[$userId] = $cached;
            continue;
        }
        
        $result = Token::verifyToken($token);
        Cache::set($cacheKey, $result, 300);
        
        $results[$userId] = $result;
    }
    
    return $results;
}
```

### 4. 错误处理

```php
try {
    $result = Token::createToken($userData, true, null, $useCookie);
    
    if ($result['code'] !== 200) {
        throw new \Exception($result['msg']);
    }
    
    // 处理成功逻辑
    
} catch (\InvalidArgumentException $e) {
    // 参数错误
    return json(['code' => 400, 'msg' => '参数错误: ' . $e->getMessage()]);
    
} catch (\Exception $e) {
    // 其他错误
    return json(['code' => 500, 'msg' => '系统错误']);
}
```

---

## 🎯 总结

| 场景 | 推荐模式 | 配置 |
|------|---------|------|
| 传统Web应用 | Cookie模式 | `'cookie_mode' => true` |
| 前后端分离 | 前端模式 | `'cookie_mode' => false` |
| 移动App H5 | 前端模式 | `'cookie_mode' => false` |
| 混合应用 | 动态切换 | 使用 `$useCookie` 参数 |
| 高安全需求 | Cookie模式 | `'cookie_mode' => true` + HTTPS |

**核心优势：**
- ✅ 一套代码，两种模式
- ✅ 可以全局配置，也可以动态切换
- ✅ 向后兼容，不影响现有代码
- ✅ 灵活适应不同项目需求

根据你的项目特点选择合适的模式，或者在不同场景下动态切换！
