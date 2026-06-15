# Think-Token 插件使用指南

## 📋 目录
- [安装配置](#安装配置)
- [基本用法](#基本用法)
- [高级功能](#高级功能)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)

---

## 🔧 安装配置

### 1. 基础配置

配置文件位于 `config/token.php`：

```php
<?php
return [
    // JWT签名密钥（至少32个字符）
    'key'           =>  env('TOKEN_KEY') ?: '',
    
    // access_token过期时间（秒），默认2小时
    'expire_time'   =>  (int)(env('TOKEN_EXPIRE_TIME') ?: 7200),
    
    // 加密算法：HS256, HS384, HS512, RS256, RS384, RS512
    'method'        =>  env('TOKEN_METHOD') ?: 'HS256',
    
    // 是否开启刷新token功能
    'is_refresh'    =>  true,
];
```

### 2. 环境变量配置（推荐）

在 `.env` 文件中配置：

```env
# JWT密钥（建议使用以下命令生成）
# php -r "echo bin2hex(random_bytes(32));"
TOKEN_KEY=your_secure_64_character_hex_key_here

# Token过期时间（秒）
TOKEN_EXPIRE_TIME=7200

# 加密算法
TOKEN_METHOD=HS256
```

### 3. 生成安全密钥

```php
// 方法1：使用命令行
php -r "echo \think\Token::generateKey();"

// 方法2：在代码中生成
$key = \think\Token::generateKey();
echo $key; // 输出类似：a3f5b8c9d2e1f4a7b6c5d8e9f2a1b4c7d6e9f8a1b2c3d4e5f6a7b8c9d0e1f2a3
```

---

## 💡 基本用法

### 1. 生成 Token

#### 生成 Access Token

```php
use think\Token;

// 用户登录成功后生成token
$userData = [
    'user_id' => 1,
    'username' => 'john_doe',
    'role' => 'admin'
];

$result = Token::createToken($userData);

if ($result['code'] === 200) {
    $accessToken = $result['data']['access_token'];
    $tokenType = $result['data']['token_type']; // Bearer
    $expiresIn = $result['data']['expires_in']; // 7200秒
    
    return json([
        'code' => 200,
        'msg' => '登录成功',
        'data' => [
            'access_token' => $accessToken,
            'token_type' => $tokenType,
            'expires_in' => $expiresIn
        ]
    ]);
}
```

#### 同时生成 Access Token 和 Refresh Token

```php
// 第二个参数设为 true，同时返回 refresh_token
$result = Token::createToken($userData, true);

if ($result['code'] === 200) {
    return json([
        'code' => 200,
        'msg' => '登录成功',
        'data' => [
            'access_token' => $result['data']['access_token'],
            'refresh_token' => $result['data']['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => $result['data']['expires_in'], // access_token过期时间
            'refresh_expires_in' => $result['data']['refresh_expires_in'] // refresh_token过期时间
        ]
    ]);
}
```

#### 自定义过期时间

```php
// 第三个参数设置自定义过期时间（秒）
$customExpireTime = 3600; // 1小时
$result = Token::createToken($userData, true, $customExpireTime);
```

---

### 2. 验证 Token

#### 基础验证

```php
use think\Token;

// 从请求头获取token
$token = request()->header('Authorization');
$token = str_replace('Bearer ', '', $token);

// 验证token
$result = Token::verifyToken($token);

if ($result['code'] === 200) {
    // token有效，获取用户数据
    $userData = $result['data'];
    echo "用户ID: " . $userData['user_id'];
    echo "用户名: " . $userData['username'];
} else {
    // token无效
    echo "错误: " . $result['msg'];
}
```

#### 获取完整Payload（谨慎使用）

```php
// 第二个参数设为true，返回完整的JWT payload
$result = Token::verifyToken($token, true);

if ($result['code'] === 200) {
    $userData = $result['data']; // 用户数据
    $payload = $result['payload']; // 完整payload（包含exp, iat等）
}
```

---

### 3. 刷新 Token

#### 手动刷新

```php
use think\Token;

// 从请求中获取refresh_token
$refreshToken = request()->param('refresh_token');

// 使用refresh_token换取新的tokens
$result = Token::swapToken($refreshToken);

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
} else {
    return json([
        'code' => 401,
        'msg' => 'Token刷新失败: ' . $result['msg']
    ]);
}
```

#### 自动刷新（智能判断）

```php
use think\Token;

// 提供当前的access_token和refresh_token
$tokens = [
    'access_token' => request()->header('X-Access-Token'),
    'refresh_token' => request()->header('X-Refresh-Token')
];

$result = Token::autoSwapToken($tokens);

if ($result['code'] === 200) {
    if ($result['data']['status'] === 'valid') {
        // access_token仍然有效
        return json([
            'code' => 200,
            'msg' => 'Token有效',
            'data' => $result['data']['user_data']
        ]);
    } else {
        // Token已刷新，返回新tokens
        return json([
            'code' => 200,
            'msg' => 'Token已刷新',
            'data' => [
                'access_token' => $result['data']['access_token'],
                'refresh_token' => $result['data']['refresh_token'],
                'expires_in' => $result['data']['expires_in']
            ]
        ]);
    }
} else {
    // 刷新失败，需要重新登录
    return json([
        'code' => 401,
        'msg' => '请重新登录'
    ]);
}
```

---

### 4. 撤销 Token（加入黑名单）

```php
use think\Token;

// 用户登出时，将token加入黑名单
$token = request()->header('Authorization');
$token = str_replace('Bearer ', '', $token);

$success = Token::blacklistToken($token);

if ($success) {
    return json(['code' => 200, 'msg' => '登出成功']);
} else {
    return json(['code' => 500, 'msg' => '登出失败']);
}
```

---

## 🚀 高级功能

### 1. 创建中间件进行Token验证

创建文件 `app/middleware/AuthCheck.php`：

```php
<?php
namespace app\middleware;

use think\Token;
use think\Response;

class AuthCheck
{
    public function handle($request, \Closure $next)
    {
        // 获取token
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
        
        // 将用户信息注入到请求中
        $request->userInfo = $result['data'];
        
        return $next($request);
    }
}
```

在路由中使用：

```php
use app\middleware\AuthCheck;

// 需要认证的路由
Route::group(function () {
    Route::get('user/profile', 'UserController/profile');
    Route::post('user/update', 'UserController/update');
})->middleware(AuthCheck::class);
```

在控制器中获取用户信息：

```php
<?php
namespace app\api\controller;

use think\Request;

class UserController
{
    public function profile(Request $request)
    {
        // 获取中间件注入的用户信息
        $userInfo = $request->userInfo;
        
        return json([
            'code' => 200,
            'data' => [
                'user_id' => $userInfo['user_id'],
                'username' => $userInfo['username'],
                'role' => $userInfo['role']
            ]
        ]);
    }
}
```

---

### 2. 完整的登录控制器示例

```php
<?php
namespace app\api\controller;

use think\Request;
use think\Token;

class AuthController
{
    /**
     * 用户登录
     */
    public function login(Request $request)
    {
        $username = $request->param('username');
        $password = $request->param('password');
        
        // TODO: 验证用户名密码（这里简化处理）
        $user = $this->validateUser($username, $password);
        
        if (!$user) {
            return json(['code' => 400, 'msg' => '用户名或密码错误']);
        }
        
        // 准备用户数据（不要包含敏感信息如密码）
        $userData = [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role'],
            'nickname' => $user['nickname']
        ];
        
        // 生成tokens
        $result = Token::createToken($userData, true);
        
        if ($result['code'] === 200) {
            return json([
                'code' => 200,
                'msg' => '登录成功',
                'data' => $result['data']
            ]);
        }
        
        return json(['code' => 500, 'msg' => 'Token生成失败']);
    }
    
    /**
     * 刷新Token
     */
    public function refreshToken(Request $request)
    {
        $refreshToken = $request->param('refresh_token');
        
        if (empty($refreshToken)) {
            return json(['code' => 400, 'msg' => '请提供refresh_token']);
        }
        
        $result = Token::swapToken($refreshToken);
        
        return json($result);
    }
    
    /**
     * 用户登出
     */
    public function logout(Request $request)
    {
        $token = $request->header('Authorization');
        
        if (empty($token)) {
            return json(['code' => 400, 'msg' => '未提供token']);
        }
        
        $token = str_replace('Bearer ', '', $token);
        
        // 将token加入黑名单
        Token::blacklistToken($token);
        
        return json(['code' => 200, 'msg' => '登出成功']);
    }
    
    /**
     * 获取当前用户信息
     */
    public function getUserInfo(Request $request)
    {
        $token = $request->header('Authorization');
        $token = str_replace('Bearer ', '', $token);
        
        $result = Token::verifyToken($token);
        
        if ($result['code'] !== 200) {
            return json(['code' => 401, 'msg' => $result['msg']]);
        }
        
        return json([
            'code' => 200,
            'data' => $result['data']
        ]);
    }
    
    /**
     * 验证用户（示例方法）
     */
    private function validateUser(string $username, string $password): ?array
    {
        // TODO: 实际项目中应该从数据库验证
        // 这里仅作演示
        if ($username === 'admin' && $password === '123456') {
            return [
                'id' => 1,
                'username' => 'admin',
                'role' => 'admin',
                'nickname' => '管理员'
            ];
        }
        
        return null;
    }
}
```

---

### 3. 前端调用示例（JavaScript）

```javascript
// 登录
async function login(username, password) {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    });
    
    const result = await response.json();
    
    if (result.code === 200) {
        // 保存tokens
        localStorage.setItem('access_token', result.data.access_token);
        localStorage.setItem('refresh_token', result.data.refresh_token);
        return result.data;
    }
    
    throw new Error(result.msg);
}

// 使用token发起请求
async function fetchWithAuth(url, options = {}) {
    const accessToken = localStorage.getItem('access_token');
    
    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        }
    };
    
    const response = await fetch(url, { ...defaultOptions, ...options });
    
    // 如果token过期，尝试刷新
    if (response.status === 401) {
        const newTokens = await refreshToken();
        if (newTokens) {
            // 重试原请求
            defaultOptions.headers.Authorization = `Bearer ${newTokens.access_token}`;
            return fetch(url, { ...defaultOptions, ...options });
        }
    }
    
    return response;
}

// 刷新token
async function refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    
    const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ refresh_token: refreshToken })
    });
    
    const result = await response.json();
    
    if (result.code === 200) {
        localStorage.setItem('access_token', result.data.access_token);
        localStorage.setItem('refresh_token', result.data.refresh_token);
        return result.data;
    }
    
    // 刷新失败，跳转到登录页
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    window.location.href = '/login';
    return null;
}

// 登出
async function logout() {
    const accessToken = localStorage.getItem('access_token');
    
    await fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    });
    
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    window.location.href = '/login';
}
```

---

## ✨ 最佳实践

### 1. 安全建议

✅ **推荐做法：**
- 使用环境变量存储密钥，不要硬编码在代码中
- 密钥长度至少32个字符（16字节），建议使用64位十六进制字符串
- Access Token 设置较短的过期时间（1-2小时）
- Refresh Token 可以设置较长的过期时间（7-30天）
- 用户登出时将token加入黑名单
- HTTPS传输token
- 不要在日志中记录完整的token

❌ **避免做法：**
- 不要在前端存储敏感信息在token中
- 不要使用简单的密钥
- 不要将token暴露在URL中
- 不要忽略token过期检查

### 2. 性能优化

```php
// 批量验证时，可以考虑缓存验证结果
use think\facade\Cache;

function batchVerifyTokens(array $tokens): array
{
    $results = [];
    
    foreach ($tokens as $userId => $token) {
        $cacheKey = 'token_verify_' . md5($token);
        
        // 先从缓存获取
        $cached = Cache::get($cacheKey);
        if ($cached !== false) {
            $results[$userId] = $cached;
            continue;
        }
        
        // 验证并缓存结果（缓存5分钟）
        $result = \think\Token::verifyToken($token);
        Cache::set($cacheKey, $result, 300);
        
        $results[$userId] = $result;
    }
    
    return $results;
}
```

### 3. 错误处理

```php
try {
    $result = Token::createToken($userData, true);
    
    if ($result['code'] !== 200) {
        throw new \Exception($result['msg']);
    }
    
    // 处理成功逻辑
    
} catch (\InvalidArgumentException $e) {
    // 参数错误
    log_error('Token参数错误: ' . $e->getMessage());
    return json(['code' => 400, 'msg' => '参数错误']);
    
} catch (\Exception $e) {
    // 其他错误
    log_error('Token操作失败: ' . $e->getMessage());
    return json(['code' => 500, 'msg' => '系统错误']);
}
```

---

## ❓ 常见问题

### Q1: Token被篡改怎么办？

A: JWT自带签名验证机制，任何篡改都会导致签名验证失败。`verifyToken()` 方法会自动检测并返回错误。

### Q2: 如何实现单点登录（SSO）？

A: 可以使用相同的密钥在多个应用间共享token，或者实现中央认证服务。

### Q3: Refresh Token可以被重复使用吗？

A: 默认情况下，每次使用refresh token刷新后，旧的refresh token会被加入黑名单（通过`swapToken`的第三个参数控制）。这防止了重放攻击。

### Q4: 如何强制所有用户下线？

A: 更改密钥即可使所有现有token失效：

```php
// 生成新密钥
$newKey = Token::generateKey();
Token::setKey($newKey);

// 更新配置文件或环境变量
```

### Q5: Token太大怎么办？

A: 
- 减少token中存储的数据量
- 只存储用户ID，其他信息从数据库查询
- 使用更短的密钥（但不低于安全要求）

---

## 📝 更新日志

### v2.0.0 (当前版本)
- ✅ 修复了autoSwapToken的逻辑缺陷
- ✅ 增加了Token黑名单机制
- ✅ 增强了安全性（密钥验证、防重放攻击）
- ✅ 改进了错误处理和返回值
- ✅ 添加了类型提示和文档注释
- ✅ 优化了性能（初始化机制）
- ✅ 完善了测试用例

---

## 📞 技术支持

如有问题，请查看：
- ThinkPHP官方文档
- JWT规范 RFC 7519
- 插件源码注释
