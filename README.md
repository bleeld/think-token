# Think-Token - JWT Token 管理插件

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D7.4-green.svg)](https://php.net)
[![ThinkPHP](https://img.shields.io/badge/thinkphp-6.x-orange.svg)](https://www.thinkphp.cn)

一个为 ThinkPHP 6.x 设计的轻量级 JWT Token 管理插件，提供完整的认证解决方案。

## ✨ 特性

- 🔐 **安全的JWT实现** - 基于RFC 7519标准
- 🔄 **Token刷新机制** - Access Token + Refresh Token
- 🚫 **Token黑名单** - 支持撤销和强制下线
- ⚡ **高性能** - 智能缓存和初始化
- 🛡️ **防重放攻击** - Refresh Token一次性使用
- 📝 **完整文档** - 详细的使用指南和示例
- 🎯 **双模式支持** - Cookie模式和前端模式灵活切换

## 📦 安装

```bash
composer require bleeld/think-token
```

## 🚀 快速开始

### 1. 配置

在 `.env` 文件中添加：

```env
TOKEN_KEY=your_secure_64_character_hex_key_here
TOKEN_EXPIRE_TIME=7200
TOKEN_METHOD=HS256
TOKEN_COOKIE_MODE=0  # 0=前端模式(默认), 1=Cookie模式
```

生成安全密钥：
```bash
php -r "echo \think\Token::generateKey();"
```

### 2. 选择Token管理模式

Think-Token 支持两种模式，根据项目需求选择：

#### 模式一：Cookie模式（更安全）
```php
// config/token.php
'cookie_mode' => true,

// 后端自动设置HttpOnly Cookie，JavaScript无法访问
$result = Token::createToken($userData, true);
// Token已存储在Cookie中，浏览器自动携带
```

#### 模式二：前端模式（更灵活，默认）
```php
// config/token.php
'cookie_mode' => false,  // 或不配置

// Token返回给前端，前端自行存储
$result = Token::createToken($userData, true);
// 返回: {"access_token": "...", "refresh_token": "..."}
```

📚 详细对比和使用指南请查看：[双模式使用指南](DUAL_MODE_GUIDE.md)

### 3. 生成Token

```php
use think\Token;

// 用户登录成功后
$userData = [
    'user_id' => 1,
    'username' => 'john_doe',
    'role' => 'admin'
];

$result = Token::createToken($userData, true);

// 返回:
// {
//     "code": 200,
//     "msg": "success",
//     "data": {
//         "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
//         "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
//         "token_type": "Bearer",
//         "expires_in": 7200,
//         "refresh_expires_in": 86400
//     }
// }
```

### 4. 验证Token

```php
$token = request()->header('Authorization');
$token = str_replace('Bearer ', '', $token);

$result = Token::verifyToken($token);

if ($result['code'] === 200) {
    // Token有效
    $userId = $result['data']['user_id'];
} else {
    // Token无效
    echo $result['msg'];
}
```

### 5. 刷新Token

```php
$refreshToken = request()->param('refresh_token');

$result = Token::swapToken($refreshToken);

if ($result['code'] === 200) {
    // 获取新的tokens
    $newAccessToken = $result['data']['access_token'];
    $newRefreshToken = $result['data']['refresh_token'];
}
```

### 6. 撤销Token（登出）

```php
$token = request()->header('Authorization');
$token = str_replace('Bearer ', '', $token);

Token::blacklistToken($token);

// Token已被撤销，无法再使用
```

## 📖 文档

- [📚 完整使用指南](USAGE_EXAMPLE.md) - 详细的API文档和示例
- [🍪 双模式使用指南](DUAL_MODE_GUIDE.md) - Cookie模式 vs 前端模式详解
- [📊 优化报告](OPTIMIZATION_REPORT.md) - 本次优化的详细说明
- [🧪 测试脚本](test_token_quick.php) - 功能测试用例

## 🔧 API 参考

### 核心方法

| 方法 | 说明 | 参数 | 返回值 |
|------|------|------|--------|
| `createToken()` | 生成Token | `$data`, `$isRefreshToken`, `$expTime` | `array` |
| `verifyToken()` | 验证Token | `$token`, `$getData` | `array` |
| `swapToken()` | 刷新Token | `$refresh_token`, `$isAutoSet`, `$revokeOld` | `array` |
| `autoSwapToken()` | 自动刷新Token | `$tokens`, `$isAutoSet` | `array` |
| `blacklistToken()` | 撤销Token | `$token`, `$ttl` | `bool` |
| `generateKey()` | 生成密钥 | `$length` | `string` |

### 配置方法

| 方法 | 说明 | 参数 |
|------|------|------|
| `setKey()` | 设置密钥 | `$key` |
| `setExpireTime()` | 设置过期时间 | `$expire_time` |
| `setMethod()` | 设置加密方法 | `$method` |
| `setStorage()` | 设置存储驱动 | `$storage` |

## 🛡️ 安全建议

1. **使用强密钥** - 至少32个字符的十六进制字符串
2. **环境变量存储** - 不要在代码中硬编码密钥
3. **HTTPS传输** - 始终使用HTTPS传输Token
4. **合理设置过期时间** - Access Token建议1-2小时
5. **及时撤销Token** - 用户登出时调用`blacklistToken()`
6. **不要存储敏感信息** - Token中只存必要的用户标识

## 📝 更新日志

### v2.0.0 (2026-04-15)

**新增功能**:
- ✅ Token黑名单机制
- ✅ 增强的错误处理
- ✅ 完整的类型提示
- ✅ 防重放攻击保护

**修复问题**:
- ✅ 修复autoSwapToken逻辑缺陷
- ✅ 修复swapToken返回值问题
- ✅ 强化密钥验证规则
- ✅ 改进参数检查顺序

**性能优化**:
- ✅ 统一初始化机制
- ✅ 延长配置缓存时间
- ✅ 减少重复函数调用

**破坏性变更**:
- ⚠️ 最小密钥长度从16提升到32字符
- ⚠️ 某些方法的返回值结构有调整（更规范）

查看完整的 [优化报告](OPTIMIZATION_REPORT.md) 了解更多详情。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License - 查看 [LICENSE](LICENSE) 文件了解详情。

## 💡 示例项目

查看完整的使用示例：
- [登录控制器示例](USAGE_EXAMPLE.md#2-完整的登录控制器示例)
- [认证中间件](USAGE_EXAMPLE.md#1-创建中间件进行token验证)
- [前端调用示例](USAGE_EXAMPLE.md#3-前端调用示例javascript)

## 📞 支持

遇到问题？
1. 查看 [使用指南](USAGE_EXAMPLE.md)
2. 查看 [常见问题](USAGE_EXAMPLE.md#-常见问题)
3. 提交 [Issue](https://github.com/bleeld/think-token/issues)

---

**Made with ❤️ for ThinkPHP Community**
