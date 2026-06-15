# 参数使用说明和迁移指南

## 📋 参数变更说明

在 v2.0.0 版本中，我们对 Token 管理插件进行了双模式重构，部分参数发生了变化。

---

## 🔄 参数对比

### `swapToken()` 方法

#### 旧版本（v1.x）
```php
public static function swapToken(
    ?string $refresh_token = null, 
    bool $isAutoSet = false  // 用于控制是否自动设置Cookie
): array
```

#### 新版本（v2.0.0）
```php
public static function swapToken(
    ?string $refresh_token = null, 
    bool $isAutoSet = false,      // ⚠️ 已废弃，仅为向后兼容保留
    bool $revokeOld = true,       // ✅ 新增：是否撤销旧token
    ?bool $useCookie = null       // ✅ 新增：控制Cookie/前端模式
): array
```

**变更说明：**
- `$isAutoSet` 参数已被 `$useCookie` 取代
- 保留 `$isAutoSet` 是为了向后兼容，但不再起作用
- 推荐使用 `$useCookie` 参数来控制模式

---

### `autoSwapToken()` 方法

#### 旧版本（v1.x）
```php
public static function autoSwapToken(
    ?array $tokens = null, 
    bool $isAutoSet = false  // 用于控制是否自动设置Cookie
): array
```

#### 新版本（v2.0.0）
```php
public static function autoSwapToken(
    ?array $tokens = null, 
    ?bool $useCookie = null  // ✅ 替代了 isAutoSet
): array
```

**变更说明：**
- `$isAutoSet` 参数已被移除
- 使用 `$useCookie` 参数来控制模式
- 这是一个破坏性变更，但影响很小（因为该参数原本就没被实际使用）

---

## 💡 为什么这样设计？

### 问题

在双模式设计中，我们需要一个清晰的参数来控制是使用 **Cookie模式** 还是 **前端模式**。原来的 `$isAutoSet` 参数语义不明确：
- `isAutoSet = true` 是什么意思？
- 它和 Cookie 模式有什么关系？
- 在前端模式下这个参数有意义吗？

### 解决方案

引入明确的 `$useCookie` 参数：
- `true` = 使用 Cookie 模式（后端设置 HttpOnly Cookie）
- `false` = 使用前端模式（返回 token 给前端）
- `null` = 使用全局配置

这样语义更清晰，代码更易理解。

---

## 📝 使用示例

### 1. swapToken() 方法

#### ❌ 旧写法（不推荐）
```php
// 旧代码仍然可以运行，但 isAutoSet 参数不起作用
$result = Token::swapToken($refreshToken, true);
```

#### ✅ 新写法（推荐）

**前端模式：**
```php
// 明确指定使用前端模式
$result = Token::swapToken($refreshToken, false, true, false);
// 或者省略后面的参数，使用默认值
$result = Token::swapToken($refreshToken);
```

**Cookie模式：**
```php
// 明确指定使用Cookie模式
$result = Token::swapToken($refreshToken, false, true, true);
```

**使用全局配置：**
```php
// 不指定 useCookie，使用配置文件中的 cookie_mode
$result = Token::swapToken($refreshToken, false, true);
```

---

### 2. autoSwapToken() 方法

#### ❌ 旧写法（会报错）
```php
// v2.0.0 中 isAutoSet 参数已被移除
$result = Token::autoSwapToken($tokens, true);  // ⚠️ 参数数量错误
```

#### ✅ 新写法（推荐）

**前端模式：**
```php
// 传入tokens数组，指定前端模式
$result = Token::autoSwapToken($tokens, false);
```

**Cookie模式：**
```php
// Cookie模式下不需要传tokens，会自动从Cookie读取
$result = Token::autoSwapToken(null, true);
```

**使用全局配置：**
```php
// 不指定模式，使用配置文件中的 cookie_mode
$result = Token::autoSwapToken($tokens);
```

---

## 🔧 迁移指南

### 如果你的项目正在使用 v1.x

#### 步骤1：更新调用代码

**swapToken 调用：**

```php
// 之前
Token::swapToken($refreshToken, true);

// 之后 - 方案A：保持简单（推荐）
Token::swapToken($refreshToken);  // 使用默认值和全局配置

// 之后 - 方案B：明确指定模式
Token::swapToken($refreshToken, false, true, false);  // 前端模式
Token::swapToken($refreshToken, false, true, true);   // Cookie模式
```

**autoSwapToken 调用：**

```php
// 之前
Token::autoSwapToken($tokens, true);

// 之后 - 方案A：保持简单（推荐）
Token::autoSwapToken($tokens);  // 使用全局配置

// 之后 - 方案B：明确指定模式
Token::autoSwapToken($tokens, false);  // 前端模式
Token::autoSwapToken(null, true);      // Cookie模式
```

#### 步骤2：更新配置文件

```php
// config/token.php
return [
    // ... 其他配置 ...
    
    // 添加 cookie_mode 配置
    'cookie_mode' => false,  // false=前端模式, true=Cookie模式
];
```

或在 `.env` 中：
```env
TOKEN_COOKIE_MODE=0  # 0=前端模式, 1=Cookie模式
```

#### 步骤3：测试验证

```bash
cd vendor/bleeld/think-token
php test_standalone.php
```

---

### 如果是新项目

直接使用新版本的推荐写法即可，无需考虑兼容性。

---

## 📊 参数优先级

当多个地方都配置了模式时，优先级如下：

```
方法参数 ($useCookie) > 全局配置 (config/token.php) > 环境变量 (.env) > 默认值 (false)
```

**示例：**

```php
// .env 文件
TOKEN_COOKIE_MODE=1  // 全局设置为Cookie模式

// config/token.php
'cookie_mode' => false,  // 覆盖环境变量，设置为前端模式

// 代码调用
Token::createToken($data, true, null, true);  // 方法参数覆盖配置，使用Cookie模式
```

---

## ❓ 常见问题

### Q1: 我之前的代码使用了 `isAutoSet` 参数，升级后会报错吗？

**A:** 
- `swapToken()`: 不会报错，参数仍然保留（虽然不起作用）
- `autoSwapToken()`: 会报错，因为参数已被移除

**解决方案：** 移除 `autoSwapToken()` 的第二个参数，改用 `$useCookie`。

---

### Q2: 为什么不直接删除 `isAutoSet` 参数？

**A:** 为了向后兼容。如果删除 `swapToken()` 中的 `$isAutoSet` 参数，所有调用这个方法的地方都需要修改参数位置，这会造成更大的破坏。

---

### Q3: `$useCookie = null` 是什么意思？

**A:** 表示使用全局配置。系统会从 `config('token.cookie_mode')` 读取配置。如果配置也不存在，则默认为 `false`（前端模式）。

---

### Q4: 我应该使用哪种模式？

**A:** 
- **传统Web应用**（多页、SSR）→ Cookie模式
- **前后端分离**（SPA、API）→ 前端模式
- **不确定** → 先用前端模式，更灵活

详细对比请查看 [MODE_COMPARISON.md](MODE_COMPARISON.md)

---

### Q5: 可以在运行时动态切换模式吗？

**A:** 可以！通过 `$useCookie` 参数：

```php
// 根据设备类型动态选择
$isMobile = request()->isMobile();
$useCookie = !$isMobile;  // PC用Cookie，移动端用前端

$result = Token::createToken($data, true, null, $useCookie);
```

---

## 🎯 最佳实践

### 1. 明确指定模式（推荐）

```php
// 好的做法：明确指定模式
Token::createToken($data, true, null, false);  // 前端模式
Token::swapToken($token, false, true, false);  // 前端模式
```

### 2. 使用全局配置

```php
// config/token.php
'cookie_mode' => false,  // 统一配置

// 代码中不需要每次都指定
Token::createToken($data, true);  // 自动使用全局配置
```

### 3. 避免混用

```php
// ❌ 不好的做法：混用不同模式
Token::createToken($data, true, null, false);  // 前端模式
Token::swapToken($token, false, true, true);   // Cookie模式

// ✅ 好的做法：保持一致
$mode = false;  // 统一使用前端模式
Token::createToken($data, true, null, $mode);
Token::swapToken($token, false, true, $mode);
```

---

## 📚 相关文档

- [双模式使用指南](DUAL_MODE_GUIDE.md) - 详细的使用方法
- [模式对比](MODE_COMPARISON.md) - 两种模式的对比
- [完整示例](USAGE_EXAMPLE.md) - 完整的代码示例
- [优化报告](OPTIMIZATION_REPORT.md) - 版本变更详情

---

## 🔄 版本历史

### v2.0.0 (2026-04-15)
- ✅ 新增 `$useCookie` 参数
- ⚠️ `autoSwapToken()` 移除 `$isAutoSet` 参数
- ⚠️ `swapToken()` 标记 `$isAutoSet` 为废弃
- ✅ 保持向后兼容（`swapToken` 仍接受旧参数）

### v1.x
- 使用 `$isAutoSet` 参数控制Cookie设置

---

**最后更新**: 2026-04-15  
**适用版本**: v2.0.0+
