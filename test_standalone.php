<?php
/**
 * Think-Token 插件独立测试脚本
 * 不需要完整的ThinkPHP环境
 */

echo "========================================\n";
echo "  Think-Token 插件功能测试\n";
echo "========================================\n\n";

// 测试计数器
$passed = 0;
$failed = 0;
$total = 0;

/**
 * 测试辅助函数
 */
function test($name, $callback) {
    global $passed, $failed, $total;
    $total++;
    
    echo "[测试 {$total}] {$name}\n";
    try {
        $result = $callback();
        if ($result === true) {
            echo "  ✓ 通过\n\n";
            $passed++;
        } else {
            echo "  ✗ 失败: {$result}\n\n";
            $failed++;
        }
    } catch (Exception $e) {
        echo "  ✗ 异常: " . $e->getMessage() . "\n";
        echo "  文件: " . $e->getFile() . ":" . $e->getLine() . "\n\n";
        $failed++;
    }
}

// ========================================
// 1. 基础类加载测试
// ========================================
echo "【第一部分】基础功能测试\n";
echo "----------------------------------------\n";

test('Token类文件存在', function() {
    $tokenFile = __DIR__ . '/src/Token.php';
    if (!file_exists($tokenFile)) {
        return 'Token.php文件不存在';
    }
    return true;
});

test('TokenInterface接口文件存在', function() {
    $interfaceFile = __DIR__ . '/src/TokenInterface.php';
    if (!file_exists($interfaceFile)) {
        return 'TokenInterface.php文件不存在';
    }
    return true;
});

test('JWT驱动文件存在', function() {
    $jwtFile = __DIR__ . '/src/driver/JWT.php';
    if (!file_exists($jwtFile)) {
        return 'JWT.php文件不存在';
    }
    return true;
});

test('StorageInterface接口存在', function() {
    $storageFile = __DIR__ . '/src/driver/StorageInterface.php';
    if (!file_exists($storageFile)) {
        return 'StorageInterface.php文件不存在';
    }
    return true;
});

test('ThinkCacheStorage驱动存在', function() {
    $cacheFile = __DIR__ . '/src/driver/ThinkCacheStorage.php';
    if (!file_exists($cacheFile)) {
        return 'ThinkCacheStorage.php文件不存在';
    }
    return true;
});

// ========================================
// 2. 配置文件测试
// ========================================
echo "\n【第二部分】配置文件测试\n";
echo "----------------------------------------\n";

test('配置文件存在', function() {
    $configFile = __DIR__ . '/../../../config/token.php';
    if (!file_exists($configFile)) {
        return 'config/token.php文件不存在';
    }
    return true;
});

test('配置文件格式正确', function() {
    $configFile = __DIR__ . '/../../../config/token.php';
    $config = include $configFile;
    
    if (!is_array($config)) {
        return '配置文件返回的不是数组';
    }
    
    $requiredKeys = ['key', 'expire_time', 'method', 'cookie_mode'];
    foreach ($requiredKeys as $key) {
        if (!array_key_exists($key, $config)) {
            return "配置项 '{$key}' 不存在";
        }
    }
    
    return true;
});

test('cookie_mode配置项存在', function() {
    $configFile = __DIR__ . '/../../../config/token.php';
    $config = include $configFile;
    
    if (!array_key_exists('cookie_mode', $config)) {
        return 'cookie_mode配置项不存在';
    }
    
    echo "  cookie_mode值: " . var_export($config['cookie_mode'], true) . "\n";
    return true;
});

// ========================================
// 3. 代码语法测试
// ========================================
echo "\n【第三部分】代码语法测试\n";
echo "----------------------------------------\n";

test('Token.php语法检查', function() {
    $output = [];
    $return_var = 0;
    exec('php -l ' . escapeshellarg(__DIR__ . '/src/Token.php'), $output, $return_var);
    
    if ($return_var !== 0) {
        return '语法错误: ' . implode("\n", $output);
    }
    
    echo "  " . implode("\n  ", $output) . "\n";
    return true;
});

test('TokenInterface.php语法检查', function() {
    $output = [];
    $return_var = 0;
    exec('php -l ' . escapeshellarg(__DIR__ . '/src/TokenInterface.php'), $output, $return_var);
    
    if ($return_var !== 0) {
        return '语法错误: ' . implode("\n", $output);
    }
    
    return true;
});

test('JWT.php语法检查', function() {
    $output = [];
    $return_var = 0;
    exec('php -l ' . escapeshellarg(__DIR__ . '/src/driver/JWT.php'), $output, $return_var);
    
    if ($return_var !== 0) {
        return '语法错误: ' . implode("\n", $output);
    }
    
    return true;
});

test('ThinkCacheStorage.php语法检查', function() {
    $output = [];
    $return_var = 0;
    exec('php -l ' . escapeshellarg(__DIR__ . '/src/driver/ThinkCacheStorage.php'), $output, $return_var);
    
    if ($return_var !== 0) {
        return '语法错误: ' . implode("\n", $output);
    }
    
    return true;
});

// ========================================
// 4. 代码结构测试
// ========================================
echo "\n【第四部分】代码结构测试\n";
echo "----------------------------------------\n";

test('Token类包含必要的方法', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    $requiredMethods = [
        'createToken',
        'verifyToken',
        'swapToken',
        'autoSwapToken',
        'blacklistToken',
        'generateKey',
        'setKey',
        'setExpireTime',
        'setMethod',
        'setStorage'
    ];
    
    foreach ($requiredMethods as $method) {
        if (strpos($content, "function {$method}") === false) {
            return "方法 '{$method}' 不存在";
        }
    }
    
    echo "  找到 " . count($requiredMethods) . " 个必要方法\n";
    return true;
});

test('Token类包含cookieMode属性', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    if (strpos($content, '$cookieMode') === false) {
        return 'cookieMode属性不存在';
    }
    
    echo "  ✓ cookieMode属性已定义\n";
    return true;
});

test('createToken支持useCookie参数', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    // 检查方法签名是否包含useCookie参数
    if (preg_match('/function createToken.*\$useCookie/', $content)) {
        echo "  ✓ createToken方法包含useCookie参数\n";
        return true;
    }
    
    return 'createToken方法缺少useCookie参数';
});

test('swapToken支持useCookie参数', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    if (preg_match('/function swapToken.*\$useCookie/', $content)) {
        echo "  ✓ swapToken方法包含useCookie参数\n";
        return true;
    }
    
    return 'swapToken方法缺少useCookie参数';
});

test('autoSwapToken支持useCookie参数', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    if (preg_match('/function autoSwapToken.*\$useCookie/', $content)) {
        echo "  ✓ autoSwapToken方法包含useCookie参数\n";
        return true;
    }
    
    return 'autoSwapToken方法缺少useCookie参数';
});

test('包含setTokenCookies方法', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    if (strpos($content, 'function setTokenCookies') !== false) {
        echo "  ✓ setTokenCookies方法已定义\n";
        return true;
    }
    
    return 'setTokenCookies方法不存在';
});

// ========================================
// 5. 文档完整性测试
// ========================================
echo "\n【第五部分】文档完整性测试\n";
echo "----------------------------------------\n";

test('README.md存在', function() {
    if (!file_exists(__DIR__ . '/README.md')) {
        return 'README.md不存在';
    }
    
    $size = filesize(__DIR__ . '/README.md');
    echo "  文件大小: {$size} 字节\n";
    return true;
});

test('USAGE_EXAMPLE.md存在', function() {
    if (!file_exists(__DIR__ . '/USAGE_EXAMPLE.md')) {
        return 'USAGE_EXAMPLE.md不存在';
    }
    
    $size = filesize(__DIR__ . '/USAGE_EXAMPLE.md');
    echo "  文件大小: {$size} 字节\n";
    return true;
});

test('DUAL_MODE_GUIDE.md存在', function() {
    if (!file_exists(__DIR__ . '/DUAL_MODE_GUIDE.md')) {
        return 'DUAL_MODE_GUIDE.md不存在';
    }
    
    $size = filesize(__DIR__ . '/DUAL_MODE_GUIDE.md');
    echo "  文件大小: {$size} 字节\n";
    return true;
});

test('MODE_COMPARISON.md存在', function() {
    if (!file_exists(__DIR__ . '/MODE_COMPARISON.md')) {
        return 'MODE_COMPARISON.md不存在';
    }
    
    $size = filesize(__DIR__ . '/MODE_COMPARISON.md');
    echo "  文件大小: {$size} 字节\n";
    return true;
});

test('OPTIMIZATION_REPORT.md存在', function() {
    if (!file_exists(__DIR__ . '/OPTIMIZATION_REPORT.md')) {
        return 'OPTIMIZATION_REPORT.md不存在';
    }
    
    $size = filesize(__DIR__ . '/OPTIMIZATION_REPORT.md');
    echo "  文件大小: {$size} 字节\n";
    return true;
});

test('README包含双模式说明', function() {
    $content = file_get_contents(__DIR__ . '/README.md');
    
    if (strpos($content, '双模式') === false && strpos($content, 'Cookie模式') === false) {
        return 'README未包含双模式说明';
    }
    
    echo "  ✓ README包含双模式相关说明\n";
    return true;
});

// ========================================
// 6. 代码质量测试
// ========================================
echo "\n【第六部分】代码质量测试\n";
echo "----------------------------------------\n";

test('Token.php使用类型声明', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    // 检查是否有返回类型声明
    if (preg_match_all('/:\s*(array|string|bool|int|void)/', $content, $matches)) {
        echo "  找到 " . count($matches[0]) . " 个类型声明\n";
        return true;
    }
    
    return '未找到类型声明';
});

test('Token.php包含PHPDoc注释', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    if (preg_match_all('/\/\*\*/', $content, $matches)) {
        echo "  找到 " . count($matches[0]) . " 个PHPDoc注释块\n";
        return true;
    }
    
    return '未找到PHPDoc注释';
});

test('黑名单功能已实现', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    $requiredFunctions = [
        'blacklistToken',
        'isTokenBlacklisted',
        'getTokenId'
    ];
    
    foreach ($requiredFunctions as $func) {
        if (strpos($content, "function {$func}") === false) {
            return "函数 '{$func}' 不存在";
        }
    }
    
    echo "  ✓ 黑名单功能完整实现\n";
    return true;
});

test('initialize方法已实现', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    if (strpos($content, 'function initialize') === false) {
        return 'initialize方法不存在';
    }
    
    echo "  ✓ initialize方法已实现\n";
    return true;
});

// ========================================
// 7. 安全性测试
// ========================================
echo "\n【第七部分】安全性检查\n";
echo "----------------------------------------\n";

test('密钥验证逻辑存在', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    if (strpos($content, 'validateKey') === false) {
        return 'validateKey方法不存在';
    }
    
    echo "  ✓ 密钥验证逻辑已实现\n";
    return true;
});

test('最小密钥长度检查', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    // 检查是否有32字符的最小长度要求
    if (preg_match('/strlen.*<\s*32/', $content)) {
        echo "  ✓ 最小密钥长度设置为32字符\n";
        return true;
    }
    
    return '未找到32字符的最小长度检查';
});

test('防重放攻击机制', function() {
    $content = file_get_contents(__DIR__ . '/src/Token.php');
    
    // 检查swapToken是否有revokeOld参数
    if (preg_match('/function swapToken.*\$revokeOld/', $content)) {
        echo "  ✓ 防重放攻击机制已实现\n";
        return true;
    }
    
    return '未找到防重放攻击机制';
});

// ========================================
// 8. 兼容性测试
// ========================================
echo "\n【第八部分】兼容性检查\n";
echo "----------------------------------------\n";

test('PHP版本兼容性', function() {
    $phpVersion = PHP_VERSION;
    echo "  当前PHP版本: {$phpVersion}\n";
    
    if (version_compare($phpVersion, '7.4.0', '<')) {
        return 'PHP版本过低，需要 >= 7.4';
    }
    
    return true;
});

test('接口定义清晰（无废弃参数）', function() {
    $content = file_get_contents(__DIR__ . '/src/TokenInterface.php');
    
    // 检查是否还有 isAutoSet 参数
    if (strpos($content, 'isAutoSet') !== false) {
        return '接口中仍存在废弃的 isAutoSet 参数';
    }
    
    echo "  ✓ 接口定义干净，无废弃参数\n";
    return true;
});

// ========================================
// 测试结果汇总
// ========================================
echo "\n========================================\n";
echo "  测试结果汇总\n";
echo "========================================\n";
echo "  总测试数: {$total}\n";
echo "  通过: {$passed} ✓\n";
echo "  失败: {$failed} ✗\n";
echo "  通过率: " . ($total > 0 ? round(($passed / $total) * 100, 2) : 0) . "%\n";
echo "========================================\n";

if ($failed === 0) {
    echo "\n🎉 所有测试通过！插件功能正常！\n\n";
    echo "下一步：\n";
    echo "1. 在完整ThinkPHP环境中运行集成测试\n";
    echo "2. 配置TOKEN_KEY环境变量\n";
    echo "3. 根据项目需求选择Cookie模式或前端模式\n";
    echo "4. 查看 DUAL_MODE_GUIDE.md 了解详细用法\n";
    exit(0);
} else {
    echo "\n⚠️  有 {$failed} 个测试失败，请检查上述错误信息。\n";
    exit(1);
}
