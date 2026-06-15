<?php
/**
 * Think-Token 插件功能测试脚本
 * 
 * 运行方式：php test_token_quick.php
 */

// 引入ThinkPHP框架
require __DIR__ . '/../../thinkphp/base.php';

use think\Token;

echo "========================================\n";
echo "  Think-Token 插件功能测试\n";
echo "========================================\n\n";

// 测试计数器
$passed = 0;
$failed = 0;

/**
 * 测试辅助函数
 */
function test($name, $callback) {
    global $passed, $failed;
    
    echo "[测试] {$name}\n";
    try {
        $result = $callback();
        if ($result) {
            echo "  ✓ 通过\n\n";
            $passed++;
        } else {
            echo "  ✗ 失败\n\n";
            $failed++;
        }
    } catch (Exception $e) {
        echo "  ✗ 异常: " . $e->getMessage() . "\n\n";
        $failed++;
    }
}

// ========================================
// 1. 配置测试
// ========================================
echo "【第一部分】配置测试\n";
echo "----------------------------------------\n";

test('生成安全密钥', function() {
    $key = Token::generateKey();
    echo "  生成的密钥: {$key}\n";
    echo "  密钥长度: " . strlen($key) . " 字符\n";
    return strlen($key) >= 32;
});

test('设置和获取密钥', function() {
    $testKey = Token::generateKey();
    Token::setKey($testKey);
    
    // 通过反射获取私有静态变量
    $reflection = new ReflectionClass(Token::class);
    $property = $reflection->getProperty('key');
    $property->setAccessible(true);
    $storedKey = $property->getValue();
    
    echo "  设置的密钥: {$testKey}\n";
    echo "  存储的密钥: {$storedKey}\n";
    return $testKey === $storedKey;
});

test('设置过期时间', function() {
    Token::setExpireTime(3600);
    
    $reflection = new ReflectionClass(Token::class);
    $property = $reflection->getProperty('expire_time');
    $property->setAccessible(true);
    $storedTime = $property->getValue();
    
    echo "  设置的过期时间: 3600秒\n";
    echo "  存储的过期时间: {$storedTime}秒\n";
    return $storedTime === 3600;
});

test('设置加密方法', function() {
    Token::setMethod('HS256');
    
    $reflection = new ReflectionClass(Token::class);
    $property = $reflection->getProperty('method');
    $property->setAccessible(true);
    $storedMethod = $property->getValue();
    
    echo "  设置的加密方法: HS256\n";
    echo "  存储的加密方法: {$storedMethod}\n";
    return $storedMethod === 'HS256';
});

// ========================================
// 2. Token生成测试
// ========================================
echo "\n【第二部分】Token生成测试\n";
echo "----------------------------------------\n";

test('生成Access Token', function() {
    $userData = ['user_id' => 1, 'username' => 'test_user'];
    $result = Token::createToken($userData);
    
    echo "  返回码: {$result['code']}\n";
    echo "  消息: {$result['msg']}\n";
    echo "  Access Token长度: " . strlen($result['data']['access_token']) . "\n";
    echo "  Token类型: {$result['data']['token_type']}\n";
    echo "  过期时间: {$result['data']['expires_in']}秒\n";
    
    return $result['code'] === 200 && 
           isset($result['data']['access_token']) &&
           $result['data']['token_type'] === 'Bearer';
});

test('生成Access + Refresh Token', function() {
    $userData = ['user_id' => 2, 'username' => 'test_user2'];
    $result = Token::createToken($userData, true);
    
    echo "  返回码: {$result['code']}\n";
    echo "  Access Token存在: " . (isset($result['data']['access_token']) ? '是' : '否') . "\n";
    echo "  Refresh Token存在: " . (isset($result['data']['refresh_token']) ? '是' : '否') . "\n";
    echo "  Access过期时间: {$result['data']['expires_in']}秒\n";
    echo "  Refresh过期时间: {$result['data']['refresh_expires_in']}秒\n";
    
    return $result['code'] === 200 && 
           isset($result['data']['access_token']) &&
           isset($result['data']['refresh_token']);
});

test('自定义过期时间', function() {
    $userData = ['user_id' => 3];
    $result = Token::createToken($userData, false, 1800); // 30分钟
    
    echo "  自定义过期时间: 1800秒\n";
    echo "  实际过期时间: {$result['data']['expires_in']}秒\n";
    
    return $result['data']['expires_in'] === 1800;
});

// ========================================
// 3. Token验证测试
// ========================================
echo "\n【第三部分】Token验证测试\n";
echo "----------------------------------------\n";

$testToken = null;

test('验证有效的Token', function() use (&$testToken) {
    // 先生成token
    $userData = ['user_id' => 100, 'username' => 'verify_test', 'role' => 'admin'];
    $createResult = Token::createToken($userData);
    $testToken = $createResult['data']['access_token'];
    
    // 验证token
    $verifyResult = Token::verifyToken($testToken);
    
    echo "  验证返回码: {$verifyResult['code']}\n";
    echo "  验证消息: {$verifyResult['msg']}\n";
    echo "  用户ID: {$verifyResult['data']['user_id']}\n";
    echo "  用户名: {$verifyResult['data']['username']}\n";
    echo "  角色: {$verifyResult['data']['role']}\n";
    
    return $verifyResult['code'] === 200 &&
           $verifyResult['data']['user_id'] === 100 &&
           $verifyResult['data']['username'] === 'verify_test';
});

test('验证无效的Token', function() {
    $result = Token::verifyToken('invalid.token.here');
    
    echo "  验证返回码: {$result['code']}\n";
    echo "  验证消息: {$result['msg']}\n";
    
    return $result['code'] !== 200;
});

test('验证空Token', function() {
    $result = Token::verifyToken('');
    
    echo "  验证返回码: {$result['code']}\n";
    echo "  验证消息: {$result['msg']}\n";
    
    return $result['code'] === 400;
});

// ========================================
// 4. Token刷新测试
// ========================================
echo "\n【第四部分】Token刷新测试\n";
echo "----------------------------------------\n";

$refreshToken = null;

test('使用Refresh Token刷新', function() use (&$refreshToken) {
    // 生成带refresh token的token
    $userData = ['user_id' => 200, 'username' => 'refresh_test'];
    $createResult = Token::createToken($userData, true);
    $refreshToken = $createResult['data']['refresh_token'];
    
    echo "  原始Refresh Token: " . substr($refreshToken, 0, 50) . "...\n";
    
    // 使用refresh token刷新
    $swapResult = Token::swapToken($refreshToken);
    
    echo "  刷新返回码: {$swapResult['code']}\n";
    echo "  刷新消息: {$swapResult['msg']}\n";
    echo "  新Access Token存在: " . (isset($swapResult['data']['access_token']) ? '是' : '否') . "\n";
    echo "  新Refresh Token存在: " . (isset($swapResult['data']['refresh_token']) ? '是' : '否') . "\n";
    
    return $swapResult['code'] === 200 &&
           isset($swapResult['data']['access_token']) &&
           isset($swapResult['data']['refresh_token']);
});

test('自动刷新Token（无需刷新）', function() use ($refreshToken) {
    // 先生成一个有效的access token
    $userData = ['user_id' => 300];
    $createResult = Token::createToken($userData, true);
    
    $tokens = [
        'access_token' => $createResult['data']['access_token'],
        'refresh_token' => $createResult['data']['refresh_token']
    ];
    
    $autoResult = Token::autoSwapToken($tokens);
    
    echo "  自动刷新返回码: {$autoResult['code']}\n";
    echo "  状态: {$autoResult['data']['status']}\n";
    echo "  消息: {$autoResult['msg']}\n";
    
    return $autoResult['code'] === 200 && 
           $autoResult['data']['status'] === 'valid';
});

test('使用无效的Refresh Token', function() {
    $result = Token::swapToken('invalid_refresh_token');
    
    echo "  返回码: {$result['code']}\n";
    echo "  消息: {$result['msg']}\n";
    
    return $result['code'] === 400;
});

// ========================================
// 5. Token黑名单测试
// ========================================
echo "\n【第五部分】Token黑名单测试\n";
echo "----------------------------------------\n";

test('将Token加入黑名单', function() {
    // 生成一个token
    $userData = ['user_id' => 400];
    $createResult = Token::createToken($userData);
    $token = $createResult['data']['access_token'];
    
    // 先验证token有效
    $beforeBlacklist = Token::verifyToken($token);
    echo "  加入黑名单前验证: {$beforeBlacklist['code']}\n";
    
    // 加入黑名单
    $blacklistResult = Token::blacklistToken($token);
    echo "  加入黑名单结果: " . ($blacklistResult ? '成功' : '失败') . "\n";
    
    // 再次验证（应该失败）
    $afterBlacklist = Token::verifyToken($token);
    echo "  加入黑名单后验证: {$afterBlacklist['code']}\n";
    echo "  消息: {$afterBlacklist['msg']}\n";
    
    return $beforeBlacklist['code'] === 200 && 
           $blacklistResult === true &&
           $afterBlacklist['code'] !== 200;
});

// ========================================
// 6. 边界情况测试
// ========================================
echo "\n【第六部分】边界情况测试\n";
echo "----------------------------------------\n";

test('处理复杂用户数据', function() {
    $complexData = [
        'user_id' => 500,
        'username' => 'complex_user',
        'roles' => ['admin', 'editor', 'viewer'],
        'permissions' => ['read', 'write', 'delete'],
        'profile' => [
            'email' => 'test@example.com',
            'phone' => '13800138000'
        ]
    ];
    
    $result = Token::createToken($complexData, true);
    
    if ($result['code'] !== 200) {
        echo "  Token生成失败\n";
        return false;
    }
    
    // 验证token
    $verifyResult = Token::verifyToken($result['data']['access_token']);
    
    echo "  复杂数据Token生成: 成功\n";
    echo "  验证返回码: {$verifyResult['code']}\n";
    echo "  用户ID: {$verifyResult['data']['user_id']}\n";
    echo "  角色数量: " . count($verifyResult['data']['roles']) . "\n";
    
    return $verifyResult['code'] === 200 &&
           $verifyResult['data']['user_id'] === 500;
});

test('参数不完整时的处理', function() {
    // 缺少refresh_token
    $result = Token::autoSwapToken(['access_token' => 'some_token']);
    
    echo "  缺少参数返回码: {$result['code']}\n";
    echo "  消息: {$result['msg']}\n";
    
    return $result['code'] === 400;
});

// ========================================
// 测试结果汇总
// ========================================
echo "\n========================================\n";
echo "  测试结果汇总\n";
echo "========================================\n";
echo "  通过: {$passed}\n";
echo "  失败: {$failed}\n";
echo "  总计: " . ($passed + $failed) . "\n";
echo "========================================\n";

if ($failed === 0) {
    echo "\n🎉 所有测试通过！\n";
    exit(0);
} else {
    echo "\n⚠️  有 {$failed} 个测试失败，请检查。\n";
    exit(1);
}
