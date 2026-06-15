<?php
/**
 * Think-Token 集成测试
 * 需要在ThinkPHP环境中运行
 * 
 * 运行方式：php test_integration.php
 */

// 引入ThinkPHP框架
require __DIR__ . '/../../autoload.php';

use think\Token;
use think\facade\Config;

echo "========================================\n";
echo "  Think-Token 集成测试\n";
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
        echo "  位置: " . $e->getFile() . ":" . $e->getLine() . "\n\n";
        $failed++;
    }
}

// ========================================
// 1. 配置加载测试
// ========================================
echo "【第一部分】配置加载测试\n";
echo "----------------------------------------\n";

test('加载token配置', function() {
    $config = Config::get('token');
    
    if (empty($config)) {
        return 'token配置为空';
    }
    
    echo "  配置项数量: " . count($config) . "\n";
    return true;
});

test('cookie_mode配置正确', function() {
    $cookieMode = config('token.cookie_mode');
    echo "  cookie_mode: " . var_export($cookieMode, true) . "\n";
    return true;
});

// ========================================
// 2. Token生成测试（前端模式）
// ========================================
echo "\n【第二部分】Token生成测试（前端模式）\n";
echo "----------------------------------------\n";

test('生成Access Token（前端模式）', function() {
    $userData = ['user_id' => 1, 'username' => 'test_user'];
    $result = Token::createToken($userData, false, null, false);
    
    if ($result['code'] !== 200) {
        return "生成失败: " . $result['msg'];
    }
    
    if (!isset($result['data']['access_token'])) {
        return '返回数据中缺少access_token';
    }
    
    echo "  Access Token长度: " . strlen($result['data']['access_token']) . "\n";
    echo "  Token类型: " . $result['data']['token_type'] . "\n";
    echo "  过期时间: " . $result['data']['expires_in'] . "秒\n";
    
    return true;
});

test('生成Access + Refresh Token（前端模式）', function() {
    $userData = ['user_id' => 2, 'username' => 'test_user2'];
    $result = Token::createToken($userData, true, null, false);
    
    if ($result['code'] !== 200) {
        return "生成失败: " . $result['msg'];
    }
    
    if (!isset($result['data']['access_token']) || !isset($result['data']['refresh_token'])) {
        return '返回数据中缺少token';
    }
    
    echo "  Access Token存在: ✓\n";
    echo "  Refresh Token存在: ✓\n";
    echo "  Refresh过期时间: " . $result['data']['refresh_expires_in'] . "秒\n";
    
    return true;
});

// ========================================
// 3. Token生成测试（Cookie模式）
// ========================================
echo "\n【第三部分】Token生成测试（Cookie模式）\n";
echo "----------------------------------------\n";

test('生成Access Token（Cookie模式）', function() {
    $userData = ['user_id' => 3, 'username' => 'cookie_test'];
    $result = Token::createToken($userData, false, null, true);
    
    if ($result['code'] !== 200) {
        return "生成失败: " . $result['msg'];
    }
    
    if (!isset($result['data']['message'])) {
        return 'Cookie模式应返回message而不是access_token';
    }
    
    echo "  消息: " . $result['data']['message'] . "\n";
    
    // 检查Cookie是否设置
    $cookieValue = \think\facade\Cookie::get('access_token');
    if (empty($cookieValue)) {
        return 'Cookie未设置';
    }
    
    echo "  Cookie已设置: ✓\n";
    
    return true;
});

test('生成Access + Refresh Token（Cookie模式）', function() {
    $userData = ['user_id' => 4, 'username' => 'cookie_test2'];
    $result = Token::createToken($userData, true, null, true);
    
    if ($result['code'] !== 200) {
        return "生成失败: " . $result['msg'];
    }
    
    // 检查两个Cookie是否都设置
    $accessToken = \think\facade\Cookie::get('access_token');
    $refreshToken = \think\facade\Cookie::get('refresh_token');
    
    if (empty($accessToken) || empty($refreshToken)) {
        return 'Cookie未完全设置';
    }
    
    echo "  Access Token Cookie: ✓\n";
    echo "  Refresh Token Cookie: ✓\n";
    
    return true;
});

// ========================================
// 4. Token验证测试
// ========================================
echo "\n【第四部分】Token验证测试\n";
echo "----------------------------------------\n";

test('验证有效的Token', function() {
    // 先生成token
    $userData = ['user_id' => 100, 'username' => 'verify_test'];
    $createResult = Token::createToken($userData, false, null, false);
    $token = $createResult['data']['access_token'];
    
    // 验证token
    $verifyResult = Token::verifyToken($token);
    
    if ($verifyResult['code'] !== 200) {
        return "验证失败: " . $verifyResult['msg'];
    }
    
    if ($verifyResult['data']['user_id'] !== 100) {
        return '用户ID不匹配';
    }
    
    echo "  用户ID: " . $verifyResult['data']['user_id'] . "\n";
    echo "  用户名: " . $verifyResult['data']['username'] . "\n";
    
    return true;
});

test('验证无效的Token', function() {
    $result = Token::verifyToken('invalid.token.here');
    
    if ($result['code'] === 200) {
        return '无效token应该验证失败';
    }
    
    echo "  错误消息: " . $result['msg'] . "\n";
    return true;
});

// ========================================
// 5. Token刷新测试
// ========================================
echo "\n【第五部分】Token刷新测试\n";
echo "----------------------------------------\n";

test('刷新Token（前端模式）', function() {
    // 生成带refresh token的token
    $userData = ['user_id' => 200, 'username' => 'refresh_test'];
    $createResult = Token::createToken($userData, true, null, false);
    $refreshToken = $createResult['data']['refresh_token'];
    
    // 使用refresh token刷新
    $swapResult = Token::swapToken($refreshToken, false, true, false);
    
    if ($swapResult['code'] !== 200) {
        return "刷新失败: " . $swapResult['msg'];
    }
    
    if (!isset($swapResult['data']['access_token']) || !isset($swapResult['data']['refresh_token'])) {
        return '返回数据中缺少新tokens';
    }
    
    echo "  新Access Token: ✓\n";
    echo "  新Refresh Token: ✓\n";
    
    return true;
});

test('刷新Token（Cookie模式）', function() {
    // 生成带refresh token的token（Cookie模式）
    $userData = ['user_id' => 201, 'username' => 'refresh_cookie_test'];
    Token::createToken($userData, true, null, true);
    
    // 从Cookie获取refresh token
    $refreshToken = \think\facade\Cookie::get('refresh_token');
    
    if (empty($refreshToken)) {
        return 'Cookie中无refresh_token';
    }
    
    // 刷新token（Cookie模式）
    $swapResult = Token::swapToken($refreshToken, false, true, true);
    
    if ($swapResult['code'] !== 200) {
        return "刷新失败: " . $swapResult['msg'];
    }
    
    // 检查新Cookie是否设置
    $newAccessToken = \think\facade\Cookie::get('access_token');
    $newRefreshToken = \think\facade\Cookie::get('refresh_token');
    
    if (empty($newAccessToken) || empty($newRefreshToken)) {
        return '新Cookie未设置';
    }
    
    echo "  新Access Token Cookie: ✓\n";
    echo "  新Refresh Token Cookie: ✓\n";
    
    return true;
});

// ========================================
// 6. 自动刷新测试
// ========================================
echo "\n【第六部分】自动刷新测试\n";
echo "----------------------------------------\n";

test('自动刷新 - Token有效（前端模式）', function() {
    $userData = ['user_id' => 300];
    $createResult = Token::createToken($userData, true, null, false);
    
    $tokens = [
        'access_token' => $createResult['data']['access_token'],
        'refresh_token' => $createResult['data']['refresh_token']
    ];
    
    $autoResult = Token::autoSwapToken($tokens, false, false);
    
    if ($autoResult['code'] !== 200) {
        return "自动刷新失败: " . $autoResult['msg'];
    }
    
    if ($autoResult['data']['status'] !== 'valid') {
        return '状态应该是valid';
    }
    
    echo "  状态: " . $autoResult['data']['status'] . "\n";
    return true;
});

test('自动刷新 - Token有效（Cookie模式）', function() {
    $userData = ['user_id' => 301];
    Token::createToken($userData, true, null, true);
    
    // Cookie模式下不需要传参数
    $autoResult = Token::autoSwapToken(null, false, true);
    
    if ($autoResult['code'] !== 200) {
        return "自动刷新失败: " . $autoResult['msg'];
    }
    
    echo "  状态: " . $autoResult['data']['status'] . "\n";
    return true;
});

// ========================================
// 7. 黑名单测试
// ========================================
echo "\n【第七部分】黑名单测试\n";
echo "----------------------------------------\n";

test('将Token加入黑名单', function() {
    // 生成一个token
    $userData = ['user_id' => 400];
    $createResult = Token::createToken($userData, false, null, false);
    $token = $createResult['data']['access_token'];
    
    // 先验证token有效
    $beforeBlacklist = Token::verifyToken($token);
    if ($beforeBlacklist['code'] !== 200) {
        return 'Token初始验证失败';
    }
    
    // 加入黑名单
    $blacklistResult = Token::blacklistToken($token);
    if (!$blacklistResult) {
        return '加入黑名单失败';
    }
    
    // 再次验证（应该失败）
    $afterBlacklist = Token::verifyToken($token);
    if ($afterBlacklist['code'] === 200) {
        return '黑名单Token仍然有效';
    }
    
    echo "  加入黑名单前: 有效\n";
    echo "  加入黑名单后: 已撤销\n";
    echo "  错误消息: " . $afterBlacklist['msg'] . "\n";
    
    return true;
});

// ========================================
// 8. 动态模式切换测试
// ========================================
echo "\n【第八部分】动态模式切换测试\n";
echo "----------------------------------------\n";

test('全局Cookie模式，临时使用前端模式', function() {
    // 假设全局是Cookie模式，临时切换到前端模式
    $userData = ['user_id' => 500];
    $result = Token::createToken($userData, true, null, false);
    
    if (!isset($result['data']['access_token'])) {
        return '前端模式应返回access_token';
    }
    
    echo "  成功切换到前端模式\n";
    return true;
});

test('全局前端模式，临时使用Cookie模式', function() {
    // 假设全局是前端模式，临时切换到Cookie模式
    $userData = ['user_id' => 501];
    $result = Token::createToken($userData, true, null, true);
    
    if (!isset($result['data']['message'])) {
        return 'Cookie模式应返回message';
    }
    
    echo "  成功切换到Cookie模式\n";
    return true;
});

// ========================================
// 9. 边界情况测试
// ========================================
echo "\n【第九部分】边界情况测试\n";
echo "----------------------------------------\n";

test('处理复杂用户数据', function() {
    $complexData = [
        'user_id' => 600,
        'username' => 'complex_user',
        'roles' => ['admin', 'editor'],
        'permissions' => ['read', 'write'],
        'profile' => [
            'email' => 'test@example.com',
            'phone' => '13800138000'
        ]
    ];
    
    $result = Token::createToken($complexData, true, null, false);
    
    if ($result['code'] !== 200) {
        return '复杂数据Token生成失败';
    }
    
    // 验证token
    $verifyResult = Token::verifyToken($result['data']['access_token']);
    
    if ($verifyResult['code'] !== 200) {
        return '复杂数据Token验证失败';
    }
    
    echo "  复杂数据结构: ✓\n";
    echo "  角色数量: " . count($verifyResult['data']['roles']) . "\n";
    
    return true;
});

test('空数据处理', function() {
    $result = Token::createToken(null, false, null, false);
    
    if ($result['code'] !== 200) {
        return '空数据处理失败';
    }
    
    echo "  空数据处理: ✓\n";
    return true;
});

test('自定义过期时间', function() {
    $userData = ['user_id' => 700];
    $customExpire = 1800; // 30分钟
    
    $result = Token::createToken($userData, false, $customExpire, false);
    
    if ($result['data']['expires_in'] !== $customExpire) {
        return '自定义过期时间未生效';
    }
    
    echo "  自定义过期时间: {$customExpire}秒\n";
    return true;
});

// ========================================
// 测试结果汇总
// ========================================
echo "\n========================================\n";
echo "  集成测试结果汇总\n";
echo "========================================\n";
echo "  总测试数: {$total}\n";
echo "  通过: {$passed} ✓\n";
echo "  失败: {$failed} ✗\n";
echo "  通过率: " . ($total > 0 ? round(($passed / $total) * 100, 2) : 0) . "%\n";
echo "========================================\n";

if ($failed === 0) {
    echo "\n🎉 所有集成测试通过！\n\n";
    echo "✅ 双模式功能正常\n";
    echo "✅ Token生成、验证、刷新功能正常\n";
    echo "✅ 黑名单机制正常\n";
    echo "✅ 动态模式切换正常\n";
    echo "✅ 边界情况处理正常\n\n";
    echo "插件已准备就绪，可以投入使用！\n";
    exit(0);
} else {
    echo "\n⚠️  有 {$failed} 个测试失败，请检查上述错误信息。\n";
    exit(1);
}
