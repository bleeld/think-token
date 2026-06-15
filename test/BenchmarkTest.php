<?php
namespace think;

use PHPUnit\Framework\TestCase;

class BenchmarkTest extends TestCase
{
    protected function setUp(): void
    {
        // 初始化配置
        Token::setKey('test_key_1234567890abcdef');
        Token::setExpireTime(7200);
        Token::setMethod('HS256');
    }

    /**
     * 测试token生成性能
     */
    public function testTokenCreationPerformance()
    {
        $iterations = 1000;
        $startTime = microtime(true);
        $memoryStart = memory_get_usage();

        for ($i = 0; $i < $iterations; $i++) {
            Token::createToken(['user_id' => $i, 'name' => 'Test User ' . $i]);
        }

        $endTime = microtime(true);
        $memoryEnd = memory_get_usage();

        $executionTime = $endTime - $startTime;
        $memoryUsed = $memoryEnd - $memoryStart;

        echo "Token creation benchmark:\n";
        echo "Iterations: $iterations\n";
        echo "Execution time: " . number_format($executionTime, 4) . " seconds\n";
        echo "Memory used: " . number_format($memoryUsed / 1024, 2) . " KB\n";
        echo "Time per token: " . number_format(($executionTime / $iterations) * 1000, 4) . " ms\n\n";

        // 验证性能提升
        $this->assertLessThan(1.0, $executionTime, 'Token creation should be faster than 1 second for 1000 iterations');
        $this->assertLessThan(100000, $memoryUsed, 'Memory usage should be less than 100KB for 1000 iterations');
    }

    /**
     * 测试token验证性能
     */
    public function testTokenVerificationPerformance()
    {
        // 先生成一批token
        $tokens = [];
        for ($i = 0; $i < 1000; $i++) {
            $result = Token::createToken(['user_id' => $i, 'name' => 'Test User ' . $i]);
            $tokens[] = $result['data']['access_token'];
        }

        $iterations = count($tokens);
        $startTime = microtime(true);
        $memoryStart = memory_get_usage();

        foreach ($tokens as $token) {
            Token::verifyToken($token);
        }

        $endTime = microtime(true);
        $memoryEnd = memory_get_usage();

        $executionTime = $endTime - $startTime;
        $memoryUsed = $memoryEnd - $memoryStart;

        echo "Token verification benchmark:\n";
        echo "Iterations: $iterations\n";
        echo "Execution time: " . number_format($executionTime, 4) . " seconds\n";
        echo "Memory used: " . number_format($memoryUsed / 1024, 2) . " KB\n";
        echo "Time per verification: " . number_format(($executionTime / $iterations) * 1000, 4) . " ms\n\n";

        // 验证性能提升
        $this->assertLessThan(1.0, $executionTime, 'Token verification should be faster than 1 second for 1000 iterations');
        $this->assertLessThan(100000, $memoryUsed, 'Memory usage should be less than 100KB for 1000 iterations');
    }

    /**
     * 测试token刷新性能
     */
    public function testTokenSwapPerformance()
    {
        // 先生成一批refresh token
        $refreshTokens = [];
        for ($i = 0; $i < 100; $i++) {
            $result = Token::createToken(['user_id' => $i, 'name' => 'Test User ' . $i], true);
            $refreshTokens[] = $result['data']['refresh_token'];
        }

        $iterations = count($refreshTokens);
        $startTime = microtime(true);
        $memoryStart = memory_get_usage();

        foreach ($refreshTokens as $refreshToken) {
            Token::swapToken($refreshToken);
        }

        $endTime = microtime(true);
        $memoryEnd = memory_get_usage();

        $executionTime = $endTime - $startTime;
        $memoryUsed = $memoryEnd - $memoryStart;

        echo "Token swap benchmark:\n";
        echo "Iterations: $iterations\n";
        echo "Execution time: " . number_format($executionTime, 4) . " seconds\n";
        echo "Memory used: " . number_format($memoryUsed / 1024, 2) . " KB\n";
        echo "Time per swap: " . number_format(($executionTime / $iterations) * 1000, 4) . " ms\n\n";

        // 验证性能提升
        $this->assertLessThan(0.5, $executionTime, 'Token swap should be faster than 0.5 second for 100 iterations');
        $this->assertLessThan(50000, $memoryUsed, 'Memory usage should be less than 50KB for 100 iterations');
    }
}