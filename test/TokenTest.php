<?php
namespace think;

use PHPUnit\Framework\TestCase;
use think\driver\JWT;
use think\driver\Key;
use think\driver\StorageInterface;
use think\facade\Cookie;

class TokenTest extends TestCase
{
    protected function setUp(): void
    {
        // 初始化配置
        Token::setKey('test_key_1234567890abcdef');
        Token::setExpireTime(7200);
        Token::setMethod('HS256');
    }

    public function testCreateToken()
    {
        // 测试生成普通token
        $result = Token::createToken(['user_id' => 1]);
        $this->assertEquals(200, $result['code']);
        $this->assertArrayHasKey('access_token', $result['data']);
        $this->assertEquals('bearer', $result['data']['token_type']);

        // 测试生成包含刷新token的token
        $result = Token::createToken(['user_id' => 1], true);
        $this->assertEquals(200, $result['code']);
        $this->assertArrayHasKey('access_token', $result['data']);
        $this->assertArrayHasKey('refresh_token', $result['data']);
        $this->assertEquals('bearer', $result['data']['token_type']);
    }

    public function testVerifyToken()
    {
        // 先生成一个token
        $createResult = Token::createToken(['user_id' => 1]);
        $token = $createResult['data']['access_token'];

        // 测试验证有效token
        $result = Token::verifyToken($token);
        $this->assertEquals(200, $result['code']);
        $this->assertEquals(['user_id' => 1, 'scopes' => 'role_access'], $result['data']);

        // 测试验证无效token
        $result = Token::verifyToken('invalid_token');
        $this->assertEquals(400, $result['code']);
    }

    public function testSwapToken()
    {
        // 先生成一个包含刷新token的token
        $createResult = Token::createToken(['user_id' => 1], true);
        $refreshToken = $createResult['data']['refresh_token'];

        // 测试使用刷新token获取新token
        $result = Token::swapToken($refreshToken);
        $this->assertEquals(200, $result['code']);
        $this->assertEquals(['user_id' => 1, 'scopes' => 'role_access'], $result['data']);

        // 测试使用无效刷新token
        $result = Token::swapToken('invalid_refresh_token');
        $this->assertEquals(400, $result['code']);
    }

    public function testAutoSwapToken()
    {
        // 先生成一个包含刷新token的token
        $createResult = Token::createToken(['user_id' => 1], true);
        $accessToken = $createResult['data']['access_token'];
        $refreshToken = $createResult['data']['refresh_token'];

        // 测试access_token未过期的情况
        $result = Token::autoSwapToken(['access_token' => $accessToken, 'refresh_token' => $refreshToken]);
        $this->assertEquals(200, $result['code']);
        $this->assertEquals('Normal status, no need to exchange token', $result['msg']);

        // 测试参数为空的情况
        $result = Token::autoSwapToken();
        $this->assertEquals(400, $result['code']);

        // 测试参数不完整的情况
        $result = Token::autoSwapToken(['access_token' => $accessToken]);
        $this->assertEquals(400, $result['code']);
    }

    public function testGenerateKey()
    {
        // 测试生成密钥
        $key = Token::generateKey();
        $this->assertIsString($key);
        $this->assertGreaterThanOrEqual(16, strlen($key));
    }

    public function testSetStorage()
    {
        // 测试设置自定义存储驱动
        $mockStorage = $this->createMock(StorageInterface::class);
        $mockStorage->method('get')->willReturn(null);
        $mockStorage->method('set')->willReturn(true);
        
        $storage = Token::setStorage($mockStorage);
        $this->assertInstanceOf(StorageInterface::class, $storage);
    }

    public function testConfigFromEnvironment()
    {
        // 测试从环境变量读取配置
        putenv('TOKEN_KEY=env_test_key_1234567890abcdef');
        putenv('TOKEN_EXPIRE_TIME=3600');
        putenv('TOKEN_METHOD=HS512');
        
        // 清除静态变量
        $reflection = new \ReflectionClass(Token::class);
        $keyProperty = $reflection->getProperty('key');
        $keyProperty->setAccessible(true);
        $keyProperty->setValue(null, null);
        
        $expireTimeProperty = $reflection->getProperty('expire_time');
        $expireTimeProperty->setAccessible(true);
        $expireTimeProperty->setValue(null, null);
        
        $methodProperty = $reflection->getProperty('method');
        $methodProperty->setAccessible(true);
        $methodProperty->setValue(null, null);
        
        // 测试获取配置
        $result = Token::createToken(['user_id' => 1]);
        $this->assertEquals(200, $result['code']);
        
        // 清理环境变量
        putenv('TOKEN_KEY');
        putenv('TOKEN_EXPIRE_TIME');
        putenv('TOKEN_METHOD');
    }
}
