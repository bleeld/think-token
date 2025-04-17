<?php
namespace token;

use PHPUnit\Framework\TestCase;
use token\driver\JWT;
use token\driver\Key;
use think\facade\Cookie;

class TokenTest extends TestCase
{
    protected function setUp(): void
    {
        // 初始化配置
        Token::setKey('test_key');
        Token::setExpireTime(7200);
        Token::setMethod('HS256');
    }

    public function testCreateToken()
    {
        // Mock JWT::encode
        $mockToken = 'mock_token';
        $this->mockStaticMethod(JWT::class, 'encode', $mockToken);

        // 测试生成普通token
        $result = Token::createToken(['user_id' => 1]);
        $this->assertEquals(200, $result['code']);
        $this->assertEquals($mockToken, $result['data']['access_token']);

        // 测试生成包含刷新token的token
        $result = Token::createToken(['user_id' => 1], true);
        $this->assertEquals(200, $result['code']);
        $this->assertEquals($mockToken, $result['data']['access_token']);
        $this->assertEquals($mockToken, $result['data']['refresh_token']);
    }

    public function testVerifyToken()
    {
        // Mock JWT::decode 返回有效payload
        $mockPayload = (object) ['data' => ['user_id' => 1]];
        $this->mockStaticMethod(JWT::class, 'decode', $mockPayload);

        $result = Token::verifyToken('valid_token');
        $this->assertEquals(200, $result['code']);
        $this->assertEquals(['user_id' => 1], $result['data']);

        // Mock JWT::decode 抛出过期异常
        $this->mockStaticMethod(JWT::class, 'decode', function () {
            throw new \token\driver\ExpiredException('Token expired');
        });

        $result = Token::verifyToken('expired_token');
        $this->assertEquals(400, $result['code']);
        $this->assertEquals('Token expired', $result['data']);
    }

    public function testSwapToken()
    {
        // Mock verifyToken 返回有效刷新token
        $this->mockStaticMethod(Token::class, 'verifyToken', ['code' => 200, 'data' => ['scopes' => 'role_refresh']]);

        // Mock createToken 返回新token
        $mockToken = 'new_mock_token';
        $this->mockStaticMethod(Token::class, 'createToken', ['code' => 200, 'data' => ['access_token' => $mockToken, 'refresh_token' => $mockToken]]);

        // Mock Cookie::set
        $this->mockStaticMethod(Cookie::class, 'set', null);

        $result = Token::swapToken('valid_refresh_token', true);
        $this->assertEquals(200, $result['code']);
    }

    public function testAutoSwapToken()
    {
        // Mock verifyToken 返回过期token
        $this->mockStaticMethod(Token::class, 'verifyToken', ['code' => 400]);

        // Mock swapToken 返回新token
        $mockToken = 'new_mock_token';
        $this->mockStaticMethod(Token::class, 'swapToken', ['code' => 200, 'data' => ['access_token' => $mockToken, 'refresh_token' => $mockToken]]);

        $result = Token::autoSwapToken(['access_token' => 'expired_token', 'refresh_token' => 'valid_refresh_token']);
        $this->assertEquals(200, $result['code']);
    }

    private function mockStaticMethod($class, $method, $returnValue)
    {
        $mock = $this->getMockBuilder($class)
            ->disableOriginalConstructor()
            ->getMock();
        $mock->method($method)->willReturn($returnValue);
        $this->setStaticProperty($class, 'instance', $mock);
    }

    private function setStaticProperty($class, $property, $value)
    {
        $reflection = new \ReflectionClass($class);
        $property = $reflection->getProperty($property);
        $property->setAccessible(true);
        $property->setValue(null, $value);
    }
}