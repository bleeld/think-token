<?php
namespace think;

use think\driver\JWT;
use think\driver\Key;
use think\driver\StorageInterface;
use think\driver\ThinkCacheStorage;
use think\facade\Cache;

class Token implements TokenInterface
{
    //  定义变量
    private static $key;                //  密匙
    private static $expire_time;        //  过期时间
    private static $method;             //  需要加/解密的方法
    private static $storage;            //  存储驱动
    private static $initialized = false; //  是否已初始化
    private static $cookieMode = false;  //  Cookie模式：true=后端设置Cookie，false=返回给前端

    /**
     * 初始化配置
     */
    private static function initialize(): void
    {
        if (self::$initialized) {
            return;
        }
        
        // 初始化密钥、过期时间和加密方法
        self::getKey();
        self::getExpireTime();
        self::getMethod();
        
        // 初始化Cookie模式（从配置文件读取）
        self::$cookieMode = config('token.cookie_mode') ?: false;
        
        self::$initialized = true;
    }

    //  生成token
    /**
     * @method createToken 生成token
     * @param mixed|null $data 需要加密的数据，可以是字符串、数组、对象
     * @param bool|null $isRefreshToken 是否获取刷新token，默认为false，为true时，则多返回一个刷新token，否则只返回token
     * @param int|null $expTime 过期时间的净值，比如一天后过期，该值为： 86400
     * @param bool|null $useCookie 是否使用Cookie模式（覆盖全局配置），true=后端设置Cookie，false=返回给前端
     * 
     * @return array 返回加密后的数组
     */
    public static function createToken(mixed $data = null, bool $isRefreshToken = false, ?int $expTime = null, ?bool $useCookie = null): array
    {
        // 确保初始化
        self::initialize();
        
        // 确定是否使用Cookie模式（参数优先于配置）
        $cookieMode = $useCookie !== null ? $useCookie : self::$cookieMode;
        
        $time = time(); //当前时间
        if (is_null($expTime)) {
            $expTime = self::$expire_time;   //  过期时间
        }
        
        // 验证过期时间合理性
        if ($expTime < 60) {
            throw new \InvalidArgumentException('Token expiration time must be at least 60 seconds');
        }
        
        // 预计算过期时间
        $accessExp = $time + $expTime;
        $refreshExp = $accessExp + $expTime * 12; //刷新token过期时间,2*12 = 24小时
        
        // 优化数据结构，避免重复修改
        $basePayload = [
            'iss' => config('app.host') ?: 'http://localhost',  // 签发者
            'iat' => $time, //签发时间
            'nbf' => $time, //(Not Before)：某个时间点后才能访问
            'data' => is_array($data) ? $data : ['value' => $data], //自定义信息，不要定义敏感信息
        ];
        
        // 生成access token
        $accessPayload = $basePayload;
        $accessPayload['exp'] = $accessExp;
        $accessPayload['data']['scopes'] = 'role_access';   //  添加access标识
        
        // 生成access token
        $accessToken = JWT::encode($accessPayload, self::$key, self::$method);
        
        $result = [
            'code' => 200, 
            'msg' => 'success', 
            'data' => [
                'token_type' => 'Bearer',
                'expires_in' => $expTime
            ]
        ];
        
        // 根据模式决定如何返回token
        if ($cookieMode) {
            // Cookie模式：设置HttpOnly Cookie
            self::setTokenCookies($accessToken, null, $expTime, null);
            $result['data']['message'] = 'Token has been set in cookies';
        } else {
            // 前端模式：直接返回token
            $result['data']['access_token'] = $accessToken;
        }
        
        // 生成refresh token
        if ($isRefreshToken) {
            $refreshPayload = $basePayload;
            $refreshPayload['exp'] = $refreshExp;
            $refreshPayload['data']['scopes'] = 'role_refresh';  //  添加刷新标识
            $refreshToken = JWT::encode($refreshPayload, self::$key, self::$method);
            
            if ($cookieMode) {
                // Cookie模式：设置Refresh Token Cookie
                self::setTokenCookies(null, $refreshToken, null, $expTime * 12);
                $result['data']['refresh_message'] = 'Refresh token has been set in cookies';
            } else {
                // 前端模式：直接返回token
                $result['data']['refresh_token'] = $refreshToken;
                $result['data']['refresh_expires_in'] = $expTime * 12;
            }
        }
        
        return $result;
    }
    
    /**
     * 设置Token Cookies
     * @param string|null $accessToken Access Token
     * @param string|null $refreshToken Refresh Token
     * @param int|null $accessExpire Access Token过期时间（秒）
     * @param int|null $refreshExpire Refresh Token过期时间（秒）
     * @return void
     */
    private static function setTokenCookies(?string $accessToken = null, ?string $refreshToken = null, ?int $accessExpire = null, ?int $refreshExpire = null): void
    {
        // 获取Cookie配置
        $cookieConfig = config('cookie') ?: [];
        
        // Access Token Cookie设置
        if ($accessToken !== null) {
            $accessExpire = $accessExpire ?: 7200;
            \think\facade\Cookie::set('access_token', $accessToken, [
                'expire' => $accessExpire,
                'httponly' => $cookieConfig['httponly'] ?? true,  // 默认HttpOnly
                'secure' => $cookieConfig['secure'] ?? false,      // 根据环境配置
                'samesite' => $cookieConfig['samesite'] ?? 'Lax',  // CSRF保护
                'path' => $cookieConfig['path'] ?? '/',
                'domain' => $cookieConfig['domain'] ?? '',
            ]);
        }
        
        // Refresh Token Cookie设置
        if ($refreshToken !== null) {
            $refreshExpire = $refreshExpire ?: 86400;
            \think\facade\Cookie::set('refresh_token', $refreshToken, [
                'expire' => $refreshExpire,
                'httponly' => $cookieConfig['httponly'] ?? true,
                'secure' => $cookieConfig['secure'] ?? false,
                'samesite' => $cookieConfig['samesite'] ?? 'Lax',
                'path' => $cookieConfig['path'] ?? '/',
                'domain' => $cookieConfig['domain'] ?? '',
            ]);
        }
    }

    //  验证token
    /**
     * 验证token的有效性
     * @param string $token token字符串
     * @param bool $getData 是否返回完整数据（默认只返回验证结果）
     * @return array 验证结果
     */
    public static function verifyToken(string $token, bool $getData = false): array
    {
        // 确保初始化
        self::initialize();
        
        $result = ['code' => 400, 'msg' => 'failure', 'data' => []];
        
        // 检查token格式
        if (empty($token)) {
            $result['msg'] = 'Token cannot be empty';
            return $result;
        }
        
        try {
            JWT::$leeway = 60; //当前时间减去60，把时间留点余地
            $keyObject = new Key(self::$key, self::$method);
            $decoded = JWT::decode($token, $keyObject);
            
            // 将stdClass对象转换为数组（JWT decode返回的是对象）
            $decodedArray = self::objectToArray($decoded);
            $data = $decodedArray['data'] ?? [];
            
            // 检查是否被加入黑名单
            $tokenId = self::getTokenId($token);
            if (self::isTokenBlacklisted($tokenId)) {
                return [
                    'code' => 401,
                    'msg' => 'Token has been revoked',
                    'data' => []
                ];
            }
            
            if ($getData) {
                $result = [
                    'code' => 200, 
                    'msg' => 'success', 
                    'data' => $data,
                    'payload' => $decodedArray // 完整payload（谨慎使用）
                ];
            } else {
                $result = [
                    'code' => 200, 
                    'msg' => 'success', 
                    'data' => $data
                ];
            }
        } catch(\think\driver\SignatureInvalidException $e) {  //签名不正确
            $result['msg'] = 'Invalid token signature';
            $result['data'] = ['error' => $e->getMessage()];
        } catch(\think\driver\BeforeValidException $e) {  // 签名在某个时间点之后才能用
            $result['msg'] = 'Token is not yet valid';
            $result['data'] = ['error' => $e->getMessage()];
        } catch(\think\driver\ExpiredException $e) {  // token过期
            $result['msg'] = 'Token has expired';
            $result['data'] = ['error' => $e->getMessage()];
        } catch(\Exception $e) {  //其他错误
            $result['msg'] = 'Token verification failed';
            $result['data'] = ['error' => $e->getMessage()];
        }
        
        return $result;
    }
    
    /**
     * 获取token的唯一标识
     * @param string $token
     * @return string
     */
    private static function getTokenId(string $token): string
    {
        return md5($token);
    }
    
    /**
     * 检查token是否在黑名单中
     * @param string $tokenId
     * @return bool
     */
    private static function isTokenBlacklisted(string $tokenId): bool
    {
        $blacklistKey = 'token_blacklist_' . $tokenId;
        return self::getStorage()->get($blacklistKey) !== null;
    }
    
    /**
     * 将token加入黑名单（用于注销/撤销token）
     * @param string $token
     * @param int|null $ttl 黑名单有效期（秒），默认为token剩余有效期
     * @return bool
     */
    public static function blacklistToken(string $token, ?int $ttl = null): bool
    {
        try {
            // 先验证token获取过期时间
            $verifyResult = self::verifyToken($token, true);
            if ($verifyResult['code'] !== 200) {
                return false;
            }
            
            $payload = $verifyResult['payload'];
            $exp = $payload['exp'] ?? 0;
            $remainingTime = max(0, $exp - time());
            
            // 如果没有指定TTL，使用token剩余有效期
            if ($ttl === null) {
                $ttl = $remainingTime > 0 ? $remainingTime : 3600;
            }
            
            $tokenId = self::getTokenId($token);
            $blacklistKey = 'token_blacklist_' . $tokenId;
            
            return self::getStorage()->set($blacklistKey, true, $ttl);
        } catch (\Exception $e) {
            return false;
        }
    }


    //  根据refresh_token换取新的access_token和新的refresh_token
    /**
     * 使用refresh_token刷新access_token
     * @param string|null $refresh_token 刷新token
     * @param bool $revokeOld 是否撤销旧的refresh_token（防止重放攻击）
     * @param bool|null $useCookie 是否使用Cookie模式（覆盖全局配置）
     * @return array
     */
    public static function swapToken(?string $refresh_token = null, bool $revokeOld = true, ?bool $useCookie = null): array
    {
        // 确保初始化
        self::initialize();
        
        // 确定是否使用Cookie模式
        $cookieMode = $useCookie !== null ? $useCookie : self::$cookieMode;
        
        //  初始化返回值
        $result = ['code' => 400, 'msg' => 'failure', 'data' => []];
        
        //  判断刷新token是否为空
        if (is_null($refresh_token) || empty($refresh_token)) { 
            $result['msg'] = 'Refresh token is required';
            return $result; 
        }
        
        //  验证token是否正确（verifyToken已返回数组，无需再次转换）
        $ret = self::verifyToken($refresh_token, true);
        
        //  解析token，如果是refresh_token，表示当前token为刷新token，需要生成access_token和refresh_token
        if ($ret['code'] == 200 && isset($ret['data']['scopes']) && $ret['data']['scopes'] == 'role_refresh') {
            $data = $ret['data'];
            
            //  如果启用旧token撤销，将旧refresh_token加入黑名单
            if ($revokeOld) {
                self::blacklistToken($refresh_token);
            }
            
            //  开始获取新的token
            try {
                //  获取access_token 与 refresh_token
                $tokenResults = self::createToken($data, true, null, $cookieMode);
                
                if ($tokenResults['code'] === 200) {
                    if ($cookieMode) {
                        // Cookie模式：tokens已通过Cookie设置
                        $result = [
                            'code' => 200, 
                            'msg' => 'Token refreshed successfully', 
                            'data' => [
                                'message' => 'New tokens have been set in cookies',
                                'user_data' => $data,
                                'expires_in' => $tokenResults['data']['expires_in'],
                                'refresh_expires_in' => $tokenResults['data']['refresh_expires_in'] ?? null
                            ]
                        ];
                    } else {
                        // 前端模式：返回新tokens
                        $result = [
                            'code' => 200, 
                            'msg' => 'Token refreshed successfully', 
                            'data' => [
                                'access_token' => $tokenResults['data']['access_token'],
                                'refresh_token' => $tokenResults['data']['refresh_token'],
                                'token_type' => 'Bearer',
                                'expires_in' => $tokenResults['data']['expires_in'],
                                'refresh_expires_in' => $tokenResults['data']['refresh_expires_in'],
                                'user_data' => $data
                            ]
                        ];
                    }
                } else {
                    $result['msg'] = 'Failed to generate new tokens';
                }
            } catch (\Exception $e) {
                $result['msg'] = 'Token refresh failed: ' . $e->getMessage();
            }

            return $result;
        }
        
        // 如果不是refresh token或验证失败
        if ($ret['code'] !== 200) {
            $result['msg'] = 'Invalid refresh token: ' . $ret['msg'];
        } else {
            $result['msg'] = 'Invalid token type, refresh token required';
        }
        
        return $result;
    }


    //  自动刷新token,$tokens变量中包含access_token和refresh_token2个参数
    /**
     * 自动刷新token（智能判断是否需要刷新）
     * @param array|null $tokens 包含access_token和refresh_token的数组（前端模式下使用）
     * @param bool|null $useCookie 是否使用Cookie模式（覆盖全局配置）
     * @return array
     */
    public static function autoSwapToken(?array $tokens = null, ?bool $useCookie = null): array
    {
        // 确保初始化
        self::initialize();
        
        // 确定是否使用Cookie模式
        $cookieMode = $useCookie !== null ? $useCookie : self::$cookieMode;
        
        //  定义返回数据
        $result = ['code' => 400, 'msg' => 'failure', 'data' => []];
        
        // Cookie模式下，从 Cookie读取tokens
        if ($cookieMode) {
            $accessToken = \think\facade\Cookie::get('access_token');
            $refreshToken = \think\facade\Cookie::get('refresh_token');
            
            if (empty($accessToken) || empty($refreshToken)) {
                $result['msg'] = 'Tokens not found in cookies';
                return $result;
            }
            
            $tokens = [
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken
            ];
        } else {
            // 前端模式：检查参数完整性
            if (empty($tokens) || !isset($tokens['access_token']) || !isset($tokens['refresh_token'])) {
                $result['msg'] = 'Both access_token and refresh_token are required';
                return $result;
            }
        }
        
        //  验证access_token是否过期（verifyToken已返回数组，无需再次转换）
        $verifyToken = self::verifyToken($tokens['access_token']);
        
        // access_token仍然有效，无需刷新
        if ($verifyToken['code'] == 200) {
            return [
                'code' => 200, 
                'msg' => 'Token is still valid, no refresh needed', 
                'data' => [
                    'status' => 'valid',
                    'user_data' => $verifyToken['data']
                ]
            ];
        }
        
        // access_token已过期，尝试使用refresh_token刷新
        $ret = self::swapToken($tokens['refresh_token'], false, true, $cookieMode);
        
        if ($ret['code'] == 200) {
            return [
                'code' => 200, 
                'msg' => 'Token refreshed successfully', 
                'data' => $ret['data']
            ];
        }
        
        // 刷新失败，返回错误信息
        return [
            'code' => 401,
            'msg' => 'Token refresh failed: ' . $ret['msg'],
            'data' => ['status' => 'expired']
        ];
    }


    //  key 管理
	/**
     * 获取密钥
     * @return string
     */
	private static function getKey(): string
    {
		if(isset(self::$key) && self::$key) {
			return self::$key;
		}
		
		// 尝试从存储驱动获取
		$key = self::getStorage()->get('token_key');
		if ($key) {
			self::$key = $key;
			return $key;
		}
		
		self::setKey();
		return self::$key;
	}
	
	/**
     * 设置密钥
     * @param string|null $key 密钥
     * @return void
     */
	public static function setKey(?string $key = null): void
    {
        // 优先从环境变量读取
        if (empty($key)) {
            $envKey = \think\facade\Env::get('TOKEN_KEY');
            if (!empty($envKey)) {
                $key = $envKey;
            }
        }
        
        // 其次从配置文件读取
        if (empty($key)) {
            $configKey = config('token.key');
            if (!empty($configKey)) {
                $key = $configKey;
            } else {
                $key = self::generateKey();
            }
        }
        
        // 检查密钥长度和复杂度
        self::validateKey($key);
        
        self::$key = $key;
        
        // 缓存配置到存储驱动（24小时）
        self::getStorage()->set('token_key', $key, 86400);
	}
	
	/**
	 * 生成安全的密钥
	 * @param int $length 密钥长度（字节），默认32字节（64位十六进制）
	 * @return string 生成的密钥
	 */
	public static function generateKey(int $length = 32): string
	{
		if ($length < 16) {
			throw new \InvalidArgumentException('Key length must be at least 16 bytes');
		}
		return bin2hex(random_bytes($length)); // 生成随机密钥
	}
	
	/**
	 * 验证密钥的长度和复杂度
	 * @param string $key 密钥
	 * @throws \Exception 如果密钥不符合要求
	 */
	private static function validateKey(string $key): void
	{
		// 检查密钥长度（至少32个字符，即16字节的十六进制表示）
		if (strlen($key) < 32) {
			throw new \Exception('Token key must be at least 32 characters long (16 bytes in hex)');
		}
		
		// 检查密钥复杂度（至少包含字母和数字）
		if (!preg_match('/[a-zA-Z]/', $key) || !preg_match('/[0-9]/', $key)) {
			throw new \Exception('Token key must contain both letters and numbers');
		}
	}
	
	/**
	 * 获取存储驱动
	 * @return StorageInterface
	 */
	private static function getStorage(): StorageInterface
	{
		if (isset(self::$storage) && self::$storage instanceof StorageInterface) {
			return self::$storage;
		}
		return self::setStorage();
	}
	
	/**
	 * 设置存储驱动
	 * @param StorageInterface|null $storage 存储驱动实例
	 * @return StorageInterface
	 */
	public static function setStorage(?StorageInterface $storage = null): StorageInterface
	{
		if ($storage instanceof StorageInterface) {
			self::$storage = $storage;
		} else {
			// 默认使用ThinkPHP缓存存储
			self::$storage = new ThinkCacheStorage();
		}
		return self::$storage;
	}

    //  expire_time 管理
	/**
     * 获取过期时间
     * @return int
     */
	private static function getExpireTime(): int
    {
		if(isset(self::$expire_time) && self::$expire_time) {
			return self::$expire_time;
		}
		
		// 尝试从存储驱动获取
		$expireTime = self::getStorage()->get('token_expire_time');
		if ($expireTime !== null && $expireTime !== false) {
			self::$expire_time = (int)$expireTime;
			return self::$expire_time;
		}
		
		self::setExpireTime();
		return self::$expire_time;
	}
	
	/**
     * 设置过期时间
     * @param int|null $expire_time 过期时间（秒）
     * @return void
     */
	public static function setExpireTime(?int $expire_time = null): void
    {
        // 优先从环境变量读取
        if ($expire_time === null) {
            $envExpire = \think\facade\Env::get('TOKEN_EXPIRE_TIME');
            if (!empty($envExpire)) {
                $expire_time = (int) $envExpire;
            }
        }
        
        // 其次从配置文件读取
        if ($expire_time === null) {
            $configExpire = config('token.expire_time');
            $expire_time = !empty($configExpire) ? (int)$configExpire : 7200;
        }
        
        // 验证过期时间合理性
        if ($expire_time < 60) {
            throw new \InvalidArgumentException('Token expiration time must be at least 60 seconds');
        }
        
        self::$expire_time = $expire_time;
        
        // 缓存配置到存储驱动（24小时）
        self::getStorage()->set('token_expire_time', $expire_time, 86400);
	}

    //  method 管理
	/**
     * 获取加密方法
     * @return string
     */
	private static function getMethod(): string
    {
		if(isset(self::$method) && self::$method) {
			return self::$method;
		}
		
		// 尝试从存储驱动获取
		$method = self::getStorage()->get('token_method');
		if ($method) {
			self::$method = $method;
			return $method;
		}
		
		self::setMethod();
		return self::$method;
	}
	
	/**
     * 设置加密方法
     * @param string|null $method 加密方法
     * @return void
     */
	public static function setMethod(?string $method = null): void
    {
        // 支持的加密算法列表
        $supportedMethods = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'];
        
        // 优先从环境变量读取
        if (empty($method) && env('TOKEN_METHOD')) {
            $method = strtoupper(env('TOKEN_METHOD'));
        }
        
        // 其次从配置文件读取
        if (empty($method)) {
            $configMethod = config('token.method');
            $method = !empty($configMethod) ? strtoupper($configMethod) : 'HS256';
        }
        
        // 验证加密方法是否支持
        if (!in_array($method, $supportedMethods)) {
            throw new \InvalidArgumentException(
                "Unsupported encryption method: {$method}. Supported methods: " . implode(', ', $supportedMethods)
            );
        }
        
        self::$method = $method;
        
        // 缓存配置到存储驱动（24小时）
        self::getStorage()->set('token_method', $method, 86400);
	}


    /**
     * 将对象转换为数组（支持递归转换和循环引用检测）
     * @param mixed $data 要转换的数据（对象、数组或其他类型）
     * @param array &$visited 用于检测循环引用的已访问对象列表（内部使用）
     * @return mixed 转换后的数组或原始数据
     */
    public static function objectToArray($data, array &$visited = []) {
        // 处理 null 值
        if (is_null($data)) {
            return null;
        }
        
        // 如果是对象
        if (is_object($data)) {
            // 检测循环引用
            $objectId = spl_object_id($data);
            if (isset($visited[$objectId])) {
                return '[Circular Reference]'; // 避免无限递归
            }
            
            // 标记为已访问
            $visited[$objectId] = true;
            
            // 获取对象的所有属性（包括私有和受保护的）
            if ($data instanceof \JsonSerializable) {
                // 如果对象实现了 JsonSerializable 接口，使用 jsonSerialize 方法
                $array = $data->jsonSerialize();
            } elseif ($data instanceof \ArrayAccess && $data instanceof \IteratorAggregate) {
                // 如果对象实现了 ArrayAccess 和 IteratorAggregate（如 Collection）
                $array = iterator_to_array($data);
            } else {
                // 普通对象，获取所有属性
                $array = get_object_vars($data);
            }
            
            // 递归转换数组中的每个元素
            $result = [];
            foreach ($array as $key => $value) {
                $result[$key] = self::objectToArray($value, $visited);
            }
            
            // 清理已访问标记
            unset($visited[$objectId]);
            
            return $result;
        }
        
        // 如果是数组，递归转换每个元素
        if (is_array($data)) {
            $result = [];
            foreach ($data as $key => $value) {
                $result[$key] = self::objectToArray($value, $visited);
            }
            return $result;
        }
        
        // 其他类型直接返回（字符串、数字、布尔值等）
        return $data;
    }
}
