<?php
namespace token;

use token\driver\JWT;
use token\driver\Key;

class Token
{
    //  定义变量
    private static $key;                //  密匙
    private static $expire_time;        //  过期时间
    private static $method;             //  需要加/解密的方法

    //  生成token
    /**
     * @method createToken 生成token
     * @param mixed|null $data 需要加密的数据，可以是字符串、数组、对象
     * @param bool|null $isRefreshToken 是否获取刷新token，默认为false，为true时，则多返回一个刷新token，否则只返回token
     * @param int|null $expTime 过期时间的净值，比如一天后过期，该值为： 86400
     * 
     * @return array 返回加密后的数组
     */
    public static function createToken(mixed $data = null, bool $isRefreshToken = false, ?int $expTime = null)
    {
        $time = time(); //当前时间
        if (is_null($expTime)) {
            $expTime = self::getExpireTime();   //  过期时间,这里设置2个小时
        }
        $payload = [
            'iss' => 'http://www.buddha.com',  // 签发者 可选
            'iat' => $time, //签发时间
            'nbf' => $time , //(Not Before)：某个时间点后才能访问，比如设置time+30，表示当前时间30秒后才能使用
            'exp' => $time + $expTime, 
            'data' => $data, //自定义信息，不要定义敏感信息
        ];
        $payload['data']['scopes'] =   'role_access';   //  添加access标识
        $accessToken = JWT::encode($payload, self::getKey(), self::getMethod()); //签发token
        $data = ['code'=>200, 'msg'=>'success', 'data'=>['access_token'=>$accessToken, 'token_type'=>'bearer']];
        if ($isRefreshToken) {
            $payload['exp'] += (int) $expTime * 12; //刷新token过期时间,2*12 = 24小时
            $payload['data']['scopes'] =   'role_refresh';  //  添加刷新标识
            $refreshToken = JWT::encode($payload, self::getKey(), self::getMethod()); //签发token
            $data['data']['refresh_token']   =  $refreshToken;
        }
        return $data;
    }

    //  验证token
    public static function verifyToken(string $token)
    {
        $result = ['code'=>400, 'msg'=>'failure', 'data'=>[]];
        try {
            JWT::$leeway = 60;//当前时间减去60，把时间留点余地
            $decoded = JWT::decode($token, new Key(self::getKey(),  self::getMethod())); //HS256方式，这里要和签发的时候对应
            $result = ['code'=>200, 'msg'=>'success', 'data'=>(array) $decoded->data];
        } catch(\token\driver\SignatureInvalidException $e) {  //签名不正确
            $result['data'] = $e->getMessage();
        }catch(\token\driver\BeforeValidException $e) {  // 签名在某个时间点之后才能用
            $result['data'] = $e->getMessage();
        }catch(\token\driver\ExpiredException $e) {  // token过期
            $result['data'] = $e->getMessage();
        }catch(\Exception $e) {  //其他错误
            $result['data'] = $e->getMessage();
        } finally{
            return $result;
        }
    }


    //  根据refresh_token换取新的access_token和新的refresh_token
    public static function swapToken(?string $refresh_token = null, bool $isAutoSet = false)
    {
        //  初始化返回值
        $result = ['code'=>400, 'msg'=>'failure', 'data'=>[]];
        //  判断刷新token是否为空
        if (is_null($refresh_token)) { return $result; }
        //  验证token是否正确
        $ret = self::verifyToken($refresh_token);
        //  解析token，如果是refresh_token，表示当前token为刷新token，需要生成access_token和refresh_token
        if ($ret['code'] == 200 && $ret['data']['scopes'] == 'role_refresh') {
            $data = $ret['data'];
            //  开始获取新的token
            try {
                //  获取access_token 与 refresh_token
                $tokenResults = self::createToken($data, true);
                if ($tokenResults['data']['access_token'] && $tokenResults['data']['refresh_token']) {
                    $access_token = $tokenResults['data']['access_token'];
                    $refresh_token = $tokenResults['data']['refresh_token'];
                    if ($isAutoSet) {
                        //  清理掉之前的cookie
                        \think\facade\Cookie::delete('access_token');
                        \think\facade\Cookie::delete('refresh_token');
                        //  自动设置token
                        \think\facade\Cookie::set('access_token', $access_token);
                        \think\facade\Cookie::set('refresh_token', $refresh_token);
                    }
                    //  修改当前的token角色
                    $data['scopes'] = 'role_access';  // token标识，请求接口的token
                }
                //  $result = ['code'=>200, 'msg'=>'success', 'data'=>array_merge($data, $tokenResults['data'])];
                $result = ['code'=>200, 'msg'=>'ok', 'data'=>$data];
            } catch (\Exception $e) {
                $result['msg'] = $e->getMessage();
            }

            return $result;
        }
    }


    //  自动刷新token,$tokens变量中包含access_token和refresh_token2个参数
    public static function autoSwapToken(?array $tokens = null)
    {
        //  定义返回数据
        $result = ['code'=>400, 'msg'=>'failure', 'data'=>[]];
        //  判断参数是否为空，判断access_token是否过期，未过期则直接返回，过期则判断refresh_token是否过期，未过期则刷新token，过期则返回错误信息
        if (!isset($tokens['access_token']) || !isset($tokens['refresh_token']) || empty($tokens)) {
            return $result;
        }
        //  验证access_token是否过期
        $verifyToken = Token::verifyToken($tokens['access_token']);
        if ($verifyToken['code'] != 200) {
            $ret = Token::swapToken($tokens['refresh_token'], true);
            if ($ret['code'] == 200) {
                return ['code'=>200, 'msg'=>'success', 'data'=>$ret['data']];
            }
        } else {
            $result = ['code'=>200, 'msg'=>'Normal status, no need to exchange token', 'data'=>[]];
        }
        return $result;
    }


    //  key 管理
	private static function getKey()
    {
		if(isset(self::$key) && self::$key)
        {
			return self::$key;
		}
		self::setKey();
		return self::$key;
	}
	private static function setKey(?string $key = null)
    {
        self::$key = (isset($key) && !$key) ? $key : (config('token.key') ? config('token.key') : '#sdfkw%$');
	}

    //  expire_time 管理
	private static function getExpireTime()
    {
		if(isset(self::$expire_time) && self::$expire_time)
        {
			return self::$expire_time;
		}
		self::setExpireTime();
		return self::$expire_time;
	}
	private static function setExpireTime(?int $expire_time = null)
    {
        self::$expire_time = (isset($expire_time) && !$expire_time) ? $expire_time : (config('token.expire_time') ? config('token.expire_time') : 7200);
	}

    //  expire_time 管理
	private static function getMethod()
    {
		if(isset(self::$method) && self::$method)
        {
			return self::$method;
		}
		self::setMethod();
		return self::$method;
	}
	private static function setMethod($method = null)
    {
        self::$method = (isset($method) && !$method) ? $method : (config('token.method') ? config('token.method') : 'HS256');
	}


}
