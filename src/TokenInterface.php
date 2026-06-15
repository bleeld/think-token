<?php
declare (strict_types = 1);
namespace think;

/**
 * Token接口
 */
interface TokenInterface
{
    /**
     * 生成token
     * @param mixed|null $data 需要加密的数据
     * @param bool|null $isRefreshToken 是否生成刷新token
     * @param int|null $expTime 过期时间
     * @param bool|null $useCookie 是否使用Cookie模式
     * @return array
     */
    public static function createToken(mixed $data = null, bool $isRefreshToken = false, ?int $expTime = null, ?bool $useCookie = null);
    
    /**
     * 验证token
     * @param string $token token字符串
     * @return array
     */
    public static function verifyToken(string $token);
    
    /**
     * 刷新token
     * @param string|null $refresh_token 刷新token
     * @param bool $revokeOld 是否撤销旧的refresh_token
     * @param bool|null $useCookie 是否使用Cookie模式
     * @return array
     */
    public static function swapToken(?string $refresh_token = null, bool $revokeOld = true, ?bool $useCookie = null);
    
    /**
     * 自动刷新token
     * @param array|null $tokens token数组（前端模式下使用）
     * @param bool|null $useCookie 是否使用Cookie模式
     * @return array
     */
    public static function autoSwapToken(?array $tokens = null, ?bool $useCookie = null);
    
    /**
     * 生成密钥
     * @return string
     */
    public static function generateKey(): string;
}