<?php
declare (strict_types = 1);

namespace think\driver;

/**
 * 存储驱动接口
 */
interface StorageInterface
{
    /**
     * 设置值
     * @param string $key 键
     * @param mixed $value 值
     * @param int $expire 过期时间
     * @return bool
     */
    public function set(string $key, $value, int $expire = 3600): bool;
    
    /**
     * 获取值
     * @param string $key 键
     * @return mixed
     */
    public function get(string $key);
    
    /**
     * 删除值
     * @param string $key 键
     * @return bool
     */
    public function delete(string $key): bool;
    
    /**
     * 清空所有值
     * @return bool
     */
    public function clear(): bool;
}