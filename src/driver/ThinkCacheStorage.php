<?php
declare (strict_types = 1);
namespace think\driver;

use think\driver\StorageInterface;

/**
 * 基于ThinkPHP缓存的存储驱动
 */
class ThinkCacheStorage implements StorageInterface
{
    private $memoryCache = [];
    private $useMemoryCache = false;
    
    public function __construct()
    {
        // 检查是否可以使用ThinkPHP缓存
        try {
            class_exists('think\facade\Cache');
            $this->useMemoryCache = false;
        } catch (\Exception $e) {
            // 如果无法使用ThinkPHP缓存，使用内存缓存
            $this->useMemoryCache = true;
        }
    }
    
    /**
     * 设置值
     * @param string $key 键
     * @param mixed $value 值
     * @param int $expire 过期时间
     * @return bool
     */
    public function set(string $key, $value, int $expire = 3600): bool
    {
        if ($this->useMemoryCache) {
            $this->memoryCache[$key] = [
                'value' => $value,
                'expire' => time() + $expire
            ];
            return true;
        }
        
        try {
            return \think\facade\Cache::set($key, $value, $expire);
        } catch (\Exception $e) {
            // 回退到内存缓存
            $this->useMemoryCache = true;
            $this->memoryCache[$key] = [
                'value' => $value,
                'expire' => time() + $expire
            ];
            return true;
        }
    }
    
    /**
     * 获取值
     * @param string $key 键
     * @return mixed
     */
    public function get(string $key)
    {
        if ($this->useMemoryCache) {
            if (isset($this->memoryCache[$key])) {
                $item = $this->memoryCache[$key];
                if (time() < $item['expire']) {
                    return $item['value'];
                } else {
                    // 过期，删除
                    unset($this->memoryCache[$key]);
                }
            }
            return null;
        }
        
        try {
            return \think\facade\Cache::get($key);
        } catch (\Exception $e) {
            // 回退到内存缓存
            $this->useMemoryCache = true;
            return $this->memoryCache[$key]['value'] ?? null;
        }
    }
    
    /**
     * 删除值
     * @param string $key 键
     * @return bool
     */
    public function delete(string $key): bool
    {
        if ($this->useMemoryCache) {
            if (isset($this->memoryCache[$key])) {
                unset($this->memoryCache[$key]);
                return true;
            }
            return false;
        }
        
        try {
            return \think\facade\Cache::delete($key);
        } catch (\Exception $e) {
            // 回退到内存缓存
            $this->useMemoryCache = true;
            if (isset($this->memoryCache[$key])) {
                unset($this->memoryCache[$key]);
                return true;
            }
            return false;
        }
    }
    
    /**
     * 清空所有值
     * @return bool
     */
    public function clear(): bool
    {
        if ($this->useMemoryCache) {
            $this->memoryCache = [];
            return true;
        }
        
        try {
            return \think\facade\Cache::clear();
        } catch (\Exception $e) {
            // 回退到内存缓存
            $this->useMemoryCache = true;
            $this->memoryCache = [];
            return true;
        }
    }
}