<?php
// +----------------------------------------------------------------------
// | token配置
// +----------------------------------------------------------------------
return [
    'key'           =>  '#sdfkw%$',
    'expire_time'   =>  config('cookie.expire') ?: 7200,
    'method'        =>  config('cookie.method') ?: 'HS256',
    'is_refresh'    =>  true,   //  是否开启刷新token'
];