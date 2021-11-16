<?php

namespace Trappistes\ApiSign\Models;

use Illuminate\Database\Eloquent\Model;

class AccessKey extends Model
{
    /**
     * 自定义表名
     *
     * @var string
     */
    protected $table = 'access_keys';

    /**
     * 批量赋值白名单
     *
     * @var array
     */
    protected $fillable = ['id', 'app_name', 'app_desc', 'access_key', 'access_secret', 'status'];

    /**
     * 类型转换
     *
     * @var array
     */
    protected $casts = [
        'status' => 'boolean',
    ];
}
