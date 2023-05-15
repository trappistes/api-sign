<?php

namespace Trappistes\ApiSign;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;

class Signature
{
    /**
     * 错误码
     *
     * @var string[]
     */
    const ErrCodes = [
        '1001' => '[access_key]缺失',
        '1002' => '[access_key]不存在或无权限',
        '1003' => '[access_key]已失效',
        '1011' => '[version]缺失',
        '1012' => '[version]错误',
        '1021' => '[signature]签名缺失',
        '1022' => '[signature]签名错误',
        '1031' => '[nonce]缺失',
        '1032' => '[nonce]必须为字符串',
        '1033' => '[nonce]长度必须为1-32位',
        '1034' => '[nonce]已失效',
        '1041' => '[timestamp]缺失',
        '1042' => '[timestamp]已失效',
        '1043' => '[timestamp]无效的时间戳',
        '1051' => '[method]缺失',
        '1052' => '[method]错误',
    ];

    /**
     * 请求参数
     *
     * @var array
     */
    public array $params = [];

    /**
     * 签名加密方法
     *
     * @var string $method
     */
    protected string $method = 'md5';

    /**
     * 签名时间戳有效期(单位：秒)
     *
     * @var int $ttl
     */
    protected int $ttl = 600;

    /**
     * 密钥
     *
     * @var string $access_secret
     */
    protected string $access_secret = '';

    /**
     * The token model class name.
     *
     * @var string
     */
    public static $model = 'Trappistes\ApiSign\Models\AccessKey';

    /**
     * 自定义模型
     *
     * @param string $model
     * @return void
     */
    public static function useModel($model)
    {
        static::$model = $model;
    }

    /**
     * Get the token model class name.
     *
     * @return string
     */
    public static function model()
    {
        return static::$model;
    }

    /**
     * 进行校验
     *
     * @return array
     */
    public function validate(): array
    {
        // 获取参数
        $this->params = request()->query();

        // 获取加密方式
        $this->method = request()->get('Signature-Method', 'md5');

        // 参数校验
        $res = $this->paramValidate();

        if ($res['code'] !== 200) {
            return $res;
        }

        // access_key校验
        $res = $this->appValidate();

        if ($res['code'] !== 200) {
            return $res;
        }

        // 签名校验
        $res = $this->signValidate();

        if ($res['code'] !== 200) {
            return $res;
        }

        // nonce校验
        if ($this->params['Signature-Nonce']) {
            $res = $this->nonceValidate();

            if ($res['code'] !== 200) {
                return $res;
            }

            // nonce写入缓存
            Cache::tags(['nonces'])->put($this->params['Signature-Access-Key'] . '-Nonce', $this->params['Signature-Timestamp'], $this->ttl);
        }

        // 成功返回
        return $res;
    }

    /**
     * 验证url参数是否有效
     *
     * @return array
     */
    protected function paramValidate(): array
    {
        list($msec, $sec) = explode(' ', microtime());

        $msectimes = substr((float)sprintf('%.0f', (floatval($msec) + floatval($sec)) * 1000), 0, 13);

        // 验证规则
        $rules = [
            'Signature-Access-Key' => 'bail|required',
            'Signature-Version' => 'bail|required|in:1.0',
            'Signature-Nonce' => 'bail|sometimes|required|string|min:1|max:32',
            'Signature-Timestamp' => 'bail|required|integer|between:' . $msectimes - $this->ttl * 1000 . ',' . $msectimes + $this->ttl * 1000,
            'Signature' => 'bail|required',
            'Signature-Method' => 'bail|required|in:,md5,hash',
        ];

        // 验证消息
        $messages = [
            'Signature-Access-Key.required' => '1001',
            'Signature-Version.required' => '1011',
            'Signature-Version.in' => '1012',
            'Signature-Nonce.required' => '1031',
            'Signature-Nonce.string' => '1032',
            'Signature-Nonce.min' => '1033',
            'Signature-Nonce.max' => '1033',
            'Signature-Timestamp.required' => '1041',
            'Signature-Timestamp.between' => '1042',
            'Signature-Timestamp.integer' => '1043',
            'Signature.required' => '1021',
            'Signature-Method.required' => '1051',
            'Signature-Method.in' => '1052',
            'Format.required' => '1061',
            'Format.in' => '1062',
        ];

        // 验证请求数据
        $result = Validator::make($this->params, $rules, $messages);

        if ($result->fails()) {
            return $this->error($result->messages()->first());
        } else {
            return $this->success();
        }
    }

    /**
     * 验证nonce参数是否有效
     *
     * @return array
     */
    protected function nonceValidate(): array
    {
        if (Cache::tags(['Signature-Nonce'])->has($this->params['Signature-Access-Key'] . '-Nonce')) {
            return $this->error('1034');
        } else {
            return $this->success();
        }
    }

    /**
     * 验证access_key参数是否有效
     *
     * @return array
     */
    protected function appValidate(): array
    {
        // 获取模型
        $model = app(self::model());

        $key = $model::where('access_key', $this->params['Signature-Access-Key'])->first();

        if (!$key) {
            return $this->error('1002');
        } elseif ($key['status'] == 0) {
            return $this->error('1003');
        } else {

            // 向请求头中写入当前key
            request()->headers->set('key', $key);

            $this->access_secret = $key->access_secret;
            return $this->success();
        }
    }

    /**
     * 签名验证
     *
     * @return array
     */
    protected function signValidate(): array
    {
        $str = $this->generateSign();

        if ($this->params['Signature'] != $str) {
            return $this->error('1022');
        } else {
            return $this->success();
        }
    }

    /**
     * 验证成功返回
     *
     * @return array
     */
    protected function success(): array
    {
        return ['code' => 200];
    }

    /**
     * 验证失败返回
     *
     * @param string $code
     * @return array
     */
    protected function error(string $code): array
    {
        return ['code' => $code, 'message' => self::ErrCodes[$code]];
    }

    /**
     * 生成签名
     *
     * @return string
     */
    public function generateSign(): string
    {
        // 对参数进行排序
        ksort($this->params);

        $tmps = array();

        // 遍历参数，写入临时变量
        foreach ($this->params as $k => $v) {
            // 跳过sign
            if ($k == 'Signature') {
                continue;
            }
            $tmps[] = $k . $v;
        }

        // 组合字符串
        $string = implode('', $tmps) . $this->access_secret;

        // 根据指定的加密方式进行加密，并转为全大写后返回
        if ($this->method === 'md5') {
            return strtoupper(md5($string));
        } elseif ($this->method === 'hash') {
            return strtoupper(hash_hmac('sha256', $string, $this->access_secret));
        }
    }
}
