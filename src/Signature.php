<?php

namespace Trappistes\ApiSign;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;
use Trappistes\ApiSign\Models\AccessKey;

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
        '1011' => '[method]错误',
        '1012' => '[sign]缺失',
        '1013' => '[sign]签名错误',
        '1021' => '[nonce]缺失',
        '1022' => '[nonce]必须为字符串',
        '1023' => '[nonce]长度必须为1-32位',
        '1024' => '[nonce]已失效',
        '1031' => '[timestamp]缺失',
        '1032' => '[timestamp]已失效',
        '1033' => '[timestamp]无效的时间戳',
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
     * 进行校验
     *
     * @return array
     */
    public function validate(): array
    {
        // 获取header参数
        $this->params['access_key'] = request()->header('Sign-Access-Key', null);
        $this->params['method'] = request()->header('Sign-Method', $this->method);
        $this->params['nonce'] = request()->header('Sign-Nonce', null);
        $this->params['timestamp'] = request()->header('Sign-Timestamp', null);
        $this->params['sign'] = request()->header('Sign-String', null);

        // 参数校验
        $res = $this->paramValidate();

        if ($res['status'] == false) {
            return $res;
        }

        // access_key校验
        $res = $this->appValidate();

        if ($res['status'] == false) {
            return $res;
        }

        // 签名校验
        $res = $this->signValidate();

        if ($res['status'] == false) {
            return $res;
        }

        // nonce校验
        if ($this->params['nonce']) {
            $res = $this->nonceValidate();

            if ($res['status'] == false) {
                return $res;
            }

            // nonce写入缓存
            Cache::tags(['nonces'])->put($this->params['access_key'] . '_nonce', $this->params['timestamp'], $this->ttl);
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
        // 验证规则
        $rules = [
            'access_key' => 'required',
            'method' => 'required|in:,md5,hash',
            'nonce' => 'sometimes|required|string|min:1|max:32',
            'timestamp' => 'required|integer|between:' . time() - $this->ttl . ',' . time() + $this->ttl,
            'sign' => 'required',
        ];

        // 验证消息
        $messages = [
            'access_key.required' => '1001',
            'method.in' => '1011',
            'nonce.required' => '1021',
            'nonce.string' => '1022',
            'nonce.min' => '1023',
            'nonce.max' => '1023',
            'timestamp.required' => '1031',
            'timestamp.between' => '1032',
            'timestamp.integer' => '1033',
            'sign.required' => '1012'
        ];

        // 验证请求数据
        $result = Validator::make($this->params, $rules, $messages);

        // 如果存在指定的加密方式时，覆盖默认设置
        if (in_array('method', $this->params)) {
            $this->method = $this->params['method'];
        }

        if ($result->fails()) {
            return $this->error($result->messages()->first());
        } else {
            return ['status' => true];
        }
    }

    /**
     * 验证nonce参数是否有效
     *
     * @return array
     */
    protected function nonceValidate(): array
    {
        if (Cache::tags(['nonces'])->has($this->params['access_key'] . '_nonce')) {
            return $this->error('1024');
        } else {
            return ['status' => true];
        }
    }

    /**
     * 验证access_key参数是否有效
     *
     * @return array
     */
    protected function appValidate(): array
    {
        $key = AccessKey::where('access_key', $this->params['access_key'])->first();

        if (!$key) {
            return $this->error('1002');
        } elseif ($key['status'] == 0) {
            return $this->error('1003');
        } else {
            $this->access_secret = $key->access_secret;
            return ['status' => true];
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

        if ($this->params['sign'] != $str) {
            return $this->error('1013');
        } else {
            return ['status' => true];
        }
    }

    /**
     * 验证失败返回
     *
     * @param string $code
     * @return array
     */
    protected function error(string $code): array
    {
        return ['status' => false, 'code' => $code, 'message' => self::ErrCodes[$code]];
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
            if ($k == 'sign') {
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
