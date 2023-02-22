<?php

namespace Trappistes\ApiSign;

use Trappistes\ApiSign\Models\AccessKey;
use Validator;

class ApiSign
{
    /**
     * 错误码
     *
     * @var string[]
     */
    const ErrCodes = [
        '1001' => '[app_key]缺失',
        '1002' => '[app_key]不存在或无权限',
        '1011' => '[sign_method]错误',
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
    protected array $params = [];

    /**
     * 签名加密方法
     *
     * @var string $sign_method
     */
    protected string $sign_method = 'md5';

    /**
     * 签名时间戳有效期(单位：秒)
     *
     * @var int $ttl
     */
    protected int $ttl = 30;

    /**
     * 密钥
     *
     * @var string $app_secret
     */
    protected string $app_secret;

    /**
     * 进行校验
     *
     * @return array
     */
    public function SignatureValidation(): array
    {
        $this->params = request()->all();

        // 参数校验
        $this->paramValidate();

        // access_key校验
        $this->appValidate();

        // 签名校验
        $this->signValidate();

        // nonce校验
        $this->nonceValidate();

        // nonce写入缓存
        Cache::tags(['nonces'])->put($this->params['access_key'] . '_nonce', $this->params['timestamp'], $this->ttl);

        // 成功返回
        return ['$res_sign_validate'];
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
            'sign_method' => 'in:,md5,hash',
            'nonce' => 'sometimes|required|string|min:1|max:32',
            'timestamp' => 'required|integer|between:' . time() - $this->ttl . ',' . time() + $this->ttl,
            'sign' => 'required',
        ];

        // 验证消息
        $messages = [
            'access_key.required' => '1001',
            'sign_method.in' => '1011',
            'nonce.required' => '1021',
            'nonce.string' => '1022',
            'nonce.min' => '1023',
            'nonce.max' => '1023',
            'timestamp.required' => '1031',
            'timestamp.between' => '1032',
            'timestamp.integer' => '1033',
            'sign.required' => '1012'
        ];

        $result = Validator::make($this->params, $rules, $messages);

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
        }
    }

    /**
     * 验证access_key参数是否有效
     *
     * @return array
     */
    protected function appValidate(): array
    {
        $app = AccessKey::where('access_key', $this->params['access_key'])->first();

        if (!$app) {
            return $this->error('1002');
        } else {
            $this->app_secret = $app->app_secret;
        }
    }

    /**
     * 签名验证
     *
     * @return array
     */
    protected function signValidate(): array
    {
        $signRes = $this->checkSign();

        if (!$signRes || !$signRes['status']) {
            return $this->error($signRes['code']);
        } else {
            return ['status' => true];
        }
    }

    /**
     * 验证签名
     *
     * @return array
     */
    protected function checkSign(): array
    {
        if ($this->params['sign'] != $this->generateSign()) {
            return $this->error('1013');
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
     * 验证成功返回
     *
     * @return bool[]
     */
    protected function success(): array
    {
        return ['status' => true];
    }


    /**
     * 生成签名
     *
     * @return string|false
     */
    private function generateSign($params): bool|string
    {
        if (in_array('sign', $params)) {
            unset($params['sign']);
        }

        // 对参数进行排序
        ksort($params);

        $tmps = array();

        // 遍历参数，写入临时变量
        foreach ($params as $k => $v) {
            $tmps[] = $k . $v;
        }

        // 组合字符串
        $string = implode('', $tmps) . $this->app_secret;

        // 判断加密方式
        if ($params['sign_method'] === 'md5') {
            return strtoupper(md5($string));
        } elseif ($params['sign_method'] === 'hash') {
            return strtoupper(hash_hmac('sha256', $string, $this->app_secret));
        }
    }
}
