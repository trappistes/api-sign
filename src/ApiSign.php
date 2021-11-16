<?php

namespace Trappistes\ApiSign;

use Validator;

class ApiSign
{
    /**
     * 错误码
     *
     * @var string[]
     */
    protected $errCodes = [
        '1001' => '[app_key]缺失',
        '1002' => '[app_key]不存在或无权限',
        '1005' => '[sign_method]错误',
        '1006' => '[sign]缺失',
        '1007' => '[sign]签名错误',
        '1010' => '[nonce]缺失',
        '1011' => '[nonce]必须为字符串',
        '1012' => '[nonce]长度必须为1-32位',
        '1013' => '[timestamp]缺失',
        '1014' => '[timestamp]已失效',
        '1015' => '[timestamp]无效的时间戳',
    ];

    /**
     * 请求参数
     *
     * @var array
     */
    protected $params = [];

    /**
     * access_key
     *
     * @var string
     */
    protected $access_key;

    /**
     * access_secret
     *
     * @var string
     */
    protected $access_secret;

    /**
     * 签名加密方法
     *
     * @var string
     */
    protected $sign_method = 'md5';

    /**
     * 签名时间戳有效期
     */
    protected $time_out = 300;

    /**
     * 进行校验
     *
     * @return array
     */
    public function hasValidSignature()
    {
        $this->params = request()->all();

        // 参数校验
        $res_param_validate = $this->paramValidate($this->params);

        if ($res_param_validate['status'] != true) {
            return $res_param_validate;
        }

        // access_key校验
        $res_app_validate = $this->appValidate($this->access_key);

        if ($res_app_validate['status'] != true) {
            return $res_app_validate;
        }

        // 签名校验
        $res_sign_validate = $this->signValidate();

        if ($res_sign_validate['status'] != true) {
            return $res_sign_validate;
        }

        // 成功返回
        return $res_sign_validate;
    }

    /**
     * url参数校验
     *
     * @param $params
     * @return array
     */
    protected function paramValidate($params)
    {
        // 校验规则
        $rules = [
            'access_key' => 'required',
            'sign_method' => 'in:,md5,hash',
            'nonce' => 'sometimes|required|string|min:1|max:32',
            'timestamp' => 'required|integer|between:' . time() - $this->time_out . ',' . time() + $this->time_out,
            'sign' => 'required',
        ];

        // 校验消息
        $messages = [
            'access_key.required' => '1001',
            'sign_method.in' => '1005',
            'nonce.required' => '1010',
            'nonce.string' => '1011',
            'nonce.min' => '1012',
            'nonce.max' => '1012',
            'timestamp.required' => '1013',
            'timestamp.between' => '1014',
            'timestamp.integer' => '1015',
            'sign.required' => '1006'
        ];

        // 参数赋值
        $this->sign_method = !empty($this->params['sign_method']) ? $this->params['sign_method'] : $this->sign_method;
        $this->access_key = $this->params['access_key'];

        $result = Validator::make($params, $rules, $messages);

        if ($result->fails()) {
            return $this->error($result->messages()->first());
        } else {
            return ['status' => true];
        }
    }

    /**
     * app校验
     *
     * @param $key
     * @return array
     */
    protected function appValidate($key)
    {
        $app = \Trappistes\ApiSign\Models\AccessKey::where('access_key', $key)->first();

        if (!$app) {
            return $this->error('1002');
        } else {
            $this->access_secret = $app->access_secret;
            return ['status' => true];
        }
    }

    /**
     * 签名验证
     *
     * @return array
     */
    protected function signValidate()
    {
        $signRes = $this->checkSign($this->params);

        if (!$signRes || !$signRes['status']) {
            return $this->error($signRes['code']);
        } else {
            return ['status' => true];
        }
    }

    /**
     * 校验签名
     *
     * @param $params
     * @return array
     */
    protected function checkSign($params)
    {
        $sign = array_key_exists('sign', $params) ? $params['sign'] : '';

        if (empty($sign)) {
            return $this->error('1006');
        }

        unset($params['sign']);

        if ($sign != $this->generateSign($params)) {
            return $this->error('1007');
        } else {
            return ['status' => true, 'code' => '200'];
        }
    }

    /**
     * 生成签名
     *
     * @param array $params 待校验签名参数
     * @return string|false
     */
    protected function generateSign($params)
    {
        ksort($params);

        $tmps = array();
        foreach ($params as $k => $v) {
            $tmps[] = $k . $v;
        }

        $string = implode('', $tmps) . $this->access_secret;

        if ($this->sign_method === 'md5') {
            return $this->generateMd5Sign($string);
        } elseif ($this->sign_method === 'hash') {
            \Log::info($this->generateHashSign($string));
            return $this->generateHashSign($string);
        }

        return false;
    }

    /**
     * 生成签名 MD5方式
     *
     * @param array $params 待签名参数
     * @return string
     */
    protected function generateMd5Sign($string)
    {
        return strtoupper(md5($string));
    }

    /**
     * 生成签名 Hash方式
     *
     * @param array $params 待签名参数
     * @return string
     */
    protected function generateHashSign($string)
    {
        return strtoupper(hash_hmac('sha256', $string, $this->access_secret));
    }

    /**
     * 输出错误结果
     *
     * @param string $code
     * @return array
     */
    protected function error(string $code)
    {
        return ['status' => false, 'code' => $code, 'message' => $this->errCodes[$code]];
    }

}
