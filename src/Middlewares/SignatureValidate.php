<?php

namespace Trappistes\ApiSign\Middlewares;

use Closure;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Trappistes\ApiSign\Signature;

class SignatureValidate
{
    /**
     * 中间件
     *
     * @param $request
     * @param Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next): mixed
    {
        $signature = new Signature();

        $signature->setParam();

        $res = $signature->validate();

        if ($res['code'] == 200) {
            return $next($request);
        } else {
            return response()->json($res);
        }
    }
}
