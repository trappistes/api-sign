<?php

namespace Trappistes\ApiSign\Middlewares;

use Closure;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Trappistes\ApiSign\Facades\Signature;

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
        $res = Signature::validate();

        if ($res['status'] == true) {
            return $next($request);
        } else {
            return response()->json($res);
        }
    }
}
