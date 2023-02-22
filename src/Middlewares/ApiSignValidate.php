<?php

namespace Trappistes\ApiSign\Middlewares;

use Closure;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Trappistes\ApiSign\Facades\ApiSign;

class ApiSignValidate
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
        $res = ApiSign::SignatureValidation();

        if ($res['status'] == true) {
            return $next($request);
        } else {
            return response()->json($res);
        }
    }
}
