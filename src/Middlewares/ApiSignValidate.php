<?php

namespace Trappistes\ApiSign\Middlewares;

use Closure;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Trappistes\ApiSign\Facades\ApiSign;
use Trappistes\ApiSign\Response;
use function Couchbase\defaultDecoder;

class ApiSignValidate
{
    /**
     * 中间件
     *
     * @param $request
     * @param Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $valid = ApiSign::SignatureValidation();

        if ($valid['status'] == true) {
            return $next($request);
        }else{
            return response()->json($valid);
        }
    }
}
