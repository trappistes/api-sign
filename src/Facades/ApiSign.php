<?php

namespace Trappistes\ApiSign\Facades;

use Illuminate\Support\Facades\Facade;

class ApiSign extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'api-sign';
    }
}
