<?php

namespace Trappistes\ApiSign;

use Illuminate\Foundation\Application as Laravel;
use Laravel\Lumen\Application as Lumen;
use Illuminate\Support\ServiceProvider;

class ApiSignServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('api-sign', function () {
            return new ApiSign();
        });
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        if ($this->app instanceof Laravel) {
            $this->publishes([
                __DIR__ . '/../database/migrations/' => database_path('migrations')
            ], 'migrations');
        }

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }
}
