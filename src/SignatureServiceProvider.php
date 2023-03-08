<?php

namespace Trappistes\ApiSign;

use Illuminate\Foundation\Application as Laravel;
use Laravel\Lumen\Application as Lumen;
use Illuminate\Support\ServiceProvider;

class SignatureServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('signature', function () {
            return new Signature();
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
