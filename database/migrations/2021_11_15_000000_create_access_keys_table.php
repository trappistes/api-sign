<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('access_keys', function (Blueprint $table) {
            $table->id();
            $table->string('app_name')->unique()->comment('应用名称');
            $table->string('app_desc')->nullable()->comment('应用描述');
            $table->string('access_key')->unique()->comment('应用密钥对');
            $table->string('access_secret')->comment('应用密钥对');
            $table->tinyInteger('status')->default(1)->comment('状态：0. 已禁用；1. 已启用');
            $table->index('access_key');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('access_keys');
    }
};
