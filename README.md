# API 签名校验

## 介绍

Laravel/Lumen API 签名校验包

## 安装教程

### Laravel

首选安装包

```shell
composer require trappistes/api-sign
```

发布资源(非必须),仅在需要调整表数据结构时使用

```shell
php artisan vendor:publish
```

执行迁移

```shell
php artisan migrate
```

注册路由中间件，在 app/Http/Kernel.php 中添加

```injectablephp
protected $routeMiddleware = [
     'sign' => \Trappistes\ApiSign\Middlewares\ApiSignValidate::class
];
```

### Lumen

首选安装包

```shell
composer require trappistes/api-sign
```

需要手动注册服务，在 bootstrap/app.php 中添加

``` injectablephp
$app->register(\Trappistes\ApiSign\ApiSignServiceProvider::class);
```

发布资源(非必须),仅在需要调整表数据结构时使用

```shell
将 database/migrations/create_access_keys_table.php 复制到 database/migrations 目录下
```

执行迁移

```shell
php artisan migrate
```

注册路由中间件, 在 bootstrap/app.php 中添加

```injectablephp
$app->routeMiddleware([
   'sign' => \Trappistes\ApiSign\Middlewares\ApiSignValidate::class
]);
```

## 使用

#### 公共参数

|      参数名      |  类型  |   是否必须  |     描述    |
|-----------------|--------|:----------:|------------|
| access_key         | string |     是     | 应用Key                              |
| sign_method     | string |     否     | 签名类型，默认：md5（支持md5,hmacsha256）       |
| nonce           | string |     是     | 一次性验证随机字符串，长度1-32位任意字符（建议使用时间戳+随机字符串）   |
| timestamp       | string |     是     | 签名时间戳，有效期600s（$ttl参数控制）                              |
| sign            | string |     是     | 签名字符串，参考签名规则                |

#### 业务参数

> API除了必须包含公共参数外，如果API本身有业务级的参数也必须传入。

#### 签名方法

1. 对除`sign`参数外的所有API请求参数（包括公共参数和业务请求参数），根据参数名称的ASCII码表的顺序排序。 如：`foo=1, bar=2, foo_bar=3, foobar=4`
   排序后的顺序是 `bar=2, foo=1, foo_bar=3, foobar=4`;
2. 将排序好的参数名和参数值拼装在一起，根据上面的示例得到的结果为：`bar2foo1foo_bar3foobar4`;
3. 把拼装好的字符串采用utf-8编码，使用签名算法对编码后的字符串进行摘要;
   如：`md5(bar2foo1foo_bar3foobar4 + secret)`,`hash_hmac('sha256', bar2foo1foo_bar3foobar4 + secret, secret)`;
4. 将摘要得到的字节结果使用大写表示。如：`strtoupper($sign_string)`;
5. 发送请求地址

#### 校验方法

在需要校验的路由上使用中间件校验

Laravel

```injectablephp
Route::resource('user',UserController::class)->middleware('sign');
```

Lumen

```injectablephp
$router->get('admin/profile', ['middleware' => ['sign','auth'], 'uses' => 'AdminController@showProfile']);
```

#### key & secret 管理（略）CURD自行实现
Trappistes\ApiSign\Models\AccessKey;