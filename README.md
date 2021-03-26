# laravel-cas

Laravel Cas Client 服务是基于 [phpCas](https://github.com/apereo/phpCAS) 基础上进行封装

## 支持

- `laravel5.5+`
- `laravel6.x`
- `laravel7.x`
- `laravel8.x`

### 版本说明

- 当前版本稳定版本为 [laravel-cas 1.0.2](https://github.com/wangyongdong/laravelcas)
    - 此版本改动较大，需更新老版本代码

## 安装

### 编辑 `Composer.json`

```json
{
    "repositories": {
        "wangyongdong/phpcas": {
            "type": "git",
            "url": "https://github.com/wangyongdong/phpCAS.git"
        },
        "wangyongdong/laravelcas": {
            "type": "git",
            "url": "https://github.com/wangyongdong/laravelCas.git"
        }
    },
    "require": {
      "wangyongdong/laravelcas": "^3.0"
    },
    "config": {
        "secure-http": false
    } 
}
```

### 执行安装

 - `composer install` 或 `composer require "wangyongdong/laravelcas:1.0.2"`

### 配置 `provider` 和 `aliases`

> NOTE : 该软件包支持Laravel 5.5的自动发现功能，因此，如果您使用的是Laravel 5.5，则可以跳过本节。

#### 1. 配置 `provider `

`
'providers' => [
     Wangyongdong\LaravelCas\CasServiceProvider::class
 ],
`

#### 2. 配置 `aliases`

`
'aliases' => [
    ... 
    'Laravelcas' => Wangyongdong\LaravelCas\Facades\Cas::class,
],
`

### 发布配置文件

`php artisan vendor:publish --provider="Wangyongdong\LaravelCas\CasServiceProvider"`

#### 配置文件

发布完成后，将自动生成一个名为 `config/cas.php` 的配置文件。

一般来说，仅需配置一下几项即可

- 配置 `laravel` 项目根目录下 `.env`文件，修改 `APP_URL` 的值

- `CAS_HOST`: CAS服务端主域名
- `CAS_CONTENT`: CAS服务路径名称
- `CAS_PORT`: CAS服务端口
- `CAS_LOGOUT_URL`: CAS服务退出url地址

更多配置项在文件 `config/cas.php` 中查看  

### 使用中间件

如果要将CAS服务用作身份验证的中间件，则可以在 `app/Http/Kernel.php`中的 `$routeMiddleware` 对其进行配置。

```php
'LaravelCasMiddleware' => \Wangyongdong\LaravelCas\Middleware\CASAuth::class,
```

```php
Route::group(['middleware' => ['LaravelCasMiddleware']], function () {
    Route::get('/login/auth', function (Illuminate\Http\Request $request) {
        $user = $request->userid;
        dd($user);
    });
});
```

### 支持方法

- 验证是否登录 `LaravelCas::checkAuthentication()`
- 强制执行登录 `LaravelCas::forceAuthentication()`
- 获取登录地址 `LaravelCas::login_url()`
- 获取退出地址 `LaravelCas::logout_url()`
- 执行退出 `LaravelCas::logout($service = '')`
- 获取当前登录用户id `LaravelCas::user()`
- Laravel项目获取登陆用户id：`$request->userid` or `$request->session()->get('userid')`

## Updates

- 支持 `laravel6.x` `laravel7.x` `laravel8.x`
- 更新版本 [phpCAS 1.3.9](https://apereo.github.io/phpCAS/)，解决 `phpCAS error: phpCAS::client(): ErrorException: "continue" targeting switch is equivalent to "break". Did you mean to use "continue 2"?` 问题
- 兼容 `composer2.0`，优化命名空间
- 支持重定向注销登陆
- 添加支持中间件的使用
- 更新包 [phpCAS](https://github.com/wangyongdong/phpCAS.git)，兼容 `http` 和 `https`的判断
- 支持配置文件，对 `phpCAS` 客户端进行配置

## 问题

1. `Parse error: syntax error, unexpected '?', expecting variable (T_VARIABLE)`
 - 报错版本：`laravel5.5` `php7.0.9`
 - 问题原因：包 `symfony/translation` 使用 `php7.1` 新增特性 [可为空（Nullable）类型](https://www.php.net/manual/zh/migration71.new-features.php) 导致报错
 - 解决办法：升级 `laravel` 版本，或升级 `php` 版本

2. `Declaration of Illuminate\Container\Container::get($id) must be compatible with Psr\Container\ContainerInterface::get(string $id) in`
 - 报错版本：
    - `laravel5.6` `php7.1.9`
    - `laravel5.7` `php7.1.9`
    - `laravel5.8` `php7.1.9`
 - 问题原因：因 `laravel5.6+` 版本中引用的扩展包里，使用了 `php7.2` 新特性 [参数类型声明]()，导致报错   
 - 解决办法：
    - 1. 升级到 `php7.2+`
    - 2. 修改`Illuminate\Container\Container` 592行，161行。改为 `public function get(string $id)`，`public function has(string $id)`

## Links

[PHPCAS](https://github.com/apereo/phpCAS)
