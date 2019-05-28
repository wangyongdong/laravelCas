## laravelCAS
CAS Authentication for Laravel 5.x

This is a simple CAS service based on "PHP CAS" developed for Laravel5.*. 
The package is built for your own use and many features are not compatible. 
The easiest way to achieve the CAS service I need.

## Installation

`composer require wangyongdong/laravelcas`


### Setup
> NOTE : This package supports the auto-discovery feature of Laravel 5.5, So you can skip this section if you're using Laravel 5.5.

1.register the service provider in config/app.php

`
'providers' => [
     ...
     Laravelcas\Cas\CasServiceProvider::class,
 ],
`

2.Optional: And the facade in the aliases array:

`
'aliases' => [
    ...
    'Cas' => Laravelcas\Cas\Facades\Cas::class,
],
`

3.Publish the config file

`php artisan vendor:publish --provider="Cas\CasServiceProvider"`

4.Use CAS middleware

If you want to use the CAS service as a middleware for authentication, you can configure it in the $routeMiddleware `app/Http/Kernel.php`

`'cas' => \Laravelcas\Cas\Middleware\CASAuth::class,`

AND Using middleware

```php
Route::group(['middleware' => ['cas']], function () {
    Route::get('/auth', function (Request $request) {
        $user = Cas::getUser();
        dd($user);
    });
});
```

### Configuration

After the publish is completed, a configuration file named `config/cas.php` is automatically generated.

- CAS_HOST: Full Hostname of your CAS Server.
- CAS_CONTENT: Context of the CAS Server.
- CAS_PORT: Port of your CAS server. 
- CAS_VERSION: CAS version,Usually use the default.

More configuration can be found in config/cas.php

### Usage

- 获取验证身份URL `Cas::login_url()`
- 获取注销身份URL `Cas::logout_url()`
- 执行注销操作 `Cas::logout()`
- 获取当前CAS验证的用户 `Cas::user()`
- 根据当前请求对用户进行身份验证 `Cas::authenticate()` 
- 检查是否使用CAS进行身份验证 `Cas::checkAuthentication()`
- laravel项目，获取登陆用户 `$request->user`


### Links
[PHPCAS](https://github.com/apereo/phpCAS)
