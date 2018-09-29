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
     Cas\CasServiceProvider::class,
 ],
`

2.Optional: And the facade in the aliases array:

`
'aliases' => [
    ...
    'Cas' => Cas\Facades\Cas::class,
],
`

3.Publish the config file

`php artisan vendor:publish --provider="Cas\CasServiceProvider"`

4.Use CAS middleware

If you want to use the CAS service as a middleware for authentication, you can configure it in the $routeMiddleware `app/Http/Kernel.php`

`'cas' => \Cas\Middleware\CASAuth::class,`

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

- Cas::isAuthenticated();
- Cas::checkAuthentication();
- Cas::authenticate();
- Cas::getUser();
- Cas::logoutWithUrl();
- Cas::logout_url();


### Links
[PHPCAS](https://github.com/apereo/phpCAS)