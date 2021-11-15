<?php
namespace Wangyongdong\LaravelCas\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array getConfig()
 * @method static string login_url()
 * @method static string logout_url()
 * @method static validateLogout()
 * @method static logout($service = '')
 * @method static int user()
 * @method static bool isAuthenticated()
 * @method static bool checkAuthentication()
 * @method static bool forceAuthentication()
 * @method static mixed getAttribute($key)
 * @method static bool hasAttribute($key)
 * @method static mixed getAttributes()
 * @method static setAttributes(array $attr)
 * @see \Wangyongdong\LaravelCas\Cas
 */
class Cas extends Facade {
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor() {
        return 'cas';
    }
}